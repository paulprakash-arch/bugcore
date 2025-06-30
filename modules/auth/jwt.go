package auth

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type jwtPayload struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

func RunJWTScan(domain string) {
	sources := map[string]string{
		"live.txt":        fmt.Sprintf("output/%s/%s_live.txt", domain, domain),
		"paramurls.txt":   fmt.Sprintf("output/%s/%s_paramurls/paramurls.txt", domain, domain),
		"param_urls.txt":  fmt.Sprintf("output/%s/%s_vulns/param_urls.txt", domain, domain),
		"dirs/200.txt":    fmt.Sprintf("output/%s/%s_dirs/200.txt", domain, domain),
		"dirs/403.txt":    fmt.Sprintf("output/%s/%s_dirs/403.txt", domain, domain),
	}

	var allURLs []string
	for label, path := range sources {
		urls, err := parseFileLive(path)
		if err == nil && len(urls) > 0 {
			fmt.Printf("[+] Parsed %d URLs from %s\n", len(urls), label, path)
			allURLs = append(allURLs, urls...)
		}
	}

	fmt.Printf("[*] [jwt] Scanning %d URLs for JWT vulnerabilities...\n", len(allURLs))

	outputPath := fmt.Sprintf("output/%s/%s_vulns/jwt_vulns.txt", domain, domain)
	os.MkdirAll(fmt.Sprintf("output/%s/%s_vulns", domain, domain), os.ModePerm)
	outFile, err := os.Create(outputPath)
	if err != nil {
		fmt.Println("[!] Error creating output file:", err)
		return
	}
	defer outFile.Close()
	writer := bufio.NewWriter(outFile)
	defer writer.Flush()

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, url := range allURLs {
		sem <- struct{}{}
		wg.Add(1)
		go func(endpoint string) {       //url being passed here till 10 so it launches 10 goroutines with 10 diff urls so scanforJwt call 10 times with diff url at a time if on url is finished another come to the empty go routine to fill 
			defer wg.Done()
			scanForJWT(endpoint, writer)
			<-sem
		}(url)
	}
	wg.Wait()

	fmt.Printf("[+] JWT scan completed. Results saved to: %s\n", outputPath)
}

func scanForJWT(url string, writer *bufio.Writer) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	fmt.Printf("[*] Testing: %s [%d]\n", url, resp.StatusCode)

	if resp.StatusCode != 200 && resp.StatusCode != 403 {
		return
	}

	// Check Set-Cookie
	for _, cookie := range resp.Cookies() {
		if strings.Contains(strings.ToLower(cookie.Name), "token") || strings.Contains(strings.ToLower(cookie.Name), "jwt") {
			analyzeJWT(cookie.Value, url, writer, "Set-Cookie")
		}
	}

	// Check headers
	for k, v := range resp.Header {
		if strings.Contains(strings.ToLower(k), "token") || strings.Contains(strings.ToLower(k), "auth") {
			for _, hv := range v {
				if strings.HasPrefix(hv, "Bearer ") {
					analyzeJWT(strings.TrimPrefix(hv, "Bearer "), url, writer, "Header: "+k)
				} else {
					analyzeJWT(hv, url, writer, "Header: "+k)
				}
			}
		}
	}

	// Check body
	buf := new(strings.Builder)
	_, _ = io.Copy(buf, resp.Body)
	body := buf.String()
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		if strings.Contains(line, "eyJ") && strings.Count(line, ".") == 2 {
			start := strings.Index(line, "eyJ")
			end := strings.IndexAny(line[start:], "\"' <")
			if end == -1 {
				end = len(line)
			} else {
				end += start
			}
			jwt := line[start:end]
			analyzeJWT(jwt, url, writer, "Body")
		}
	}
}

func analyzeJWT(token, url string, writer *bufio.Writer, source string) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return
	}

	var header jwtPayload
	err = json.Unmarshal(headerBytes, &header)
	if err != nil {
		return
	}

	var findings []string

	if header.Alg == "none" {
		findings = append(findings, "Algorithm 'none' accepted")
	}
	if header.Alg == "HS256" && header.Kid != "" && strings.Contains(header.Kid, "../") {
		findings = append(findings, "Possible KID path traversal")
	}
	if header.Alg == "RS256" {
		findings = append(findings, "RS256 detected - test for alg confusion")
	}

	if len(findings) > 0 {
		title := fmt.Sprintf("[+] %s\n    Source: %s\n    Token Snippet: %s...\n    Issues:", url, source, token[:min(30, len(token))])
		fmt.Println(title)
		writer.WriteString(title + "\n")
		for _, f := range findings {
			line := fmt.Sprintf("    - %s\n", f)
			fmt.Print(line)
			writer.WriteString(line)
		}
		writer.WriteString("\n")
		writer.Flush()
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func parseFileLive(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "http") {
			spaceIdx := strings.Index(line, " ")
			if spaceIdx != -1 {
				line = strings.TrimSpace(line[:spaceIdx])
			}
			urls = append(urls, line)
		}
	}

	return urls, scanner.Err()
}

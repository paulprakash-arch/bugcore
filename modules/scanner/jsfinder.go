package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/html"
)

func RunJSFinder(domain string) {
	liveFile := fmt.Sprintf("output/%s/%s_live.txt", domain, domain)
	f, err := os.Open(liveFile)
	if err != nil {
		fmt.Println("[-] Failed to open live hosts file:", err)
		return
	}
	defer f.Close()

	var urls []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) > 0 {
			urls = append(urls, parts[0])
		}
	}

	client := &http.Client{Timeout: 10 * time.Second}
	jsFiles := make(map[string]string)

	fmt.Println("[*] Extracting JS files from live targets...")

	for _, base := range urls {
		resp, err := client.Get(base)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		doc := html.NewTokenizer(resp.Body)
		for {
			tt := doc.Next()
			if tt == html.ErrorToken {
				break
			}
			tok := doc.Token()
			if tok.Type == html.StartTagToken && tok.Data == "script" {
				for _, attr := range tok.Attr {
					if attr.Key == "src" && strings.HasSuffix(attr.Val, ".js") {
						jsURL := attr.Val
						if strings.HasPrefix(jsURL, "//") {
							jsURL = "https:" + jsURL
						} else if strings.HasPrefix(jsURL, "/") {
							jsURL = base + jsURL
						} else if !strings.HasPrefix(jsURL, "http") {
							jsURL = base + "/" + jsURL
						}
						if _, seen := jsFiles[jsURL]; !seen {
							fmt.Println("[*] Found JS file:", jsURL)
							jsFiles[jsURL] = base
						}
					}
				}
			}
		}
	}

	if len(jsFiles) == 0 {
		fmt.Println("[-] No JavaScript files found.")
		return
	}

	// Secret regexes
	secretRegexes := []*regexp.Regexp{
		regexp.MustCompile(`(?i)api[_-]?key['"]?\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]`),
		regexp.MustCompile(`(?i)(aws|gcp|google)?[_-]?secret['"]?\s*[:=]\s*['"][A-Za-z0-9/\+=]{20,}['"]`),
		regexp.MustCompile(`(?i)authorization['"]?\s*[:=]\s*['"]?Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+['"]?`),
		regexp.MustCompile(`(?i)(password|pass|pwd)['"]?\s*[:=]\s*['"][^'"]{6,}['"]`),
		regexp.MustCompile(`(?i)(client|access)[_-]?token['"]?\s*[:=]\s*['"][A-Za-z0-9\-_]{10,}['"]`),
	}

	// Output
	outDir := fmt.Sprintf("output/%s/%s_vulns", domain, domain)
	os.MkdirAll(outDir, 0755)
	secretOut := fmt.Sprintf("%s/js_secrets.txt", outDir)
	endpointOut := fmt.Sprintf("%s/js_endpoints.txt", outDir)

	secretSet := make(map[string]struct{})
	endpointSet := make(map[string]struct{})

	fmt.Println("[*] Scanning JS files for secrets and API endpoints...")

	for jsURL, parent := range jsFiles {
		// GET JS content
		resp, err := client.Get(jsURL)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		jsContent := string(body)

		// Regex scan
		for _, re := range secretRegexes {
			matches := re.FindAllString(jsContent, -1)
			for _, match := range matches {
				entry := fmt.Sprintf("[!] %s (found in: %s)\n → %s", jsURL, parent, match)
				if _, exists := secretSet[entry]; !exists {
					secretSet[entry] = struct{}{}
					fmt.Println(entry)
				}
			}
		}

		// LinkFinder
		cmd := exec.Command(
			"/home/kali/tools/LinkFinder/venv/bin/python3",
			"/home/kali/tools/LinkFinder/linkfinder.py",
			"-i", jsURL,
			"-o", "cli",
		)
		var outBuf bytes.Buffer
		cmd.Stdout = &outBuf
		cmd.Stderr = &outBuf

		if err := cmd.Run(); err != nil {
			continue
		}

		lines := strings.Split(outBuf.String(), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if isProbablyAPI(line) {
				var guessedURL string

				// ✨ [MODIFIED] Guess full domain for relative API
				if strings.HasPrefix(line, "/") {
					guessedURL = parent + line
				} else {
					guessedURL = line
				}

				entry := fmt.Sprintf("[+] %s → %s\n    → Full URL guess: %s", jsURL, line, guessedURL)

				if _, exists := endpointSet[entry]; !exists {
					endpointSet[entry] = struct{}{}
					fmt.Println(entry)
				}
			}
		}
	}

	// Save secrets
	if len(secretSet) > 0 {
		var uniqueSecrets []string
		for s := range secretSet {
			uniqueSecrets = append(uniqueSecrets, s)
		}
		os.WriteFile(secretOut, []byte(strings.Join(uniqueSecrets, "\n")), 0644)
		fmt.Println("[+] JS secrets saved to:", secretOut)
	} else {
		fmt.Println("[-] No secrets found.")
	}

	// Save endpoints
	if len(endpointSet) > 0 {
		var uniqueEndpoints []string
		for e := range endpointSet {
			uniqueEndpoints = append(uniqueEndpoints, e)
		}
		os.WriteFile(endpointOut, []byte(strings.Join(uniqueEndpoints, "\n")), 0644)
		fmt.Println("[+] JS endpoints saved to:", endpointOut)
	} else {
		fmt.Println("[-] No endpoints found.")
	}
}

func isProbablyAPI(line string) bool {
	if strings.HasPrefix(line, "/") &&
		(strings.Contains(line, "/api/") || strings.Contains(line, "/v1/") ||
			strings.Contains(line, "/auth") || strings.Contains(line, "/user") ||
			strings.Contains(line, "/login") || strings.Contains(line, "/register")) {
		return true
	}
	if strings.HasPrefix(line, "http") &&
		(strings.Contains(line, "/api/") || strings.Contains(line, "/v1/")) {
		return true
	}
	return false
}

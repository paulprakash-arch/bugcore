package scanner

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func RunOpenRedirectScan(domain string) {
	fmt.Println("[*] Starting Open Redirect scan...")

	// FIXED PATH
	inputFile := fmt.Sprintf("output/%s/%s_paramurls/paramurls.txt", domain, domain)
	outputFile := fmt.Sprintf("output/%s/%s_vulns/open_redirects.txt", domain, domain)

	payloads := []string{
		"https://evil.com",
		"//evil.com",
		"///evil.com",
		"https://evil.com@yourdomain.com",
		"//evil.com%2f..",
		"evil.com",
	}

	// Read input
	f, err := os.Open(inputFile)
	if err != nil {
		fmt.Println("[-] Failed to open paramurls.txt:", err)
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	client := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}

	var results []string

	for scanner.Scan() {
		original := scanner.Text()
		if !strings.Contains(original, "=") {
			continue
		}

		u, err := url.Parse(original)
		if err != nil {
			continue
		}
		q := u.Query()

		for param := range q {
			for _, payload := range payloads {
				q.Set(param, payload)
				u.RawQuery = q.Encode()
				testURL := u.String()

				req, err := http.NewRequest("GET", testURL, nil)
				if err != nil {
					continue
				}
				req.Header.Set("User-Agent", "Mozilla/5.0")

				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				resp.Body.Close()

				// Check for redirect
				if resp.StatusCode >= 300 && resp.StatusCode < 400 {
					loc := resp.Header.Get("Location")
					if loc == "" {
						continue
					}

					// Check if redirect is external
					parsed, err := url.Parse(loc)
					if err != nil {
						continue
					}

					// If absolute & different host → Potentially vulnerable
					if parsed.IsAbs() && !strings.Contains(parsed.Host, "remitly.com") {
						entry := fmt.Sprintf("[🔥] VALID Open Redirect:\n → Target: %s\n → Param: %s\n → Payload: %s\n → Redirects To: %s\n",
							testURL, param, payload, loc)
						fmt.Println(entry)
						results = append(results, entry)
					} else {
						entry := fmt.Sprintf("[~] Benign redirect (internal):\n → %s → %s", testURL, loc)
						fmt.Println(entry)
					}
				}
			}
		}
	}

	if len(results) == 0 {
		fmt.Println("[-] No exploitable open redirects found.")
		return
	}

	os.MkdirAll(fmt.Sprintf("output/%s/%s_vulns", domain, domain), 0755)
	os.WriteFile(outputFile, []byte(strings.Join(results, "\n")), 0644)
	fmt.Println("[+] Real Open Redirects saved to:", outputFile)
}

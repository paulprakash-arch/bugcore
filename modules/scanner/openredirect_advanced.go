package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
)

var redirectPayloads = []string{
	"https://evil.com",
	"//evil.com",
	"/\\evil.com",
	"///evil.com",
	"////evil.com",
	"https://evil.com/%2e%2e",
	"http://evil.com",
}

// Main entry
func RunOpenRedirectAdv(targetDomain string, inputFiles []string, outputFile string, threads int) {
	fmt.Println("[*] [openredirect-adv] Starting advanced open redirect scanner on:", targetDomain)

	// Launch one persistent Chrome instance
	allocatorCtx, cancelAllocator := chromedp.NewExecAllocator(context.Background(), chromedp.DefaultExecAllocatorOptions[:]...)
	defer cancelAllocator()

	parentCtx, cancelBrowser := chromedp.NewContext(allocatorCtx)
	defer cancelBrowser()

	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)
	results := make(chan string)

	// Launch scans
	for _, file := range inputFiles {
		f, err := os.Open(file)
		if err != nil {
			fmt.Printf("[-] [openredirect-adv] Failed to open input file: %s\n", file)
			continue
		}

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			original := scanner.Text()
			if !strings.HasPrefix(original, "http") {
				continue
			}

			for _, payload := range redirectPayloads {
				injected := injectRedirectPayload(original, payload)
				if injected == "" {
					continue
				}

				wg.Add(1)
				sem <- struct{}{}

				go func(testURL, payload string) {
					defer wg.Done()
					defer func() { <-sem }()
					childCtx, cancel := chromedp.NewContext(parentCtx)
					defer cancel()

					if validateRedirectWithContext(childCtx, testURL) {
						results <- fmt.Sprintf("[OPENREDIRECT-ADV] %s -> %s", testURL, payload)
					}
				}(injected, payload)
			}
		}
		f.Close()
	}

	// Close result writer after all
	go func() {
		wg.Wait()
		close(results)
	}()

	writeRedirectResults(outputFile, results)
}

// Inject redirect payload into all parameters
func injectRedirectPayload(rawURL, payload string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.RawQuery == "" {
		return ""
	}

	q := parsed.Query()
	found := false
	for key := range q {
		q.Set(key, payload)
		found = true
	}
	if !found {
		return ""
	}
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

// Headless browser-based redirect check (per child context)
func validateRedirectWithContext(ctx context.Context, testURL string) bool {
	ctxTimeout, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	var finalURL string
	err := chromedp.Run(ctxTimeout,
		chromedp.Navigate(testURL),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Location(&finalURL),
	)

	return err == nil && strings.Contains(finalURL, "evil.com")
}

// Output writer
func writeRedirectResults(outputFile string, data <-chan string) {
	if err := os.MkdirAll(getDir(outputFile), 0755); err != nil {
		fmt.Println("[-] Failed to create output dir:", err)
		return
	}

	f, err := os.Create(outputFile)
	if err != nil {
		fmt.Println("[-] Failed to create output file:", err)
		return
	}
	defer f.Close()

	for entry := range data {
		fmt.Println(entry)
		f.WriteString(entry + "\n")
	}
}

// Get directory from file path
func getDir(path string) string {
	parts := strings.Split(path, "/")
	return strings.Join(parts[:len(parts)-1], "/")
}

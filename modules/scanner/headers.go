package scanner

import (
    "bufio"
    "crypto/tls"
    "fmt"
    "net/http"
    "os"
    "strings"
    "sync"
    "time"
)

var interestingHeaders = []string{
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Access-Control-Allow-Origin",
    "Referrer-Policy",
    "X-Powered-By",
    "Server",
}

func ScanHeaders(domain string) {
    liveFile := fmt.Sprintf("output/%s/%s_live.txt", domain, domain)
    file, err := os.Open(liveFile)
    if err != nil {
        fmt.Println("[-] Cannot open live hosts file:", err)
        return
    }
    defer file.Close()

    outDir := fmt.Sprintf("output/%s/%s_vulns", domain, domain)
    os.MkdirAll(outDir, 0755)
    outFile := fmt.Sprintf("%s/headers.txt", outDir)
    output := []string{}

    fmt.Println("[*] Scanning HTTP headers...")

    scanner := bufio.NewScanner(file)
    var wg sync.WaitGroup
    var mu sync.Mutex

    client := &http.Client{
        Timeout: 6 * time.Second,
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        },
    }

    sem := make(chan struct{}, 30) // 30 parallel scans

    for scanner.Scan() {
        line := scanner.Text()
        parts := strings.Fields(line)
        if len(parts) < 1 {
            continue
        }
        url := parts[0]

        wg.Add(1)
        sem <- struct{}{}

        go func(url string) {
            defer wg.Done()
            defer func() { <-sem }()

            req, err := http.NewRequest("GET", url, nil)
            if err != nil {
                return
            }

            resp, err := client.Do(req)
            if err != nil {
                return
            }
            defer resp.Body.Close()

            issues := []string{}
            headers := resp.Header

            for _, h := range interestingHeaders {
                val := headers.Get(h)
                if val == "" {
                    issues = append(issues, fmt.Sprintf("Missing: %s", h))
                } else {
                    if h == "Access-Control-Allow-Origin" && val == "*" {
                        issues = append(issues, fmt.Sprintf("Wildcard CORS: %s", val))
                    }
                    if h == "X-Powered-By" || h == "Server" {
                        issues = append(issues, fmt.Sprintf("Leaky Header: %s = %s", h, val))
                    }
                }
            }

            if len(issues) > 0 {
                report := fmt.Sprintf("%s\n%s\n", url, strings.Join(issues, "\n"))
                mu.Lock()
                output = append(output, report)
                mu.Unlock()
                fmt.Printf("[!] %s - Issues Found\n", url)
            }
        }(url)
    }

    wg.Wait()
    os.WriteFile(outFile, []byte(strings.Join(output, "\n\n")), 0644)
    fmt.Println("[+] Header scan complete. Results saved to:", outFile)
}

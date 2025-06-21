package recon

import (
    "bufio"
    "crypto/tls"
    "fmt"
    "math/rand"
    "net/http"
    "os"
    "strings"
    "sync"
    "time"

    "golang.org/x/net/html"
)

func ProbeLiveHosts(domain string) {
    // Ensure output/<domain> folder exists
    outputDir := fmt.Sprintf("output/%s", domain)
    os.MkdirAll(outputDir, 0755)

    subdomainFile := fmt.Sprintf("%s/%s_subdomains.txt", outputDir, domain)
    file, err := os.Open(subdomainFile)
    if err != nil {
        fmt.Println("[-] Failed to open subdomains file:", err)
        return
    }
    defer file.Close()

    fmt.Println("[*] Probing for live hosts...")

    scanner := bufio.NewScanner(file)
    subdomains := []string{}
    for scanner.Scan() {
        sub := strings.TrimSpace(scanner.Text())
        if sub != "" {
            subdomains = append(subdomains, sub)
        }
    }

    var liveHosts []string
    var mu sync.Mutex
    var wg sync.WaitGroup

    concurrency := 30                          // 30 parallel workers for real-time performance
    sem := make(chan struct{}, concurrency)   // Semaphore to throttle concurrency

    for _, sub := range subdomains {
        for _, scheme := range []string{"http", "https"} {
            url := fmt.Sprintf("%s://%s", scheme, sub)

            wg.Add(1)
            sem <- struct{}{}

            go func(url string) {
                defer wg.Done()
                defer func() { <-sem }()

                // Random delay (300ms to 800ms) to mimic human access patterns
                time.Sleep(time.Duration(rand.Intn(500)+300) * time.Millisecond)

                client := &http.Client{
                    Timeout: 5 * time.Second,
                    Transport: &http.Transport{
                        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
                    },
                    CheckRedirect: func(req *http.Request, via []*http.Request) error {
                        return nil
                    },
                }

                req, _ := http.NewRequest("GET", url, nil)

                // Randomize User-Agent
                uaList := []string{
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    "Mozilla/5.0 (X11; Linux x86_64)",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:100.0)",
                }
                req.Header.Set("User-Agent", uaList[rand.Intn(len(uaList))])

                var resp *http.Response
                var err error

                // Retry logic (up to 3 attempts)
                for i := 0; i <= 2; i++ {
                    resp, err = client.Do(req)
                    if err == nil && resp != nil {
                        break
                    }
                    time.Sleep(1 * time.Second)
                }

                if err != nil || resp == nil {
                    return
                }

                status := resp.StatusCode
                title := extractTitle(resp)
                resp.Body.Close()

                if status >= 200 && status <= 403 {
                    line := fmt.Sprintf("%s [%d] %s", url, status, title)
                    fmt.Println("[+] Live:", line)

                    mu.Lock()
                    liveHosts = append(liveHosts, line)
                    mu.Unlock()
                }
            }(url)
        }
    }

    wg.Wait()

    outPath := fmt.Sprintf("%s/%s_live.txt", outputDir, domain)
    err = os.WriteFile(outPath, []byte(strings.Join(liveHosts, "\n")), 0644)
    if err != nil {
        fmt.Println("[-] Failed to write live hosts file:", err)
        return
    }

    fmt.Printf("[+] %d live hosts found.\n", len(liveHosts))
    fmt.Println("[+] Results saved to:", outPath)
}

func extractTitle(resp *http.Response) string {
    tokenizer := html.NewTokenizer(resp.Body)
    for {
        tt := tokenizer.Next()
        switch tt {
        case html.ErrorToken:
            return "No Title"
        case html.StartTagToken, html.SelfClosingTagToken:
            t := tokenizer.Token()
            if t.Data == "title" {
                tokenizer.Next()
                return strings.TrimSpace(tokenizer.Token().Data)
            }
        }
    }
}

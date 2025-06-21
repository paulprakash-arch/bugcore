package discovery

import (
    "bufio"
    "crypto/tls"
    "fmt"
    "math/rand"
    "net/http"
    "os"
    "os/signal"
    "strings"
    "sync"
    "syscall"
    "time"

    "golang.org/x/net/html"
)

func RunDiscovery(domain string, wordlistPath string) {
    liveFile := fmt.Sprintf("output/%s/%s_live.txt", domain, domain)
    file, err := os.Open(liveFile)
    if err != nil {
        fmt.Println("[-] Failed to open live hosts file:", err)
        return
    }
    defer file.Close()

    outputDir := fmt.Sprintf("output/%s/%s_dirs", domain, domain)
    os.MkdirAll(outputDir, 0755)

    var urls []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        parts := strings.Fields(scanner.Text())
        if len(parts) > 0 {
            urls = append(urls, parts[0])
        }
    }

    wordlist := "assets/wordlists/common.txt"
    if wordlistPath != "" {
        wordlist = wordlistPath
    }

    wordsFile, err := os.Open(wordlist)
    if err != nil {
        fmt.Println("[-] Failed to open wordlist:", err)
        return
    }
    defer wordsFile.Close()

    var words []string
    wscan := bufio.NewScanner(wordsFile)
    for wscan.Scan() {
        line := strings.TrimSpace(wscan.Text())
        if line != "" {
            words = append(words, line)
        }
    }

    concurrency := 50
    sem := make(chan struct{}, concurrency)
    var wg sync.WaitGroup
    var mu sync.Mutex
    statusMap := make(map[int][]string)

    client := &http.Client{
        Timeout: 6 * time.Second,
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        },
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return nil
        },
    }

    // Graceful Ctrl+C handling
    stop := make(chan os.Signal, 1)
    signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

    fmt.Printf("[*] Fuzzing %d live hosts with %d words...\n", len(urls), len(words))

    go func() {
        <-stop
        fmt.Println("\n[!] Ctrl+C received. Saving partial results...")
        mu.Lock()
        for code, lines := range statusMap {
            path := fmt.Sprintf("%s/%d.txt", outputDir, code)
            os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
        }
        mu.Unlock()
        fmt.Println("[+] Saved partial results to:", outputDir)
        os.Exit(0)
    }()

    for _, base := range urls {
        for _, word := range words {
            url := strings.TrimRight(base, "/") + "/" + word

            wg.Add(1)
            sem <- struct{}{}

            go func(url string) {
                defer wg.Done()
                defer func() { <-sem }()

                // Panic safety wrapper
                defer func() {
                    if r := recover(); r != nil {
                        fmt.Println("[-] Panic recovered while processing:", url)
                    }
                }()

                req, _ := http.NewRequest("GET", url, nil)
                uaList := []string{
                    "Mozilla/5.0 (X11; Linux x86_64)",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                }
                req.Header.Set("User-Agent", uaList[rand.Intn(len(uaList))])

                var resp *http.Response
                var err error

                for i := 0; i < 2; i++ {
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

                if status >= 200 && status <= 499 {
                    line := fmt.Sprintf("%s [%d] %s", url, status, title)
                    fmt.Println("[+] Found:", line)

                    mu.Lock()
                    statusMap[status] = append(statusMap[status], line)
                    mu.Unlock()
                }
            }(url)
        }
    }

    wg.Wait()

    fmt.Println("[*] Writing results to disk...")
    for code, lines := range statusMap {
        path := fmt.Sprintf("%s/%d.txt", outputDir, code)
        os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
    }

    fmt.Println("[+] Discovery complete. Results saved under:", outputDir)
}

func extractTitle(resp *http.Response) string {
    tokenizer := html.NewTokenizer(resp.Body)
    for {
        tt := tokenizer.Next()
        switch tt {
        case html.ErrorToken:
            return ""
        case html.StartTagToken, html.SelfClosingTagToken:
            t := tokenizer.Token()
            if t.Data == "title" {
                tokenizer.Next()
                return strings.TrimSpace(tokenizer.Token().Data)
            }
        }
    }
}

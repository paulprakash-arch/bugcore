package scanner

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func RunReflectScan(domain string) {
	inputPath := fmt.Sprintf("output/%s/%s_paramurls/paramurls.txt", domain, domain)
	file, err := os.Open(inputPath)
	if err != nil {
		fmt.Println("[-] Failed to open paramurls file:", err)
		return
	}
	defer file.Close()

	payload := "RefTest_1337"
	client := &http.Client{Timeout: 10 * time.Second}

	var reflected []string
	scanner := bufio.NewScanner(file)

	fmt.Println("[*] Scanning URLs for reflection...")

	for scanner.Scan() {
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}
		modified := injectTestPayload(raw, payload)

		resp, err := client.Get(modified)
		if err != nil || resp.Body == nil {
			continue
		}
		defer resp.Body.Close()

		bodyBytes := make([]byte, 1024*128)
		n, _ := resp.Body.Read(bodyBytes)
		body := string(bodyBytes[:n])

		if strings.Contains(body, payload) {
			fmt.Println("[+] Reflected:", modified)
			reflected = append(reflected, modified)
		}
	}

	outDir := fmt.Sprintf("output/%s/%s_paramurls", domain, domain)
	os.MkdirAll(outDir, 0755)
	outPath := fmt.Sprintf("%s/reflected.txt", outDir)
	os.WriteFile(outPath, []byte(strings.Join(reflected, "\n")), 0644)

	fmt.Println("[+] Reflection scan complete. Found:", len(reflected), "reflected URLs")
	fmt.Println("[*] Saved to:", outPath)
}

func injectTestPayload(url, payload string) string {
	if !strings.Contains(url, "?") || !strings.Contains(url, "=") {
		return url
	}
	parts := strings.Split(url, "?")
	base := parts[0]
	query := parts[1]

	params := strings.Split(query, "&")
	for i := range params {
		if strings.Contains(params[i], "=") {
			kv := strings.SplitN(params[i], "=", 2)
			params[i] = kv[0] + "=" + payload
			break
		}
	}
	return base + "?" + strings.Join(params, "&")
}

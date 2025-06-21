package scanner

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func RunCORSScan(domain string) {
	liveFile := fmt.Sprintf("output/%s/%s_live.txt", domain, domain)
	file, err := os.Open(liveFile)
	if err != nil {
		fmt.Println("[-] Could not open live hosts file:", err)
		return
	}
	defer file.Close()

	outputDir := fmt.Sprintf("output/%s/%s_vulns", domain, domain)
	os.MkdirAll(outputDir, 0755)
	outputFile := fmt.Sprintf("%s/cors.txt", outputDir)

	out, err := os.Create(outputFile)
	if err != nil {
		fmt.Println("[-] Could not create CORS output file:", err)
		return
	}
	defer out.Close()

	fmt.Println("[*] Scanning for CORS misconfigurations...")

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := strings.Fields(scanner.Text())[0]
		testOrigin := "https://evil.com"

		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Origin", testOrigin)

		client := &http.Client{Timeout: 6 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
		allowCreds := resp.Header.Get("Access-Control-Allow-Credentials")

		if allowOrigin == "*" || allowOrigin == testOrigin {
			vuln := fmt.Sprintf("[!] Potential CORS misconfig: %s | ACAO: %s | ACAC: %s", url, allowOrigin, allowCreds)
			fmt.Println(vuln)
			out.WriteString(vuln + "\n")
		}
	}

	fmt.Println("[+] CORS scan complete. Results saved to:", outputFile)
}

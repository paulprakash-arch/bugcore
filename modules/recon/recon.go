package recon

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"os"
)

func RunRecon(domain string) {
	var results []string

	// 1. HackerTarget API
	fmt.Println("[*] Fetching from HackerTarget...")
	hackerData := fetchFromHackerTarget(domain)
	results = append(results, hackerData...)

	// 2. CRT.sh API
	fmt.Println("[*] Fetching from CRT.sh...")
	crtshData := fetchFromCRT(domain)
	results = append(results, crtshData...)

	// Clean + dedupe
	unique := make(map[string]bool)
	for _, r := range results {
		r = strings.TrimSpace(r)
		if r != "" && strings.HasSuffix(r, domain) {
			unique[r] = true
		}
	}

	var final []string
	for sub := range unique {
		final = append(final, sub)
	}

	// Create per-domain output directory
	outputDir := fmt.Sprintf("output/%s", domain)
	os.MkdirAll(outputDir, 0755)

	// Write subdomains to file inside that folder
	filePath := fmt.Sprintf("%s/%s_subdomains.txt", outputDir, domain)
	err := ioutil.WriteFile(filePath, []byte(strings.Join(final, "\n")), 0644)
	if err != nil {
		fmt.Println("[-] Failed to write output:", err)
		return
	}

	fmt.Printf("[+] Found %d unique subdomains.\n", len(final))
	fmt.Println("[+] Results saved to:", filePath)

	// Call live probing + enrichment
	ProbeLiveHosts(domain)
	EnrichHosts(domain)
}

func fetchFromHackerTarget(domain string) []string {
	var results []string
	resp, err := http.Get("https://api.hackertarget.com/hostsearch/?q=" + domain)
	if err != nil {
		fmt.Println("[-] HackerTarget failed:", err)
		return results
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		parts := strings.Split(line, ",")
		if len(parts) > 0 {
			results = append(results, parts[0])
		}
	}
	return results
}

func fetchFromCRT(domain string) []string {
	var results []string
	url := "https://crt.sh/?q=%25." + domain + "&output=json"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "bugcore/1.0")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("[-] CRT.sh failed:", err)
		return results
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	re := regexp.MustCompile(`"common_name":"(.*?)"`)
	matches := re.FindAllStringSubmatch(string(body), -1)

	for _, m := range matches {
		if len(m) > 1 {
			results = append(results, m[1])
		}
	}
	return results
}

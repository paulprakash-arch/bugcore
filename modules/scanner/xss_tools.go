package scanner

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func RunXSSTools(domain string) {
	paramFile := fmt.Sprintf("output/%s/%s_paramurls/paramurls.txt", domain, domain)
	urls := readLines(paramFile)
	if len(urls) == 0 {
		fmt.Println("[-] No parameterized URLs found for XSStrike/Dalfox")
		return
	}

	outDir := fmt.Sprintf("output/%s/%s_vulns", domain, domain)
	os.MkdirAll(outDir, 0755)

	// Run XSStrike
	xssStrikeOut := fmt.Sprintf("%s/xss_xsstrike.txt", outDir)
	runXSStrike(urls, xssStrikeOut)

	// Run Dalfox
	dalfoxOut := fmt.Sprintf("%s/xss_dalfox.txt", outDir)
	runDalfox(urls, dalfoxOut)
}

func runXSStrike(urls []string, outFile string) {
	fmt.Println("[*] Running XSStrike on targets...")

	var output strings.Builder

	for _, target := range urls {
		cmd := exec.Command("xsstrike", "-u", target, "--crawl", "--skip")
		stdout, err := cmd.CombinedOutput()
		if err != nil {
			output.WriteString(fmt.Sprintf("[!] Error on: %s\n%s\n", target, err))
			continue
		}
		output.WriteString(fmt.Sprintf("[Target]: %s\n%s\n\n", target, stdout))
	}

	os.WriteFile(outFile, []byte(output.String()), 0644)
	fmt.Println("[+] XSStrike scan complete. Saved to:", outFile)
}

func runDalfox(urls []string, outFile string) {
	fmt.Println("[*] Running Dalfox on targets...")

	var output strings.Builder

	for _, target := range urls {
		cmd := exec.Command("dalfox", "url", target, "--skip-bav", "--only-poc", "--no-spinner")
		stdout, err := cmd.CombinedOutput()
		if err != nil {
			output.WriteString(fmt.Sprintf("[!] Error on: %s\n%s\n", target, err))
			continue
		}
		output.WriteString(fmt.Sprintf("[Target]: %s\n%s\n\n", target, stdout))
	}

	os.WriteFile(outFile, []byte(output.String()), 0644)
	fmt.Println("[+] Dalfox scan complete. Saved to:", outFile)
}

func readLines(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		trimmed := strings.TrimSpace(scanner.Text())
		if trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	return lines
}

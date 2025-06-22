package scanner

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// RunParamFinder uses gau and katana to find URLs with parameters
func RunParamFinder(domain string) {
	outputDir := fmt.Sprintf("output/%s/%s_paramurls", domain, domain)
	os.MkdirAll(outputDir, 0755)

	paramSet := make(map[string]bool)

	// -----------------------------
	// GAU
	// -----------------------------
	fmt.Println("[*] Running gau...")
	gauCmd := exec.Command("gau", domain)
	gauOut, err := gauCmd.Output()
	if err != nil {
		fmt.Println("[-] gau failed:", err)
	} else {
		gauPath := filepath.Join(outputDir, "gau.txt")
		os.WriteFile(gauPath, gauOut, 0644)

		scanner := bufio.NewScanner(strings.NewReader(string(gauOut)))
		for scanner.Scan() {
			url := scanner.Text()
			if strings.Contains(url, "?") {
				paramSet[url] = true
			}
		}
	}

	// -----------------------------
	// Katana
	// -----------------------------
	fmt.Println("[*] Running katana...")
	katanaCmd := exec.Command("katana", "-u", domain, "-silent")
	katanaOut, err := katanaCmd.Output()
	if err != nil {
		fmt.Println("[-] katana failed:", err)
	} else {
		katanaPath := filepath.Join(outputDir, "katana.txt")
		os.WriteFile(katanaPath, katanaOut, 0644)

		scanner := bufio.NewScanner(strings.NewReader(string(katanaOut)))
		for scanner.Scan() {
			url := scanner.Text()
			if strings.Contains(url, "?") {
				paramSet[url] = true
			}
		}
	}

	// -----------------------------
	// Final merge & dedup
	// -----------------------------
	var final []string
	for url := range paramSet {
		final = append(final, url)
	}
	resultPath := filepath.Join(outputDir, "paramurls.txt")
	err = os.WriteFile(resultPath, []byte(strings.Join(final, "\n")), 0644)
	if err != nil {
		fmt.Println("[-] Failed to write output:", err)
		return
	}

	fmt.Println("[+] Parameterized URLs saved to:", resultPath)
}

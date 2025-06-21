package recon

import (
    "bufio"
    "fmt"
    "net"
    "os"
    "strings"

    "github.com/jamesog/iptoasn"
)

func EnrichHosts(domain string) {
    // Define and ensure target-specific output folder
    outputDir := fmt.Sprintf("output/%s", domain)
    os.MkdirAll(outputDir, 0755)

    livePath := fmt.Sprintf("%s/%s_live.txt", outputDir, domain)
    file, err := os.Open(livePath)
    if err != nil {
        fmt.Println("[-] Cannot open live hosts file:", err)
        return
    }
    defer file.Close()

    fmt.Println("[*] Enriching hosts with IP → ASN + Org info...")

    scanner := bufio.NewScanner(file)
    var output []string

    for scanner.Scan() {
        line := scanner.Text()
        parts := strings.Fields(line)
        if len(parts) == 0 {
            continue
        }

        url := parts[0]
        host := extractHostname(url)
        ips, err := net.LookupIP(host)
        if err != nil || len(ips) == 0 {
            continue
        }

        ipStr := ips[0].String()

        // ASN lookup via iptoasn
        info, err := iptoasn.LookupIP(ipStr)
        var asnInfo string
        if err != nil {
            asnInfo = "ASN lookup failed"
        } else {
            asnInfo = fmt.Sprintf("AS%d (%s)", info.ASNum, info.ASName)
        }

        lineOut := fmt.Sprintf("%s [%s] %s", url, ipStr, asnInfo)
        output = append(output, lineOut)
    }

    outFile := fmt.Sprintf("%s/%s_enriched.txt", outputDir, domain)
    err = os.WriteFile(outFile, []byte(strings.Join(output, "\n")), 0644)
    if err != nil {
        fmt.Println("[-] Failed to write enrichment file:", err)
        return
    }

    fmt.Println("[+] Enrichment complete. Saved to:", outFile)
}

// extractHostname strips the protocol and port from a URL to get clean hostname
func extractHostname(url string) string {
    url = strings.TrimPrefix(url, "http://")
    url = strings.TrimPrefix(url, "https://")
    url = strings.Split(url, "/")[0]
    url = strings.Split(url, ":")[0]
    return url
}


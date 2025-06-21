package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/paulprakash-arch/bugcore/modules/scanner"
)

var corsFlag bool
var xssScan bool
var scanTarget string

var scannerCmd = &cobra.Command{
	Use:   "scanner",
	Short: "Run vulnerability scans on live hosts",
	Run: func(cmd *cobra.Command, args []string) {
		if corsFlag {
			fmt.Println("[*] Starting CORS scan on:", scanTarget)
			scanner.RunCORSScan(scanTarget)
		} else {
			fmt.Println("[-] No scan type selected. Use --cors to scan for CORS misconfigs.")
		}

                 if xssScan {
	                fmt.Println("[*] Running XSS scan...")
	                scanner.RunXSSScan(scanTarget)
                 }

	},
}

func init() {
	scannerCmd.Flags().StringVarP(&scanTarget, "domain", "d", "", "Target domain (required)")
	scannerCmd.MarkFlagRequired("domain")

	scannerCmd.Flags().BoolVar(&corsFlag, "cors", false, "Run CORS misconfiguration scanner")
        scannerCmd.Flags().BoolVar(&xssScan, "xss", false, "Scan for reflected XSS vulnerabilities")



	rootCmd.AddCommand(scannerCmd)
}

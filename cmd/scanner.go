package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/paulprakash-arch/bugcore/modules/scanner"
)

var scanTarget string
var corsFlag bool
var xssScan bool
var xssDeepScan bool
var paramScan bool
var reflectScan bool

var scannerCmd = &cobra.Command{
	Use:   "scanner",
	Short: "Run vulnerability scans on live hosts or param URLs",
	Run: func(cmd *cobra.Command, args []string) {
		if corsFlag {
			fmt.Println("[*] Starting CORS scan on:", scanTarget)
			scanner.RunCORSScan(scanTarget)
		}

		if xssScan {
			fmt.Println("[*] Running XSS scanner (basic)...")
			scanner.RunXSSScan(scanTarget)
		}

		if xssDeepScan {
			fmt.Println("[*] Running deep browser-based XSS scan...")
			scanner.RunXSSDeepScan(scanTarget)
		}

		if paramScan {
			fmt.Println("[*] Running param URL finder...")
			scanner.RunParamFinder(scanTarget)
		}
                if reflectScan {
	                fmt.Println("[*] Running reflection-based param scan...")
	                scanner.RunReflectScan(scanTarget)
                }

		if !corsFlag && !xssScan && !xssDeepScan && !paramScan {
			fmt.Println("[-] No scanner module selected. Use --help for available flags.")
		}
	},
}

func init() {
	scannerCmd.Flags().StringVarP(&scanTarget, "domain", "d", "", "Target domain (required)")
	scannerCmd.MarkFlagRequired("domain")

	scannerCmd.Flags().BoolVar(&corsFlag, "cors", false, "Run CORS misconfiguration scanner")
	scannerCmd.Flags().BoolVar(&xssScan, "xss", false, "Run basic reflected XSS scanner")
	scannerCmd.Flags().BoolVar(&xssDeepScan, "xssdeep", false, "Run browser-based XSS scanner with Chrome")
	scannerCmd.Flags().BoolVar(&paramScan, "paramurls", false, "Run parameterized URL discovery")
        scannerCmd.Flags().BoolVar(&reflectScan, "reflect", false, "Find URLs where parameters are reflected")

	rootCmd.AddCommand(scannerCmd)
}

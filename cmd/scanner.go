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
var xssTools bool
var jsScan bool
var openRedirectScan bool
var openRedirectAdvScan bool


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

		if xssTools {
			fmt.Println("[*] Running XSStrike and Dalfox scans...")
			scanner.RunXSSTools(scanTarget)
		}

		if jsScan {
			fmt.Println("[*] Running JavaScript secrets and endpoint scanner...")
			scanner.RunJSFinder(scanTarget)
		}

		if openRedirectScan {
			fmt.Println("[*] Running Open Redirect scanner...")
			scanner.RunOpenRedirectScan(scanTarget)
		}

		if openRedirectAdvScan {
			fmt.Println("[*] Running Advanced Open Redirect scanner...")
			scanner.RunOpenRedirectAdv(
				scanTarget,
				[]string{
					fmt.Sprintf("output/%s/%s_paramurls/gau.txt", scanTarget, scanTarget),
					fmt.Sprintf("output/%s/%s_paramurls/paramurls.txt", scanTarget, scanTarget),
				},
				fmt.Sprintf("output/%s/%s_vulns/open_redirect_adv.txt", scanTarget, scanTarget),
				10,
			)
		}


		if !corsFlag && !xssScan && !xssDeepScan && !paramScan &&
			!reflectScan && !xssTools && !jsScan && !openRedirectScan && !openRedirectAdvScan {
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
	scannerCmd.Flags().BoolVar(&xssTools, "xsstools", false, "Run XSStrike and Dalfox on parameterized URLs")
	scannerCmd.Flags().BoolVar(&jsScan, "jsfinder", false, "Scan JS files for secrets and endpoints")
	scannerCmd.Flags().BoolVar(&openRedirectScan, "openredirect", false, "Scan for basic open redirects")
	scannerCmd.Flags().BoolVar(&openRedirectAdvScan, "openredirect-adv", false, "Scan for browser-validated advanced open redirects")

	rootCmd.AddCommand(scannerCmd)
}

package cmd

import (
	"fmt"

	"github.com/paulprakash-arch/bugcore/modules/auth"
	"github.com/spf13/cobra"
)

var authTarget string
var authBypassFlag bool
var jwtScanFlag bool
var customLiveFile string

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Run authentication and authorization attack modules",
	Run: func(cmd *cobra.Command, args []string) {
		if authTarget == "" {
			fmt.Println("[-] Please provide a domain with -d or --domain.")
			return
		}

		if authBypassFlag {
			fmt.Println("[*] Running auth bypass module...")
			if customLiveFile != "" {
				auth.RunAuthBypassFromFile(authTarget, customLiveFile)
			} else {
				auth.RunAuthBypassScan(authTarget)
			}
		}

		if jwtScanFlag {
			fmt.Println("[*] Running JWT vulnerability scanner...")
			auth.RunJWTScan(authTarget)
		}

		if !authBypassFlag && !jwtScanFlag {
			fmt.Println("[-] No auth module selected. Use --help to see available flags.")
		}
	},
}

func init() {
	authCmd.Flags().StringVarP(&authTarget, "domain", "d", "", "Target domain (required)")
	authCmd.MarkFlagRequired("domain")

	authCmd.Flags().BoolVar(&authBypassFlag, "authbypass", false, "Scan for browser-validated auth bypass techniques")
	authCmd.Flags().BoolVar(&jwtScanFlag, "jwt", false, "Scan for JWT-related vulnerabilities")

	authCmd.Flags().StringVar(&customLiveFile, "live", "", "Path to custom live hosts file (optional)")

	rootCmd.AddCommand(authCmd)
}

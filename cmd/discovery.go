package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/paulprakash-arch/bugcore/modules/discovery"
)

var discTarget string
var wordlistPath string

var discoveryCmd = &cobra.Command{
	Use:   "discovery",
	Short: "Bruteforce directories and files on all live hosts",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("[*] Starting discovery on:", domain)
		discovery.RunDiscovery(discTarget, wordlistPath)
	},
}


func init() {
	discoveryCmd.Flags().StringVarP(&discTarget, "domain", "d", "", "Target domain")
	discoveryCmd.MarkFlagRequired("domain")

	discoveryCmd.Flags().StringVarP(&wordlistPath, "wordlist", "w", "", "Custom wordlist path (optional)")

	rootCmd.AddCommand(discoveryCmd)
}

package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/paulprakash-arch/bugcore/modules/recon"
)

// Local variable only for the recon command
var reconTarget string

var reconCmd = &cobra.Command{
	Use:   "recon",
	Short: "Perform subdomain enumeration on a target domain",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("[*] Starting recon on:", domain)
		recon.RunRecon(reconTarget)
	},
}

func init() {
	reconCmd.Flags().StringVarP(&reconTarget, "domain", "d", "", "Target domain")
	reconCmd.MarkFlagRequired("domain")

	rootCmd.AddCommand(reconCmd)
}

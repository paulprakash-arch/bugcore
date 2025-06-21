package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// Global flag variable used across all subcommands
var domain string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "bugcore",
	Short: "BugCore: A modular bug bounty automation tool",
	Long: `An extensible CLI tool for recon, fuzzing, and vulnerability scanning.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Cobra supports persistent flags, which are global to all subcommands
	// Uncomment the below if you want a global config file flag:
	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.bugcore.yaml)")

	// This is a local flag (not global)
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

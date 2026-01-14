package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "gorecon",
	Short: "A heuristic-based autonomous reconnaissance tool",
	Long: `GoRecon is a CLI tool that automates the reconnaissance stage.
It uses a decision engine to passively find subdomains, port scan active targets, 
and heuristically detect services.`,
	// This function runs if no subcommand is provided
	Run: func(cmd *cobra.Command, args []string) {
		// Just print help
		// fmt.Println("You printed ", args)
		cmd.Help()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once.
func Execute() {
	print("command is executing")
	if err := rootCmd.Execute(); err != nil {
		// fmt.Println(err)
		os.Exit(1)
	}
	print("cmd is ending")
}

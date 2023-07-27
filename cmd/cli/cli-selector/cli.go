package cli

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "aws-eks-na-cli",
	Short: "aws-eks-na-cli - a CLI to dump BPF states",
	Long: `aws-eks-na-cli CLI can be used to dump eBPF maps,
programs, qdiscs and so on`,
	Run: func(cmd *cobra.Command, args []string) {

	},
}

func init() {
	rootCmd.AddCommand(subCmd)
}

func Execute() error {
	return rootCmd.Execute()
}

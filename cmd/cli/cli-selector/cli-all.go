package cli

import (
	"fmt"
	"strconv"

	"github.com/achevuru/aws-network-policy-agent/pkg/clihelper"
	"github.com/spf13/cobra"
)

var subCmd = &cobra.Command{
	Use:     "ebpf",
	Aliases: []string{"ebpf"},
	Short:   "Dump all ebpf related data",
	Run: func(cmd *cobra.Command, args []string) {

	},
}

var progCmd = &cobra.Command{
	Use:     "progs",
	Aliases: []string{"p"},
	Short:   "Dump all ebpf program related data",
	Args:    cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		err := clihelper.ProgShow()
		if err != nil {
			fmt.Println("Failed to execute the cmd - ", err)
		}
	},
}

var mapCmd = &cobra.Command{
	Use:     "maps",
	Aliases: []string{"m"},
	Short:   "Dump all ebpf maps related data",
	Args:    cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		err := clihelper.MapShow()
		if err != nil {
			fmt.Println("Failed to execute the cmd - ", err)
		}
	},
}

var ebpfdataCmd = &cobra.Command{
	Use:     "loaded-ebpfdata",
	Aliases: []string{"e"},
	Short:   "Dump all ebpf related data",
	Args:    cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		err := clihelper.Show()
		if err != nil {
			fmt.Println("Failed to execute the cmd - ", err)
		}
	},
}

var mapWalkCmd = &cobra.Command{
	Use:     "dump-maps",
	Aliases: []string{"d"},
	Short:   "Dump all ebpf maps related data",
	Args:    cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		mapID := args[0]
		strMapID, _ := strconv.Atoi(mapID)
		err := clihelper.MapWalk(strMapID)
		if err != nil {
			fmt.Println("Failed to execute the cmd - ", err)
		}
	},
}

func init() {

	subCmd.AddCommand(progCmd)
	subCmd.AddCommand(mapCmd)
	subCmd.AddCommand(ebpfdataCmd)
	subCmd.AddCommand(mapWalkCmd)
}

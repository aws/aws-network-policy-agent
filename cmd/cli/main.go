package main

import (
	"fmt"
	"os"

	cli "github.com/achevuru/aws-network-policy-agent/cmd/cli/cli-selector"
)

func main() {

	if err := cli.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "There was an error while executing your CLI '%s'", err)
		os.Exit(1)
	}
}

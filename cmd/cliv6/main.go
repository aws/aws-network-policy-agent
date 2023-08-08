package main

import (
	"fmt"
	"os"

	cli "github.com/aws/aws-network-policy-agent/cmd/cliv6/cli-selector-v6"
)

func main() {

	if err := cli.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "There was an error while executing your CLI '%s'", err)
		os.Exit(1)
	}
}

package aws

import (
	"github.com/spf13/pflag"
)

const (
	flagAWSRegion    = "aws-region"
	flagAWSAccountID = "aws-account-id"
)

type CloudConfig struct {
	// AWS Region for the kubernetes cluster
	Region string
	// AccountID for the kubernetes cluster
	AccountID string
	// Cluster Name for the kubernetes cluster
	ClusterName string
}

func (cfg *CloudConfig) BindFlags(fs *pflag.FlagSet) {
	fs.StringVar(&cfg.Region, flagAWSRegion, "", "AWS Region for the kubernetes cluster")
	fs.StringVar(&cfg.AccountID, flagAWSAccountID, "", "AWS AccountID for the kubernetes cluster")
}

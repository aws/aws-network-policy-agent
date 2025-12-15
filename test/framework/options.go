package framework

import (
	"flag"

	"github.com/pkg/errors"
	"k8s.io/client-go/tools/clientcmd"
)

var GlobalOptions Options

func init() {
	GlobalOptions.BindFlags()
}

type Options struct {
	AWSRegion         string
	KubeConfig        string
	ClusterName       string
	NgNameLabelKey    string
	NgNameLabelVal    string
	EKSEndpoint       string
	TestImageRegistry string
	IpFamily          string
	IsAutoCluster     bool
}

func (options *Options) BindFlags() {
	flag.StringVar(&options.KubeConfig, "cluster-kubeconfig", "", "Path to kubeconfig containing embedded authinfo (required)")
	flag.StringVar(&options.AWSRegion, "aws-region", "", `AWS Region for the kubernetes cluster`)
	flag.StringVar(&options.ClusterName, "cluster-name", "", `Kubernetes cluster name (required)`)
	flag.StringVar(&options.NgNameLabelKey, "ng-name-label-key", "eks.amazonaws.com/nodegroup", "label key used to identify nodegroup name")
	flag.StringVar(&options.NgNameLabelVal, "ng-name-label-val", "", "label value with the nodegroup name")
	flag.StringVar(&options.EKSEndpoint, "eks-endpoint", "", "optional eks api server endpoint")
	flag.StringVar(&options.TestImageRegistry, "test-image-registry", "617930562442.dkr.ecr.us-west-2.amazonaws.com", `AWS registry where the e2e test images are stored`)
	flag.StringVar(&options.IpFamily, "ip-family", "IPv4", `IP family for the cluster`)
	flag.BoolVar(&options.IsAutoCluster, "is-auto-cluster", false, "Set to true if running on auto-managed cluster (affects DNS configuration)")
}

func (options *Options) Validate() error {
	if len(options.KubeConfig) == 0 {
		return errors.Errorf("%s must be set!", clientcmd.RecommendedConfigPathFlag)
	}
	if len(options.ClusterName) == 0 {
		return errors.Errorf("%s must be set!", "cluster-name")
	}
	if len(options.TestImageRegistry) == 0 {
		return errors.Errorf("%s must be set!", "test-image-registry")
	}
	return nil
}

package aws

import (
	"context"

	"github.com/aws/aws-network-policy-agent/pkg/aws/services"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/pkg/errors"
)

const (
	resourceID  = "resource-id"
	resourceKey = "key"
)

var (
	clusterNameTags = []string{
		"aws:eks:cluster-name",
	}
)

type Cloud interface {
	//CloudWatch provides API access to AWS Cloudwatch Service
	CloudWatchLogs() services.CloudWatchLogs

	// AccountID provides AccountID for the kubernetes cluster
	AccountID() string

	// Region for the kubernetes cluster
	Region() string

	// Cluster Name
	ClusterName() string
}

func NewCloud(ctx context.Context, cfg CloudConfig) (Cloud, error) {

	// Load the AWS SDK configuration
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load AWS config")
	}

	metadata := services.NewEC2Metadata(awsCfg)
	if len(cfg.Region) == 0 {
		region, err := metadata.Region(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "failed to introspect region from EC2Metadata, specify --aws-region instead if EC2Metadata is unavailable")
		}
		cfg.Region = region
	}

	// Update the region in the config
	if cfg.Region != "" {
		awsCfg.Region = cfg.Region
	}

	instanceIdentityDocument, err := metadata.GetInstanceIdentityDocument(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get instanceIdentityDocument from EC2Metadata")
	}

	ec2ServiceClient := ec2.NewFromConfig(awsCfg)
	cfg.ClusterName = getClusterName(ctx, ec2ServiceClient, instanceIdentityDocument)

	return &defaultCloud{
		cfg:            cfg,
		cloudWatchlogs: services.NewCloudWatchLogs(awsCfg),
	}, nil
}

var _ Cloud = &defaultCloud{}

type defaultCloud struct {
	cfg CloudConfig

	cloudWatchlogs services.CloudWatchLogs
}

func (c *defaultCloud) CloudWatchLogs() services.CloudWatchLogs {
	return c.cloudWatchlogs
}

func (c *defaultCloud) AccountID() string {
	return c.cfg.AccountID
}

func (c *defaultCloud) Region() string {
	return c.cfg.Region
}

func (c *defaultCloud) ClusterName() string {
	return c.cfg.ClusterName
}

func getClusterName(ctx context.Context, ec2ServiceClient *ec2.Client, instanceIdentityDocument imds.InstanceIdentityDocument) string {
	var clusterName string
	var err error
	for _, tag := range clusterNameTags {
		clusterName, err = getClusterTag(ctx, tag, ec2ServiceClient, instanceIdentityDocument)
		if err == nil && clusterName != "" {
			break
		}
	}
	if clusterName == "" {
		clusterName = utils.DEFAULT_CLUSTER_NAME
	}
	return clusterName
}

// getClusterTag is used to retrieve a tag from the ec2 instance
func getClusterTag(ctx context.Context, tagKey string, ec2ServiceClient *ec2.Client, instanceIdentityDocument imds.InstanceIdentityDocument) (string, error) {
	input := &ec2.DescribeTagsInput{
		Filters: []types.Filter{
			{
				Name: aws.String(resourceID),
				Values: []string{
					instanceIdentityDocument.InstanceID,
				},
			}, {
				Name: aws.String(resourceKey),
				Values: []string{
					tagKey,
				},
			},
		},
	}

	//log.Infof("Calling DescribeTags with key %s", tagKey)
	results, err := ec2ServiceClient.DescribeTags(ctx, input)
	if err != nil {
		return "", errors.Wrap(err, "GetClusterTag: Unable to obtain EC2 instance tags")
	}

	if len(results.Tags) < 1 {
		return "", errors.Errorf("GetClusterTag: No tag matching key: %s", tagKey)
	}

	return *results.Tags[0].Value, nil
}

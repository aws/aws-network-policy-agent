package aws

import (
	"context"

	"github.com/aws/aws-network-policy-agent/pkg/aws/services"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
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

	// Cluster Name
	ClusterName() string
}

// NewCloud builds a Cloud for the CloudWatch-logs path. region and instanceID come from ipamd; no IMDS.
func NewCloud(ctx context.Context, region string, instanceID string) (Cloud, error) {
	if region == "" {
		return nil, errors.New("region not provided; cannot initialize AWS session for CloudWatch logs")
	}
	if instanceID == "" {
		return nil, errors.New("instance ID not provided; cannot resolve cluster name for CloudWatch logs")
	}

	// Pass the region explicitly so the SDK doesn't run its region-resolution
	// chain (which would otherwise reach IMDS).
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, errors.Wrap(err, "failed to load AWS config")
	}

	ec2ServiceClient := ec2.NewFromConfig(awsCfg)

	return &defaultCloud{
		clusterName:    getClusterName(ctx, ec2ServiceClient, instanceID),
		cloudWatchlogs: services.NewCloudWatchLogs(awsCfg),
	}, nil
}

var _ Cloud = &defaultCloud{}

type defaultCloud struct {
	clusterName    string
	cloudWatchlogs services.CloudWatchLogs
}

func (c *defaultCloud) CloudWatchLogs() services.CloudWatchLogs {
	return c.cloudWatchlogs
}

func (c *defaultCloud) ClusterName() string {
	return c.clusterName
}

func getClusterName(ctx context.Context, ec2ServiceClient *ec2.Client, instanceID string) string {
	var clusterName string
	var err error
	for _, tag := range clusterNameTags {
		clusterName, err = getClusterTag(ctx, tag, ec2ServiceClient, instanceID)
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
func getClusterTag(ctx context.Context, tagKey string, ec2ServiceClient *ec2.Client, instanceID string) (string, error) {
	input := &ec2.DescribeTagsInput{
		Filters: []types.Filter{
			{
				Name: aws.String(resourceID),
				Values: []string{
					instanceID,
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

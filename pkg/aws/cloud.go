package aws

import (
	"context"

	"github.com/achevuru/aws-network-policy-agent/pkg/aws/services"
	"github.com/achevuru/aws-network-policy-agent/pkg/utils"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
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

func NewCloud(cfg CloudConfig) (Cloud, error) {
	sess := session.Must(session.NewSession(aws.NewConfig()))
	//injectUserAgent(&sess.Handlers)

	metadata := services.NewEC2Metadata(sess)
	if len(cfg.Region) == 0 {
		region, err := metadata.Region()
		if err != nil {
			return nil, errors.Wrap(err, "failed to introspect region from EC2Metadata, specify --aws-region instead if EC2Metadata is unavailable")
		}
		cfg.Region = region
	}

	awsCfg := aws.NewConfig().WithRegion(cfg.Region).WithSTSRegionalEndpoint(endpoints.RegionalSTSEndpoint)
	sess = sess.Copy(awsCfg)
	if len(cfg.AccountID) == 0 {
		sts := services.NewSTS(sess)
		accountID, err := sts.AccountID(context.Background())
		if err != nil {
			return nil, errors.Wrap(err, "failed to introspect accountID from STS, specify --aws-account-id instead if STS is unavailable")
		}
		cfg.AccountID = accountID
	}

	instanceIdentityDocument, err := metadata.GetInstanceIdentityDocument()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get instanceIdentityDocument from EC2Metadata")
	}
	ec2ServiceClient := ec2.New(sess)
	cfg.ClusterName = getClusterName(ec2ServiceClient, instanceIdentityDocument)

	return &defaultCloud{
		cfg:            cfg,
		cloudWatchlogs: services.NewCloudWatchLogs(sess),
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

func getClusterName(ec2ServiceClient ec2iface.EC2API, instanceIdentityDocument ec2metadata.EC2InstanceIdentityDocument) string {
	var clusterName string
	var err error
	for _, tag := range clusterNameTags {
		clusterName, err = getClusterTag(tag, ec2ServiceClient, instanceIdentityDocument)
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
func getClusterTag(tagKey string, ec2ServiceClient ec2iface.EC2API, instanceIdentityDocument ec2metadata.EC2InstanceIdentityDocument) (string, error) {
	input := ec2.DescribeTagsInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String(resourceID),
				Values: []*string{
					aws.String(instanceIdentityDocument.InstanceID),
				},
			}, {
				Name: aws.String(resourceKey),
				Values: []*string{
					aws.String(tagKey),
				},
			},
		},
	}

	//log.Infof("Calling DescribeTags with key %s", tagKey)
	results, err := ec2ServiceClient.DescribeTags(&input)
	if err != nil {
		return "", errors.Wrap(err, "GetClusterTag: Unable to obtain EC2 instance tags")
	}

	if len(results.Tags) < 1 {
		return "", errors.Errorf("GetClusterTag: No tag matching key: %s", tagKey)
	}

	return aws.StringValue(results.Tags[0].Value), nil
}

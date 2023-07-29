package aws

import (
	"context"

	"github.com/achevuru/aws-network-policy-agent/pkg/aws/services"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/pkg/errors"
)

type Cloud interface {
	//CloudWatch provides API access to AWS Cloudwatch Service
	CloudWatchLogs() services.CloudWatchLogs

	// AccountID provides AccountID for the kubernetes cluster
	AccountID() string

	// Region for the kubernetes cluster
	Region() string
}

func NewCloud(cfg CloudConfig) (Cloud, error) {
	sess := session.Must(session.NewSession(aws.NewConfig()))
	//injectUserAgent(&sess.Handlers)

	if len(cfg.Region) == 0 {
		metadata := services.NewEC2Metadata(sess)
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

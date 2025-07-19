package services

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

type EC2Metadata interface {
	Region(ctx context.Context) (string, error)
	GetInstanceIdentityDocument(ctx context.Context) (imds.InstanceIdentityDocument, error)
}

// NewEC2Metadata constructs new EC2Metadata implementation.
func NewEC2Metadata(cfg aws.Config) EC2Metadata {
	return &defaultEC2Metadata{
		client: imds.NewFromConfig(cfg),
	}
}

type defaultEC2Metadata struct {
	client *imds.Client
}

func (m *defaultEC2Metadata) Region(ctx context.Context) (string, error) {
	result, err := m.client.GetRegion(ctx, &imds.GetRegionInput{})
	if err != nil {
		return "", err
	}
	return result.Region, nil
}

func (m *defaultEC2Metadata) GetInstanceIdentityDocument(ctx context.Context) (imds.InstanceIdentityDocument, error) {
	result, err := m.client.GetInstanceIdentityDocument(ctx, &imds.GetInstanceIdentityDocumentInput{})
	if err != nil {
		return imds.InstanceIdentityDocument{}, err
	}
	return result.InstanceIdentityDocument, nil
}

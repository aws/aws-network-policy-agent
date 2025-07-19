package imds

import (
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

// EC2Metadata wraps the methods from the amazon-sdk-go-v2's imds package
type EC2Metadata interface {
	GetMetadata(ctx context.Context, path string) (string, error)
	Region(ctx context.Context) (string, error)
}

func GetMetaData(key string) (string, error) {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRetryMaxAttempts(10))
	if err != nil {
		return "", fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := imds.NewFromConfig(cfg)
	resp, err := client.GetMetadata(ctx, &imds.GetMetadataInput{Path: key})
	if err != nil {
		return "", fmt.Errorf("get instance metadata: failed to retrieve %s - %s", key, err)
	}
	defer resp.Content.Close()

	content, err := io.ReadAll(resp.Content)
	if err != nil {
		return "", fmt.Errorf("failed to read metadata content: %w", err)
	}

	return string(content), nil
}

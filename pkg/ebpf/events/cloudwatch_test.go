package events

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-network-policy-agent/pkg/aws/services"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

type failingLogStreamClient struct {
	services.CloudWatchLogs
	createCalls int
	putCalls    int
}

func (c *failingLogStreamClient) CreateLogStream(context.Context, *cloudwatchlogs.CreateLogStreamInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.CreateLogStreamOutput, error) {
	c.createCalls++
	return nil, errors.New("access denied")
}

func (c *failingLogStreamClient) PutLogEvents(context.Context, *cloudwatchlogs.PutLogEventsInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutLogEventsOutput, error) {
	c.putCalls++
	return &cloudwatchlogs.PutLogEventsOutput{}, nil
}

func TestPublishDataToCloudwatchRetriesFailedLogStream(t *testing.T) {
	oldClient, oldStream, oldToken := cwl, logStreamName, sequenceToken
	t.Cleanup(func() { cwl, logStreamName, sequenceToken = oldClient, oldStream, oldToken })
	client := &failingLogStreamClient{}
	cwl, logStreamName, sequenceToken = client, "", ""

	for i := 1; i <= 2; i++ {
		publishDataToCloudwatch(context.Background(), "policy event")
		if client.createCalls != i {
			t.Fatalf("CreateLogStream calls = %d, want %d", client.createCalls, i)
		}
		if client.putCalls != 0 {
			t.Fatalf("PutLogEvents called %d times after failed stream creation", client.putCalls)
		}
		if sequenceToken != "" {
			t.Fatalf("sequence token = %q after failed stream creation", sequenceToken)
		}
	}
}

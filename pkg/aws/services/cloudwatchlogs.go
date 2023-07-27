package services

import (
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs/cloudwatchlogsiface"
)

type CloudWatchLogs interface {
	cloudwatchlogsiface.CloudWatchLogsAPI
}

func NewCloudWatchLogs(session *session.Session) CloudWatchLogs {
	return &defaultCloudWatchLogs{
		CloudWatchLogsAPI: cloudwatchlogs.New(session),
	}
}

type defaultCloudWatchLogs struct {
	cloudwatchlogsiface.CloudWatchLogsAPI
}

package events

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-network-policy-agent/pkg/aws"
	"github.com/aws/aws-network-policy-agent/pkg/aws/services"
	"github.com/aws/aws-network-policy-agent/pkg/utils"

	goebpfevents "github.com/aws/aws-ebpf-sdk-go/pkg/events"
	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/go-logr/logr"
	"github.com/google/uuid"
	"github.com/spf13/pflag"
)

var (
	RING_BUFFER_PINPATH = "/sys/fs/bpf/globals/aws/maps/global_policy_events"
	cwl                 services.CloudWatchLogs
	logStreamName       = ""
	logGroupName        = ""
	sequenceToken       = ""
	EKS_CW_PATH         = "/aws/eks/"
	NON_EKS_CW_PATH     = "/aws/"
)

type ringBufferDataV4_t struct {
	SourceIP   uint32
	SourcePort uint32
	DestIP     uint32
	DestPort   uint32
	Protocol   uint32
	Verdict    uint32
}

type ringBufferDataV6_t struct {
	SourceIP   [16]byte
	SourcePort uint32
	DestIP     [16]byte
	DestPort   uint32
	Protocol   uint32
	Verdict    uint32
}

func ConfigurePolicyEventsLogging(logger logr.Logger, enableCloudWatchLogs bool, mapFD int, enableIPv6 bool) error {
	// Enable logging and setup ring buffer
	if mapFD <= 0 {
		logger.Info("MapFD is invalid")
		return fmt.Errorf("Invalid Ringbuffer FD: %d", mapFD)
	}

	var mapFDList []int
	mapFDList = append(mapFDList, mapFD)
	eventsClient := goebpfevents.New()
	eventChanList, err := eventsClient.InitRingBuffer(mapFDList)
	if err != nil {
		logger.Info("Failed to Initialize Ring Buffer", "err:", err)
		return err
	} else {
		if enableCloudWatchLogs {
			logger.Info("Cloudwatch log support is enabled")
			err = setupCW(logger)
			if err != nil {
				logger.Error(err, "unable to initialize Cloudwatch Logs for Policy events")
				return err
			}
		}
		logger.Info("Configure Event loop ... ")
		capturePolicyEvents(eventChanList[mapFD], logger, enableCloudWatchLogs, enableIPv6)
	}
	return nil
}

func setupCW(logger logr.Logger) error {
	awsCloudConfig := aws.CloudConfig{}
	fs := pflag.NewFlagSet("", pflag.ExitOnError)
	awsCloudConfig.BindFlags(fs)

	cloud, err := aws.NewCloud(awsCloudConfig)
	if err != nil {
		logger.Error(err, "unable to initialize AWS cloud session for Cloudwatch logs")
		return err
	}

	cwl = cloud.CloudWatchLogs()

	clusterName := cloud.ClusterName()

	customlogGroupName := EKS_CW_PATH + clusterName + "/cluster"
	if clusterName == utils.DEFAULT_CLUSTER_NAME {
		customlogGroupName = NON_EKS_CW_PATH + clusterName + "/cluster"
	}
	logger.Info("Setup CW", "Setting loggroup Name", customlogGroupName)
	err = ensureLogGroupExists(customlogGroupName)
	if err != nil {
		logger.Error(err, "unable to validate log group presence. Please check IAM permissions")
		return err
	}
	logGroupName = customlogGroupName
	return nil
}

func getProtocol(protocolNum int) string {
	protocolStr := "UNKNOWN"
	if protocolNum == utils.TCP_PROTOCOL_NUMBER {
		protocolStr = "TCP"
	} else if protocolNum == utils.UDP_PROTOCOL_NUMBER {
		protocolStr = "UDP"
	} else if protocolNum == utils.SCTP_PROTOCOL_NUMBER {
		protocolStr = "SCTP"
	} else if protocolNum == utils.ICMP_PROTOCOL_NUMBER {
		protocolStr = "ICMP"
	}
	return protocolStr
}

func getVerdict(verdict int) string {
	verdictStr := "DENY"
	if verdict == utils.ACCEPT.Index() {
		verdictStr = "ACCEPT"
	} else if verdict == utils.EXPIRED_DELETED.Index() {
		verdictStr = "EXPIRED/DELETED"
	}
	return verdictStr
}

func publishDataToCloudwatch(logQueue []*cloudwatchlogs.InputLogEvent, message string, log logr.Logger) bool {
	logQueue = append(logQueue, &cloudwatchlogs.InputLogEvent{
		Message:   &message,
		Timestamp: awssdk.Int64(time.Now().UnixNano() / int64(time.Millisecond)),
	})
	if len(logQueue) > 0 {
		log.Info("Sending logs to CW")
		input := cloudwatchlogs.PutLogEventsInput{
			LogEvents:    logQueue,
			LogGroupName: &logGroupName,
		}

		if sequenceToken == "" {
			err := createLogStream()
			if err != nil {
				log.Info("Failed to create log stream")
				panic(err)
			}
		} else {
			input = *input.SetSequenceToken(sequenceToken)
		}

		input = *input.SetLogStreamName(logStreamName)

		resp, err := cwl.PutLogEvents(&input)
		if err != nil {
			log.Info("Push log events", "Failed ", err)
		}

		if resp != nil {
			sequenceToken = *resp.NextSequenceToken
		}

		logQueue = []*cloudwatchlogs.InputLogEvent{}
		return false
	}
	return true
}

func capturePolicyEvents(ringbufferdata <-chan []byte, log logr.Logger, enableCloudWatchLogs bool, enableIPv6 bool) {
	nodeName := os.Getenv("MY_NODE_NAME")
	// Read from ringbuffer channel, perf buffer support is not there and 5.10 kernel is needed.
	go func(ringbufferdata <-chan []byte) {
		done := false
		for record := range ringbufferdata {
			var logQueue []*cloudwatchlogs.InputLogEvent
			var message string
			if enableIPv6 {
				var rb ringBufferDataV6_t
				buf := bytes.NewBuffer(record)
				if err := binary.Read(buf, binary.LittleEndian, &rb); err != nil {
					log.Info("Failed to read from Ring buf", err)
					continue
				}

				protocol := getProtocol(int(rb.Protocol))
				verdict := getVerdict(int(rb.Verdict))

				log.Info("Flow Info:  ", "Src IP", utils.ConvByteToIPv6(rb.SourceIP).String(), "Src Port", rb.SourcePort,
					"Dest IP", utils.ConvByteToIPv6(rb.DestIP).String(), "Dest Port", rb.DestPort,
					"Proto", protocol, "Verdict", verdict)

				message = "Node: " + nodeName + ";" + "SIP: " + utils.ConvByteToIPv6(rb.SourceIP).String() + ";" + "SPORT: " + strconv.Itoa(int(rb.SourcePort)) + ";" + "DIP: " + utils.ConvByteToIPv6(rb.DestIP).String() + ";" + "DPORT: " + strconv.Itoa(int(rb.DestPort)) + ";" + "PROTOCOL: " + protocol + ";" + "PolicyVerdict: " + verdict
			} else {
				var rb ringBufferDataV4_t
				buf := bytes.NewBuffer(record)
				if err := binary.Read(buf, binary.LittleEndian, &rb); err != nil {
					log.Info("Failed to read from Ring buf", err)
					continue
				}
				protocol := getProtocol(int(rb.Protocol))
				verdict := getVerdict(int(rb.Verdict))

				log.Info("Flow Info:  ", "Src IP", utils.ConvByteArrayToIP(rb.SourceIP), "Src Port", rb.SourcePort,
					"Dest IP", utils.ConvByteArrayToIP(rb.DestIP), "Dest Port", rb.DestPort,
					"Proto", protocol, "Verdict", verdict)

				message = "Node: " + nodeName + ";" + "SIP: " + utils.ConvByteArrayToIP(rb.SourceIP) + ";" + "SPORT: " + strconv.Itoa(int(rb.SourcePort)) + ";" + "DIP: " + utils.ConvByteArrayToIP(rb.DestIP) + ";" + "DPORT: " + strconv.Itoa(int(rb.DestPort)) + ";" + "PROTOCOL: " + protocol + ";" + "PolicyVerdict: " + verdict
			}

			if enableCloudWatchLogs {
				done = publishDataToCloudwatch(logQueue, message, log)
				if done {
					break
				}
			}
		}
	}(ringbufferdata)
}

func ensureLogGroupExists(name string) error {
	resp, err := cwl.DescribeLogGroups(&cloudwatchlogs.DescribeLogGroupsInput{})
	if err != nil {
		return err
	}

	for _, logGroup := range resp.LogGroups {
		if *logGroup.LogGroupName == name {
			return nil
		}
	}

	_, err = cwl.CreateLogGroup(&cloudwatchlogs.CreateLogGroupInput{
		LogGroupName: &name,
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			if aerr.Code() == "ResourceAlreadyExistsException" {
				return nil
			}
		}
		return err
	}
	return nil
}

func createLogStream() error {
	name := uuid.New().String()

	_, err := cwl.CreateLogStream(&cloudwatchlogs.CreateLogStreamInput{
		LogGroupName:  &logGroupName,
		LogStreamName: &name,
	})

	logStreamName = name
	return err
}

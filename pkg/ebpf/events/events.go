package events

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/achevuru/aws-network-policy-agent/pkg/aws"
	"github.com/achevuru/aws-network-policy-agent/pkg/aws/services"
	"github.com/achevuru/aws-network-policy-agent/pkg/utils"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/go-logr/logr"
	"github.com/google/uuid"
	goebpfevents "github.com/jayanthvn/pure-gobpf/pkg/events"
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

type Event_t struct {
	SourceIP   uint32
	SourcePort uint32
	DestIP     uint32
	DestPort   uint32
	Protocol   uint32
	Verdict    uint32
}

type EventV6_t struct {
	SourceIP   [16]byte
	SourcePort uint32
	DestIP     [16]byte
	DestPort   uint32
	Protocol   uint32
	Verdict    uint32
}

type EvProgram struct {
	wg sync.WaitGroup
}

func ConfigurePolicyEventsLogging(logger logr.Logger, enableCloudWatchLogs bool, mapFD int, enableIPv6 bool) error {
	// Enable logging and setup ring buffer
	if mapFD <= 0 {
		logger.Info("MapFD is invalid")
		return fmt.Errorf("Invalid Ringbuffer FD: %d", mapFD)
	}

	var mapFDList []int
	mapFDList = append(mapFDList, mapFD)
	eventChanList, err := goebpfevents.InitRingBuffer(mapFDList)
	if err != nil {
		logger.Info("Failed to Initialize Ring Buffer", "err:", err)
		return err
	} else {
		logger.Info("Configure Event loop ... ")
		p := EvProgram{wg: sync.WaitGroup{}}
		p.capturePolicyEvents(eventChanList[mapFD], logger, enableCloudWatchLogs, enableIPv6)
		if enableCloudWatchLogs {
			logger.Info("Cloudwatch log support is enabled")
			err = setupCW(logger)
			if err != nil {
				logger.Error(err, "unable to initialize Cloudwatch Logs for Policy events")
				return err
			}
		}
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

func (p *EvProgram) capturePolicyV6Events(events <-chan []byte, log logr.Logger, enableCloudWatchLogs bool) {
	nodeName := os.Getenv("MY_NODE_NAME")
	go func(events <-chan []byte) {
		defer p.wg.Done()

		for {
			if b, ok := <-events; ok {
				var logQueue []*cloudwatchlogs.InputLogEvent

				var ev EventV6_t
				buf := bytes.NewBuffer(b)
				if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
					log.Info("Read Ring buf", "Failed ", err)
					continue
				}

				protocol := "UNKNOWN"
				if int(ev.Protocol) == utils.TCP_PROTOCOL_NUMBER {
					protocol = "TCP"
				} else if int(ev.Protocol) == utils.UDP_PROTOCOL_NUMBER {
					protocol = "UDP"
				} else if int(ev.Protocol) == utils.SCTP_PROTOCOL_NUMBER {
					protocol = "SCTP"
				} else if int(ev.Protocol) == utils.ICMP_PROTOCOL_NUMBER {
					protocol = "ICMP"
				}

				verdict := "DENY"
				if ev.Verdict == 1 {
					verdict = "ACCEPT"
				} else if ev.Verdict == 2 {
					verdict = "EXPIRED/DELETED"
				}

				log.Info("Flow Info:  ", "Src IP", utils.ConvByteToIPv6(ev.SourceIP).String(), "Src Port", ev.SourcePort,
					"Dest IP", utils.ConvByteToIPv6(ev.DestIP).String(), "Dest Port", ev.DestPort,
					"Proto", protocol, "Verdict", verdict)

				message := "Node: " + nodeName + ";" + "SIP: " + utils.ConvByteToIPv6(ev.SourceIP).String() + ";" + "SPORT: " + strconv.Itoa(int(ev.SourcePort)) + ";" + "DIP: " + utils.ConvByteToIPv6(ev.DestIP).String() + ";" + "DPORT: " + strconv.Itoa(int(ev.DestPort)) + ";" + "PROTOCOL: " + protocol + ";" + "PolicyVerdict: " + verdict

				if enableCloudWatchLogs {
					logQueue = append(logQueue, &cloudwatchlogs.InputLogEvent{
						Message:   &message,
						Timestamp: awssdk.Int64(time.Now().UnixNano() / int64(time.Millisecond)),
					})
					if len(logQueue) > 0 {
						log.Info("Sending CW")
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
							log.Info("Kprobe", "Failed ", err)
						}

						if resp != nil {
							sequenceToken = *resp.NextSequenceToken
						}

						logQueue = []*cloudwatchlogs.InputLogEvent{}
					} else {
						break
					}
				}
			}
		}
	}(events)

}

func (p *EvProgram) capturePolicyV4Events(events <-chan []byte, log logr.Logger, enableCloudWatchLogs bool) {
	nodeName := os.Getenv("MY_NODE_NAME")
	go func(events <-chan []byte) {
		defer p.wg.Done()

		for {
			if b, ok := <-events; ok {
				var logQueue []*cloudwatchlogs.InputLogEvent

				var ev Event_t
				buf := bytes.NewBuffer(b)
				if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
					log.Info("Read Ring buf", "Failed ", err)
					continue
				}

				protocol := "UNKNOWN"
				if int(ev.Protocol) == utils.TCP_PROTOCOL_NUMBER {
					protocol = "TCP"
				} else if int(ev.Protocol) == utils.UDP_PROTOCOL_NUMBER {
					protocol = "UDP"
				} else if int(ev.Protocol) == utils.SCTP_PROTOCOL_NUMBER {
					protocol = "SCTP"
				} else if int(ev.Protocol) == utils.ICMP_PROTOCOL_NUMBER {
					protocol = "ICMP"
				}

				verdict := "DENY"
				if ev.Verdict == 1 {
					verdict = "ACCEPT"
				} else if ev.Verdict == 2 {
					verdict = "EXPIRED/DELETED"
				}

				log.Info("Flow Info:  ", "Src IP", utils.ConvByteArrayToIP(ev.SourceIP), "Src Port", ev.SourcePort,
					"Dest IP", utils.ConvByteArrayToIP(ev.DestIP), "Dest Port", ev.DestPort,
					"Proto", protocol, "Verdict", verdict)

				message := "Node: " + nodeName + ";" + "SIP: " + utils.ConvByteArrayToIP(ev.SourceIP) + ";" + "SPORT: " + strconv.Itoa(int(ev.SourcePort)) + ";" + "DIP: " + utils.ConvByteArrayToIP(ev.DestIP) + ";" + "DPORT: " + strconv.Itoa(int(ev.DestPort)) + ";" + "PROTOCOL: " + protocol + ";" + "PolicyVerdict: " + verdict

				if enableCloudWatchLogs {
					logQueue = append(logQueue, &cloudwatchlogs.InputLogEvent{
						Message:   &message,
						Timestamp: awssdk.Int64(time.Now().UnixNano() / int64(time.Millisecond)),
					})
					if len(logQueue) > 0 {
						log.Info("Sending CW")
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
							log.Info("Kprobe", "Failed ", err)
						}

						if resp != nil {
							sequenceToken = *resp.NextSequenceToken
						}

						logQueue = []*cloudwatchlogs.InputLogEvent{}
					} else {
						break
					}
				}
			}
		}
	}(events)
}

func (p *EvProgram) capturePolicyEvents(events <-chan []byte, log logr.Logger, enableCloudWatchLogs bool,
	enableIPv6 bool) {
	p.wg.Add(1)

	if enableIPv6 {
		p.capturePolicyV6Events(events, log, enableCloudWatchLogs)
	} else {
		p.capturePolicyV4Events(events, log, enableCloudWatchLogs)
	}
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

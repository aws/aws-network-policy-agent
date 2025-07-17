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
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	goebpfevents "github.com/aws/aws-ebpf-sdk-go/pkg/events"
	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
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

func log() logger.Logger {
	return logger.Get()
}

const VerdictDeny uint32 = 0

var (
	dropCountTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "network_policy_drop_count_total",
			Help: "Total number of packets dropped by network policy agent",
		},
		[]string{"direction"},
	)

	dropBytesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "network_policy_drop_bytes_total",
			Help: "Total number of bytes dropped by network policy agent",
		},
		[]string{"direction"},
	)
)

func init() {
	metrics.Registry.MustRegister(dropBytesTotal, dropCountTotal)
}

type ringBufferDataV4_t struct {
	SourceIP   uint32
	SourcePort uint32
	DestIP     uint32
	DestPort   uint32
	Protocol   uint32
	Verdict    uint32
	PacketSz   uint32
	IsEgress   uint8
}

type ringBufferDataV6_t struct {
	SourceIP   [16]byte
	SourcePort uint32
	DestIP     [16]byte
	DestPort   uint32
	Protocol   uint32
	Verdict    uint32
	PacketSz   uint32
	IsEgress   uint8
}

func ConfigurePolicyEventsLogging(enableCloudWatchLogs bool, mapFD int, enableIPv6 bool, cloudwatchLogLevel string) error {
	// Enable logging and setup ring buffer
	if mapFD <= 0 {
		log().Errorf("MapFD is invalid %d", mapFD)
		return fmt.Errorf("Invalid Ringbuffer FD: %d", mapFD)
	}

	var mapFDList []int
	mapFDList = append(mapFDList, mapFD)
	eventsClient := goebpfevents.New()
	eventChanList, err := eventsClient.InitRingBuffer(mapFDList)
	if err != nil {
		log().Errorf("Failed to Initialize Ring Buffer err: %v", err)
		return err
	} else {
		if enableCloudWatchLogs {
			log().Info("Cloudwatch log support is enabled")
			err = setupCW()
			if err != nil {
				log().Errorf("unable to initialize Cloudwatch Logs for Policy events %v", err)
				return err
			}
		}
		log().Debug("Configure Event loop ... ")
		capturePolicyEvents(eventChanList[mapFD], enableCloudWatchLogs, enableIPv6, cloudwatchLogLevel)
	}
	return nil
}

func setupCW() error {
	awsCloudConfig := aws.CloudConfig{}
	fs := pflag.NewFlagSet("", pflag.ExitOnError)
	awsCloudConfig.BindFlags(fs)

	cloud, err := aws.NewCloud(awsCloudConfig)
	if err != nil {
		log().Errorf("unable to initialize AWS cloud session for Cloudwatch logs %v", err)
		return err
	}

	cwl = cloud.CloudWatchLogs()

	clusterName := cloud.ClusterName()

	customlogGroupName := EKS_CW_PATH + clusterName + "/cluster"
	if clusterName == utils.DEFAULT_CLUSTER_NAME {
		customlogGroupName = NON_EKS_CW_PATH + clusterName + "/cluster"
	}
	log().Infof("Setting loggroup Name %s", customlogGroupName)
	err = ensureLogGroupExists(customlogGroupName)
	if err != nil {
		log().Errorf("unable to validate log group presence. Please check IAM permissions %v", err)
		return err
	}
	logGroupName = customlogGroupName
	return nil
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

func publishDataToCloudwatch(logQueue []*cloudwatchlogs.InputLogEvent, message string) bool {
	logQueue = append(logQueue, &cloudwatchlogs.InputLogEvent{
		Message:   &message,
		Timestamp: awssdk.Int64(time.Now().UnixNano() / int64(time.Millisecond)),
	})
	if len(logQueue) > 0 {
		log().Debug("Sending logs to CW")
		input := cloudwatchlogs.PutLogEventsInput{
			LogEvents:    logQueue,
			LogGroupName: &logGroupName,
		}

		if sequenceToken == "" {
			err := createLogStream()
			if err != nil {
				log().Errorf("Failed to create log stream %v", err)
				panic(err)
			}
		} else {
			input = *input.SetSequenceToken(sequenceToken)
		}

		input = *input.SetLogStreamName(logStreamName)

		resp, err := cwl.PutLogEvents(&input)
		if err != nil {
			log().Errorf("Push log events Failed %v", err)
		} else if resp != nil && resp.NextSequenceToken != nil {
			sequenceToken = *resp.NextSequenceToken
		}

		logQueue = []*cloudwatchlogs.InputLogEvent{}
		return false
	}
	return true
}

func capturePolicyEvents(ringbufferdata <-chan []byte, enableCloudWatchLogs bool, enableIPv6 bool, cloudwatchLogLevel string) {
	nodeName := os.Getenv("MY_NODE_NAME")
	// Read from ringbuffer channel, perf buffer support is not there and 5.10 kernel is needed.
	go func(ringbufferdata <-chan []byte) {
		done := false
		for record := range ringbufferdata {
			var logQueue []*cloudwatchlogs.InputLogEvent
			var message string
			publishCloudwatchMessage := false
			direction := "egress"
			if enableIPv6 {
				var rb ringBufferDataV6_t
				buf := bytes.NewBuffer(record)
				if err := binary.Read(buf, binary.LittleEndian, &rb); err != nil {
					log().Errorf("Failed to read from Ring buf %v", err)
					continue
				}

				protocol := utils.GetProtocol(int(rb.Protocol))
				verdict := getVerdict(int(rb.Verdict))

				if rb.IsEgress == 0 {
					direction = "ingress"
				}

				if rb.Verdict == VerdictDeny {
					dropCountTotal.WithLabelValues(direction).Add(float64(1))
					dropBytesTotal.WithLabelValues(direction).Add(float64(rb.PacketSz))
					log().Infof("Flow Info: Src IP: %s Src Port: %d Dest IP: %s Dest Port: %d Proto: %s Verdict: %s Direction: %s", utils.ConvByteToIPv6(rb.SourceIP).String(), rb.SourcePort,
						utils.ConvByteToIPv6(rb.DestIP).String(), rb.DestPort, protocol, string(verdict), string(direction))
					publishCloudwatchMessage = true
				} else {
					log().Debugf("Flow Info: Src IP: %s Src Port: %d Dest IP: %s Dest Port: %d Proto: %s Verdict: %s Direction: %s", utils.ConvByteToIPv6(rb.SourceIP).String(), rb.SourcePort,
						utils.ConvByteToIPv6(rb.DestIP).String(), rb.DestPort, protocol, string(verdict), string(direction))
				}

				message = "Node: " + nodeName + ";" + "SIP: " + utils.ConvByteToIPv6(rb.SourceIP).String() + ";" + "SPORT: " + strconv.Itoa(int(rb.SourcePort)) + ";" + "DIP: " + utils.ConvByteToIPv6(rb.DestIP).String() + ";" + "DPORT: " + strconv.Itoa(int(rb.DestPort)) + ";" + "PROTOCOL: " + protocol + ";" + "PolicyVerdict: " + verdict
			} else {
				var rb ringBufferDataV4_t
				buf := bytes.NewBuffer(record)
				if err := binary.Read(buf, binary.LittleEndian, &rb); err != nil {
					log().Errorf("Failed to read from Ring buf %v", err)
					continue
				}
				protocol := utils.GetProtocol(int(rb.Protocol))
				verdict := getVerdict(int(rb.Verdict))

				if rb.IsEgress == 0 {
					direction = "ingress"
				}

				if rb.Verdict == VerdictDeny {
					dropCountTotal.WithLabelValues(direction).Add(float64(1))
					dropBytesTotal.WithLabelValues(direction).Add(float64(rb.PacketSz))
					log().Infof("Flow Info: Src IP: %s Src Port: %d Dest IP: %s Dest Port: %d Proto %s Verdict %s Direction %s", utils.ConvByteArrayToIP(rb.SourceIP), rb.SourcePort,
						utils.ConvByteArrayToIP(rb.DestIP), rb.DestPort, protocol, string(verdict), string(direction))
					publishCloudwatchMessage = true
				} else {
					log().Debugf("Flow Info: Src IP: %s Src Port: %d Dest IP: %s Dest Port: %d Proto %s Verdict %s Direction %s", utils.ConvByteArrayToIP(rb.SourceIP), rb.SourcePort,
						utils.ConvByteArrayToIP(rb.DestIP), rb.DestPort, protocol, string(verdict), string(direction))
				}

				message = "Node: " + nodeName + ";" + "SIP: " + utils.ConvByteArrayToIP(rb.SourceIP) + ";" + "SPORT: " + strconv.Itoa(int(rb.SourcePort)) + ";" + "DIP: " + utils.ConvByteArrayToIP(rb.DestIP) + ";" + "DPORT: " + strconv.Itoa(int(rb.DestPort)) + ";" + "PROTOCOL: " + protocol + ";" + "PolicyVerdict: " + verdict
			}

			if cloudwatchLogLevel == "debug" {
				publishCloudwatchMessage = true
			}

			if enableCloudWatchLogs && publishCloudwatchMessage {
				done = publishDataToCloudwatch(logQueue, message)
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

	name := "aws-network-policy-agent-audit-" + uuid.New().String()
	_, err := cwl.CreateLogStream(&cloudwatchlogs.CreateLogStreamInput{
		LogGroupName:  &logGroupName,
		LogStreamName: &name,
	})

	logStreamName = name
	return err
}

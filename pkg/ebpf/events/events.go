package events

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	awsWrapper "github.com/aws/aws-network-policy-agent/pkg/aws"
	"github.com/aws/aws-network-policy-agent/pkg/aws/services"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	"github.com/aws/aws-network-policy-agent/pkg/podmapper"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	goebpfevents "github.com/aws/aws-ebpf-sdk-go/pkg/events"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
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

// Policy lookup cache
var (
	policyCache      = make(map[uint32]utils.PolicyInfo)
	policyCacheMutex sync.RWMutex
)

func init() {
	metrics.Registry.MustRegister(dropBytesTotal, dropCountTotal)
}

// UpdatePolicyCache updates the policy cache with new policy information
func UpdatePolicyCache(policies map[uint32]utils.PolicyInfo) {
	policyCacheMutex.Lock()
	defer policyCacheMutex.Unlock()

	// Update cache with new policies
	for id, policy := range policies {
		policyCache[id] = policy
	}
}

// lookupPolicyInfo retrieves policy information by ID
func lookupPolicyInfo(policyID uint32) (string, string) {
	if policyID == 0 {
		return "default", "default"
	}

	policyCacheMutex.RLock()
	if policy, exists := policyCache[policyID]; exists {
		policyCacheMutex.RUnlock()
		return policy.Name, policy.Namespace
	}
	policyCacheMutex.RUnlock()

	// Cache miss - this should be rare in steady state
	return "cache-miss", "cache-miss"
}

type ringBufferDataV4_t struct {
	SourceIP       uint32
	SourcePort     uint32
	DestIP         uint32
	DestPort       uint32
	Protocol       uint32
	Verdict        uint32
	PacketSz       uint32
	IsEgress       uint8
	PolicyID       uint32   // NEW: Policy that made the decision
	RulePrecedence uint8    // NEW: Precedence level of the rule
	Reserved       [3]uint8 // Padding
}

type ringBufferDataV6_t struct {
	SourceIP       [16]byte
	SourcePort     uint32
	DestIP         [16]byte
	DestPort       uint32
	Protocol       uint32
	Verdict        uint32
	PacketSz       uint32
	IsEgress       uint8
	PolicyID       uint32   // NEW: Policy that made the decision
	RulePrecedence uint8    // NEW: Precedence level of the rule
	Reserved       [3]uint8 // Padding
}

func ConfigurePolicyEventsLogging(enableCloudWatchLogs bool, mapFD int, enableIPv6 bool) error {
	// Enable logging and setup ring buffer
	ctx := context.Background()
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
			log().Info("Cloudwatch log support is enabled - initializing async uploader")
			err = setupAsyncCW(ctx)
			if err != nil {
				log().Errorf("unable to initialize async Cloudwatch uploader for Policy events %v", err)
				return err
			}
		}
		log().Debug("Configure Event loop ... ")
		capturePolicyEvents(ctx, eventChanList[mapFD], enableCloudWatchLogs, enableIPv6)
	}
	return nil
}

// setupAsyncCW initializes the async CloudWatch uploader
func setupAsyncCW(ctx context.Context) error {
	awsCloudConfig := awsWrapper.CloudConfig{}
	fs := pflag.NewFlagSet("", pflag.ExitOnError)
	awsCloudConfig.BindFlags(fs)

	cloud, err := awsWrapper.NewCloud(ctx, awsCloudConfig)
	if err != nil {
		log().Errorf("unable to initialize AWS cloud session for Cloudwatch logs %v", err)
		return err
	}

	cwlClient := cloud.CloudWatchLogs()
	clusterName := cloud.ClusterName()

	customlogGroupName := EKS_CW_PATH + clusterName + "/cluster"
	if clusterName == utils.DEFAULT_CLUSTER_NAME {
		customlogGroupName = NON_EKS_CW_PATH + clusterName + "/cluster"
	}
	log().Infof("Setting loggroup Name %s", customlogGroupName)

	// Ensure log group exists (synchronous setup, but only done once)
	err = ensureLogGroupExistsAsync(ctx, customlogGroupName, cwlClient)
	if err != nil {
		log().Errorf("unable to create log group %s, err: %v", customlogGroupName, err)
		return err
	}

	// Create log stream for async uploader
	streamName, err := createLogStreamAsync(ctx, customlogGroupName, cwlClient)
	if err != nil {
		log().Errorf("unable to create log stream, err: %v", err)
		return err
	}

	// Initialize async uploader
	config := AsyncCloudWatchConfig{
		BatchSize:     100,             // Batch up to 100 events
		BatchTimeout:  5 * time.Second, // Or send every 5 seconds
		ChannelBuffer: 1000,            // Buffer up to 1000 events
		LogGroupName:  customlogGroupName,
		LogStreamName: streamName,
		CWLClient:     cwlClient,
	}

	return InitializeAsyncCloudWatchUploader(ctx, config)
}

// Keep the old setupCW for backward compatibility if needed
func setupCW(ctx context.Context) error {
	awsCloudConfig := awsWrapper.CloudConfig{}
	fs := pflag.NewFlagSet("", pflag.ExitOnError)
	awsCloudConfig.BindFlags(fs)

	cloud, err := awsWrapper.NewCloud(ctx, awsCloudConfig)
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
	err = ensureLogGroupExists(ctx, customlogGroupName)
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

func publishDataToCloudwatch(ctx context.Context, logQueue []types.InputLogEvent, message string) bool {
	logQueue = append(logQueue, types.InputLogEvent{
		Message:   aws.String(message),
		Timestamp: aws.Int64(time.Now().UnixNano() / int64(time.Millisecond)),
	})
	if len(logQueue) > 0 {
		log().Debug("Sending logs to CW")
		input := &cloudwatchlogs.PutLogEventsInput{
			LogEvents:     logQueue,
			LogGroupName:  aws.String(logGroupName),
			LogStreamName: aws.String(logStreamName),
		}

		if sequenceToken == "" {
			err := createLogStream(ctx)
			if err != nil {
				log().Errorf("Failed to create log stream %v", err)
				panic(err)
			}
		} else {
			input.SequenceToken = aws.String(sequenceToken)
		}

		resp, err := cwl.PutLogEvents(ctx, input)
		if err != nil {
			log().Errorf("Push log events Failed %v", err)
		} else if resp != nil && resp.NextSequenceToken != nil {
			sequenceToken = *resp.NextSequenceToken
		}

		logQueue = []types.InputLogEvent{}
		return false
	}
	return true
}

func capturePolicyEvents(ctx context.Context, ringbufferdata <-chan []byte, enableCloudWatchLogs bool, enableIPv6 bool) {
	nodeName := os.Getenv("MY_NODE_NAME")
	// Read from ringbuffer channel, perf buffer support is not there and 5.10 kernel is needed.
	go func(ringbufferdata <-chan []byte) {
		for record := range ringbufferdata {
			var message string
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

				// Lookup policy information
				policyName, policyNamespace := lookupPolicyInfo(rb.PolicyID)

				if rb.Verdict == VerdictDeny {
					dropCountTotal.WithLabelValues(direction).Add(float64(1))
					dropBytesTotal.WithLabelValues(direction).Add(float64(rb.PacketSz))
					log().Infof("Flow Info: Src IP: %s Src Port: %d Dest IP: %s Dest Port: %d Proto: %s Verdict: %s Direction: %s Policy: %s/%s Precedence: %d",
						utils.ConvByteToIPv6(rb.SourceIP).String(), rb.SourcePort,
						utils.ConvByteToIPv6(rb.DestIP).String(), rb.DestPort, protocol, verdict, direction,
						policyNamespace, policyName, rb.RulePrecedence)
				} else {
					log().Debugf("Flow Info: Src IP: %s Src Port: %d Dest IP: %s Dest Port: %d Proto: %s Verdict: %s Direction: %s Policy: %s/%s Precedence: %d",
						utils.ConvByteToIPv6(rb.SourceIP).String(), rb.SourcePort,
						utils.ConvByteToIPv6(rb.DestIP).String(), rb.DestPort, protocol, verdict, direction,
						policyNamespace, policyName, rb.RulePrecedence)
				}

				// Get pod names for source and destination IPs
				srcIP := utils.ConvByteToIPv6(rb.SourceIP).String()
				dstIP := utils.ConvByteToIPv6(rb.DestIP).String()
				srcPodName := podmapper.GetPodNameForIP(srcIP)
				dstPodName := podmapper.GetPodNameForIP(dstIP)

				// Build message with pod names
				message = "Node: " + nodeName + ";" + "SIP: " + srcIP + ";" + "SPORT: " + strconv.Itoa(int(rb.SourcePort)) + ";" + "DIP: " + dstIP + ";" + "DPORT: " + strconv.Itoa(int(rb.DestPort)) + ";" + "PROTOCOL: " + protocol + ";" + "PolicyVerdict: " + verdict + ";" + "PolicyName: " + policyName + ";" + "PolicyNamespace: " + policyNamespace + ";" + "Precedence: " + strconv.Itoa(int(rb.RulePrecedence))
				
				// Add pod names if available
				if srcPodName != podmapper.UnknownPod {
					message += ";" + "SrcPod: " + srcPodName
				}
				if dstPodName != podmapper.UnknownPod {
					message += ";" + "DstPod: " + dstPodName
				}
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

				// Lookup policy information
				policyName, policyNamespace := lookupPolicyInfo(rb.PolicyID)

				if rb.Verdict == VerdictDeny {
					dropCountTotal.WithLabelValues(direction).Add(float64(1))
					dropBytesTotal.WithLabelValues(direction).Add(float64(rb.PacketSz))
					log().Infof("Flow Info: Src IP: %s Src Port: %d Dest IP: %s Dest Port: %d Proto: %s Verdict: %s Direction: %s Policy: %s/%s Precedence: %d",
						utils.ConvByteArrayToIP(rb.SourceIP), rb.SourcePort,
						utils.ConvByteArrayToIP(rb.DestIP), rb.DestPort, protocol, verdict, direction,
						policyNamespace, policyName, rb.RulePrecedence)
				} else {
					log().Debugf("Flow Info: Src IP: %s Src Port: %d Dest IP: %s Dest Port: %d Proto: %s Verdict: %s Direction: %s Policy: %s/%s Precedence: %d",
						utils.ConvByteArrayToIP(rb.SourceIP), rb.SourcePort,
						utils.ConvByteArrayToIP(rb.DestIP), rb.DestPort, protocol, verdict, direction,
						policyNamespace, policyName, rb.RulePrecedence)
				}

				// Get pod names for source and destination IPs
				srcIP := utils.ConvByteArrayToIP(rb.SourceIP)
				dstIP := utils.ConvByteArrayToIP(rb.DestIP)
				srcPodName := podmapper.GetPodNameForIP(srcIP)
				dstPodName := podmapper.GetPodNameForIP(dstIP)

				// Build message with pod names
				message = "Node: " + nodeName + ";" + "SIP: " + srcIP + ";" + "SPORT: " + strconv.Itoa(int(rb.SourcePort)) + ";" + "DIP: " + dstIP + ";" + "DPORT: " + strconv.Itoa(int(rb.DestPort)) + ";" + "PROTOCOL: " + protocol + ";" + "PolicyVerdict: " + verdict + ";" + "PolicyName: " + policyName + ";" + "PolicyNamespace: " + policyNamespace + ";" + "Precedence: " + strconv.Itoa(int(rb.RulePrecedence))
				
				// Add pod names if available
				if srcPodName != podmapper.UnknownPod {
					message += ";" + "SrcPod: " + srcPodName
				}
				if dstPodName != podmapper.UnknownPod {
					message += ";" + "DstPod: " + dstPodName
				}
			}

			if enableCloudWatchLogs {
				// Send to async uploader (non-blocking)
				SendAsyncCloudWatchEvent(message)
			}
		}
	}(ringbufferdata)
}

func ensureLogGroupExists(ctx context.Context, name string) error {
	resp, err := cwl.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{})
	if err != nil {
		return err
	}

	for _, logGroup := range resp.LogGroups {
		if *logGroup.LogGroupName == name {
			return nil
		}
	}

	_, err = cwl.CreateLogGroup(ctx, &cloudwatchlogs.CreateLogGroupInput{
		LogGroupName: aws.String(name),
	})
	if err != nil {
		var resourceExists *types.ResourceAlreadyExistsException
		if errors.As(err, &resourceExists) {
			return nil
		}
		return err
	}
	return nil
}

// ensureLogGroupExistsAsync is the async version for log group creation
func ensureLogGroupExistsAsync(ctx context.Context, name string, cwlClient services.CloudWatchLogs) error {
	resp, err := cwlClient.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{})
	if err != nil {
		return err
	}

	for _, logGroup := range resp.LogGroups {
		if *logGroup.LogGroupName == name {
			return nil
		}
	}

	_, err = cwlClient.CreateLogGroup(ctx, &cloudwatchlogs.CreateLogGroupInput{
		LogGroupName: aws.String(name),
	})
	if err != nil {
		var resourceExists *types.ResourceAlreadyExistsException
		if errors.As(err, &resourceExists) {
			return nil
		}
		return err
	}
	return nil
}

// createLogStreamAsync creates a log stream for the async uploader
func createLogStreamAsync(ctx context.Context, logGroupName string, cwlClient services.CloudWatchLogs) (string, error) {
	name := "aws-network-policy-agent-audit-" + uuid.New().String()
	_, err := cwlClient.CreateLogStream(ctx, &cloudwatchlogs.CreateLogStreamInput{
		LogGroupName:  aws.String(logGroupName),
		LogStreamName: aws.String(name),
	})
	return name, err
}

func createLogStream(ctx context.Context) error {
	name := "aws-network-policy-agent-audit-" + uuid.New().String()
	_, err := cwl.CreateLogStream(ctx, &cloudwatchlogs.CreateLogStreamInput{
		LogGroupName:  aws.String(logGroupName),
		LogStreamName: aws.String(name),
	})

	logStreamName = name
	return err
}

// ShutdownAsyncServices shuts down async CloudWatch uploader and pod mapper
func ShutdownAsyncServices() {
	ShutdownAsyncCloudWatchUploader()
	podmapper.ShutdownPodMapper()
}

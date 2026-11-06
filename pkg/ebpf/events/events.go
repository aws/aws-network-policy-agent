package events

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"time"
	"unsafe"

	awsWrapper "github.com/aws/aws-network-policy-agent/pkg/aws"
	"github.com/aws/aws-network-policy-agent/pkg/aws/services"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sys/unix"

	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/google/uuid"
	"github.com/spf13/pflag"
)

var (
	cwl             services.CloudWatchLogs
	logStreamName   = ""
	logGroupName    = ""
	sequenceToken   = ""
	EKS_CW_PATH     = "/aws/eks/"
	NON_EKS_CW_PATH = "/aws/"
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
	Tier       uint8
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
	Tier       uint8
}

func ConfigurePolicyEventsLogging(enableCloudWatchLogs bool, mapFD int, enableIPv6 bool) error {
	// Enable logging and setup ring buffer
	ctx := context.Background()
	if mapFD <= 0 {
		log().Errorf("MapFD is invalid %d", mapFD)
		return fmt.Errorf("Invalid Ringbuffer FD: %d", mapFD)
	}

	// Consume the ring buffer with cilium/ebpf's pull-model reader.
	// Duplicate the recovered map FD so cilium/ebpf owns its own descriptor,
	// independent of the SDK's map cache.
	dupFD, err := unix.Dup(mapFD)
	if err != nil {
		log().Errorf("Failed to dup ring buffer map FD %d err: %v", mapFD, err)
		return err
	}
	// NewMapFromFD takes ownership of dupFD on success and on failure
	// (cilium closes it before returning an error) - never close it here.
	ringMap, err := cebpf.NewMapFromFD(dupFD)
	if err != nil {
		log().Errorf("Failed to open ring buffer map from FD %d err: %v", mapFD, err)
		return err
	}
	rd, err := ringbuf.NewReader(ringMap)
	if err != nil {
		ringMap.Close()
		log().Errorf("Failed to Initialize Ring Buffer err: %v", err)
		return err
	}
	if enableCloudWatchLogs {
		log().Info("Cloudwatch log support is enabled")
		err = setupCW(ctx)
		if err != nil {
			rd.Close()
			ringMap.Close()
			log().Errorf("unable to initialize Cloudwatch Logs for Policy events %v", err)
			return err
		}
	}
	log().Debug("Configure Event loop ... ")
	capturePolicyEvents(ctx, rd, ringMap, enableCloudWatchLogs, enableIPv6)
	return nil
}

// ipv4Str converts the u32 IP field from the ring buffer record (raw packet
// bytes read little-endian) back to dotted-quad.
func ipv4Str(v uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b).String()
}

// ipv6Str renders a 16-byte IP. Unmap() keeps parity with the previous
// net.IP.String() behavior: v4-mapped addresses (::ffff:a.b.c.d) render as
// dotted-quad.
func ipv6Str(b [16]byte) string {
	return netip.AddrFrom16(b).Unmap().String()
}

// formatFlowLine builds the flow log message without fmt. Output is
// byte-identical to the previous Infof formatting, which used different
// separators per family:
//
//	v4: "... Proto %s Verdict %s Direction %s, Tier %s"
//	v6: "... Proto: %s Verdict: %s Direction: %s Tier: %s"
func formatFlowLine(v6 bool, srcIP string, srcPort uint32, destIP string, destPort uint32, protocol, verdict, direction, tier string) string {
	b := make([]byte, 0, 160)
	b = append(b, "Flow Info: Src IP: "...)
	b = append(b, srcIP...)
	b = append(b, " Src Port: "...)
	b = strconv.AppendUint(b, uint64(srcPort), 10)
	b = append(b, " Dest IP: "...)
	b = append(b, destIP...)
	b = append(b, " Dest Port: "...)
	b = strconv.AppendUint(b, uint64(destPort), 10)
	if v6 {
		b = append(b, " Proto: "...)
		b = append(b, protocol...)
		b = append(b, " Verdict: "...)
		b = append(b, verdict...)
		b = append(b, " Direction: "...)
		b = append(b, direction...)
		b = append(b, " Tier: "...)
	} else {
		b = append(b, " Proto "...)
		b = append(b, protocol...)
		b = append(b, " Verdict "...)
		b = append(b, verdict...)
		b = append(b, " Direction "...)
		b = append(b, direction...)
		b = append(b, ", Tier "...)
	}
	b = append(b, tier...)
	return string(b)
}

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

func getTier(tier int) string {
	tierStr := "ERROR"
	if tier == utils.ADMIN_TIER.Index() {
		tierStr = "ADMIN"
	} else if tier == utils.NETWORK_POLICY_TIER.Index() {
		tierStr = "NETWORK_POLICY"
	} else if tier == utils.BASELINE_TIER.Index() {
		tierStr = "BASELINE"
	} else if tier == utils.DEFAULT_TIER.Index() {
		tierStr = "DEFAULT"
	}
	return tierStr
}

// publishDataToCloudwatch sends one policy event to CloudWatch Logs.
// TODO: one synchronous PutLogEvents per event caps consumption at ~1/RTT and
// can overflow the ring buffer at high event rates; batch the publish on a
// separate goroutine.
func publishDataToCloudwatch(ctx context.Context, message string) {
	log().Debug("Sending logs to CW")
	input := &cloudwatchlogs.PutLogEventsInput{
		LogEvents: []types.InputLogEvent{{
			Message:   aws.String(message),
			Timestamp: aws.Int64(time.Now().UnixNano() / int64(time.Millisecond)),
		}},
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
}

func capturePolicyEvents(ctx context.Context, rd *ringbuf.Reader, ringMap *cebpf.Map, enableCloudWatchLogs bool, enableIPv6 bool) {
	nodeName := os.Getenv("MY_NODE_NAME")
	// dedicated non-sugared logger without caller capture for the hot path
	flowLog := logger.GetFlowLogger()
	// Gate ACCEPT logging on the core's level rather than the raw flag string.
	debugEnabled := flowLog.Core().Enabled(zapcore.DebugLevel)
	go func() {
		// Hold ringMap for the reader's lifetime: cilium/ebpf closes the
		// underlying FD once the Map is garbage collected, and the reader
		// registers only the raw FD with epoll.
		defer ringMap.Close()
		defer rd.Close()
		var rec ringbuf.Record
		for {
			if err := rd.ReadInto(&rec); err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log().Errorf("Failed to read from Ring buf %v", err)
				// Avoid a hot error loop if the ring is in a bad state.
				time.Sleep(50 * time.Millisecond)
				continue
			}

			var isDenyVerdict bool
			direction := "egress"

			var srcIP, destIP string
			var srcPort, destPort uint32
			var protocolNum, verdictNum, packetSz uint32
			var isEgress, tierNum uint8

			if enableIPv6 {
				if len(rec.RawSample) < int(unsafe.Sizeof(ringBufferDataV6_t{})) {
					log().Errorf("Failed to read from Ring buf: short sample %d", len(rec.RawSample))
					continue
				}
				rb := (*ringBufferDataV6_t)(unsafe.Pointer(&rec.RawSample[0]))
				srcIP, destIP = ipv6Str(rb.SourceIP), ipv6Str(rb.DestIP)
				srcPort, destPort = rb.SourcePort, rb.DestPort
				protocolNum, verdictNum, packetSz = rb.Protocol, rb.Verdict, rb.PacketSz
				isEgress, tierNum = rb.IsEgress, rb.Tier
			} else {
				if len(rec.RawSample) < int(unsafe.Sizeof(ringBufferDataV4_t{})) {
					log().Errorf("Failed to read from Ring buf: short sample %d", len(rec.RawSample))
					continue
				}
				rb := (*ringBufferDataV4_t)(unsafe.Pointer(&rec.RawSample[0]))
				srcIP, destIP = ipv4Str(rb.SourceIP), ipv4Str(rb.DestIP)
				srcPort, destPort = rb.SourcePort, rb.DestPort
				protocolNum, verdictNum, packetSz = rb.Protocol, rb.Verdict, rb.PacketSz
				isEgress, tierNum = rb.IsEgress, rb.Tier
			}

			protocol := utils.GetProtocol(int(protocolNum))
			verdict := getVerdict(int(verdictNum))
			if isEgress == 0 {
				direction = "ingress"
			}
			tier := getTier(int(tierNum))
			isDenyVerdict = verdictNum == VerdictDeny

			if isDenyVerdict {
				dropCountTotal.WithLabelValues(direction).Add(float64(1))
				dropBytesTotal.WithLabelValues(direction).Add(float64(packetSz))
				flowLog.Info(formatFlowLine(enableIPv6, srcIP, srcPort, destIP, destPort, protocol, verdict, direction, tier))
			} else if debugEnabled {
				flowLog.Debug(formatFlowLine(enableIPv6, srcIP, srcPort, destIP, destPort, protocol, verdict, direction, tier))
			}

			if enableCloudWatchLogs {
				// Apply same filtering as local logging:
				// DENY always published, ACCEPT only at debug level
				if isDenyVerdict || debugEnabled {
					message := "Node: " + nodeName + ";" + "SIP: " + srcIP + ";" + "SPORT: " + strconv.Itoa(int(srcPort)) + ";" + "DIP: " + destIP + ";" + "DPORT: " + strconv.Itoa(int(destPort)) + ";" + "PROTOCOL: " + protocol + ";" + "PolicyVerdict: " + verdict + ";" + "Tier: " + tier
					publishDataToCloudwatch(ctx, message)
				}
			}
		}
	}()
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

func createLogStream(ctx context.Context) error {
	name := "aws-network-policy-agent-audit-" + uuid.New().String()
	_, err := cwl.CreateLogStream(ctx, &cloudwatchlogs.CreateLogStreamInput{
		LogGroupName:  aws.String(logGroupName),
		LogStreamName: aws.String(name),
	})

	logStreamName = name
	return err
}

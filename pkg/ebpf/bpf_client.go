package ebpf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	corev1 "k8s.io/api/core/v1"

	"github.com/aws/amazon-vpc-cni-k8s/pkg/ipamd/datastore"
	goelf "github.com/aws/aws-ebpf-sdk-go/pkg/elfparser"
	goebpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	goebpfprogs "github.com/aws/aws-ebpf-sdk-go/pkg/progs"
	"github.com/aws/aws-ebpf-sdk-go/pkg/tc"
	goebpfutils "github.com/aws/aws-ebpf-sdk-go/pkg/utils"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf/conntrack"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf/events"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/aws/aws-network-policy-agent/pkg/utils/cp"
	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	TC_INGRESS_BINARY                                = "tc.v4ingress.bpf.o"
	TC_EGRESS_BINARY                                 = "tc.v4egress.bpf.o"
	TC_V6_INGRESS_BINARY                             = "tc.v6ingress.bpf.o"
	TC_V6_EGRESS_BINARY                              = "tc.v6egress.bpf.o"
	EVENTS_BINARY                                    = "v4events.bpf.o"
	EVENTS_V6_BINARY                                 = "v6events.bpf.o"
	AWS_CONNTRACK_MAP                                = "aws_conntrack_map"
	AWS_EVENTS_MAP                                   = "policy_events"
	EKS_CLI_BINARY                                   = "aws-eks-na-cli"
	EKS_V6_CLI_BINARY                                = "aws-eks-na-cli-v6"
	hostBinaryPath                                   = "/host/opt/cni/bin/"
	IPv4_HOST_MASK                                   = "/32"
	IPv6_HOST_MASK                                   = "/128"
	CONNTRACK_MAP_PIN_PATH                           = "/sys/fs/bpf/globals/aws/maps/global_aws_conntrack_map"
	POLICY_EVENTS_MAP_PIN_PATH                       = "/sys/fs/bpf/globals/aws/maps/global_policy_events"
	CATCH_ALL_PROTOCOL               corev1.Protocol = "ANY_IP_PROTOCOL"
	POD_VETH_PREFIX                                  = "eni"
	POLICIES_APPLIED                                 = 0
	DEFAULT_ALLOW                                    = 1
	DEFAULT_DENY                                     = 2
	POD_STATE_MAP_KEY                                = 0
	CLUSTER_POLICY_POD_STATE_MAP_KEY                 = 1
	BRANCH_ENI_VETH_PREFIX                           = "vlan"
	INTERFACE_COUNT_UNKNOWN                          = -1 // Used when caller doesn't know interface count
	INTERFACE_COUNT_DEFAULT                          = 1  // Default single interface
	IPAM_JSON_PATH                                   = "/var/run/aws-node/ipam.json"
	deletedPodsMinAge                                = 5 * time.Minute
)

func log() logger.Logger {
	return logger.Get()
}

var (
	sdkAPILatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "awsnodeagent_aws_ebpf_sdk_latency_ms",
			Help: "eBPF SDK API call latency in ms",
		},
		[]string{"api", "error"},
	)

	sdkAPIErr = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "awsnodeagent_aws_ebpfsdk_error_count",
			Help: "The number of times eBPF SDK returns an error",
		},
		[]string{"fn"},
	)
	prometheusRegistered = false
)

type pod_state struct {
	state uint8
}

func msSince(start time.Time) float64 {
	return float64(time.Since(start) / time.Millisecond)
}

func prometheusRegister() {
	if !prometheusRegistered {
		metrics.Registry.MustRegister(sdkAPILatency)
		metrics.Registry.MustRegister(sdkAPIErr)
		prometheusRegistered = true
	}
}

type BpfClient interface {
	AttacheBPFProbes(pod types.NamespacedName, podIdentifier string, numInterfaces int) error
	DeleteBPFProbes(pod types.NamespacedName, podIdentifier string) error
	UpdateClusterPolicyEbpfMaps(podIdentifier string, ingressFirewallRules []fwrp.EbpfFirewallRules, egressFirewallRules []fwrp.EbpfFirewallRules) error
	UpdateEbpfMaps(podIdentifier string, ingressFirewallRules []fwrp.EbpfFirewallRules, egressFirewallRules []fwrp.EbpfFirewallRules) error
	UpdatePodStateEbpfMaps(podIdentifier string, key int, state int, updateIngress bool, updateEgress bool) error
	IsFirstPodInPodIdentifier(podIdentifier string) bool
	ReAttachEbpfProbes() error
	GetNetworkPolicyMode() string
	CreatePodStateEbpfEntryIfNotExists(podIdentifier string, key int, state int) error
	ClearDeletedPod(podNamespacedName string)
}

type BPFContext struct {
	ingressPgmInfo   goelf.BpfData
	egressPgmInfo    goelf.BpfData
	conntrackMapInfo goebpfmaps.BpfMap
}

func NewBpfClient(ctx context.Context, nodeIP string, enablePolicyEventLogs, enableCloudWatchLogs bool,
	enableIPv6 bool, conntrackTTL int, conntrackTableSize int, networkPolicyMode string, isMultiNICEnabled bool, logLevel string) (*bpfClient, error) {
	var conntrackMap goebpfmaps.BpfMap

	ebpfClient := &bpfClient{
		// Maps PolicyEndpoint resource to it's eBPF context
		policyEndpointeBPFContext:       new(sync.Map),
		ingressPodToProgMap:             new(sync.Map),
		egressPodToProgMap:              new(sync.Map),
		globalMaps:                      new(sync.Map),
		ingressProgToPodsMap:            new(sync.Map),
		egressProgToPodsMap:             new(sync.Map),
		podIdentifierLock:               new(sync.Map),
		podNameToInterfaceCount:         new(sync.Map),
		networkPolicyMode:               networkPolicyMode,
		isMultiNICEnabled:               isMultiNICEnabled,
		ingressInMemoryMap:              new(sync.Map),
		egressInMemoryMap:               new(sync.Map),
		clusterPolicyIngressInMemoryMap: new(sync.Map),
		clusterPolicyEgressInMemoryMap:  new(sync.Map),
		deletedPods:                     new(sync.Map),
	}
	ingressBinary, egressBinary, eventsBinary,
		cliBinary, hostMask := TC_INGRESS_BINARY, TC_EGRESS_BINARY, EVENTS_BINARY, EKS_CLI_BINARY, IPv4_HOST_MASK
	if enableIPv6 {
		ingressBinary, egressBinary, eventsBinary,
			cliBinary, hostMask = TC_V6_INGRESS_BINARY, TC_V6_EGRESS_BINARY, EVENTS_V6_BINARY, EKS_V6_CLI_BINARY, IPv6_HOST_MASK
	}
	ebpfClient.ingressBinary, ebpfClient.egressBinary,
		ebpfClient.hostMask = ingressBinary, egressBinary, hostMask

	bpfBinaries := []string{eventsBinary, ingressBinary, egressBinary, cliBinary}
	isConntrackMapPresent, isPolicyEventsMapPresent := false, false
	var err error

	ebpfClient.bpfSDKClient = goelf.New(goelf.Config{NamespacedMaps: utils.NamespacedBPFMaps})
	ebpfClient.bpfTCClient = tc.New([]string{POD_VETH_PREFIX, BRANCH_ENI_VETH_PREFIX})

	ebpfClient.fwRuleProcessor = fwrp.NewFirewallRuleProcessor(nodeIP, hostMask, enableIPv6)

	//Set RLIMIT
	err = ebpfClient.bpfSDKClient.IncreaseRlimit()
	if err != nil {
		//No need to error out from here. We should be good to proceed.
		log().Errorf("Failed to increase RLIMIT on the node but moving forward %v", err)
	}

	//Compare BPF binaries
	ingressUpdateRequired, egressUpdateRequired, eventsUpdateRequired, err := checkAndUpdateBPFBinaries(ebpfClient.bpfTCClient,
		bpfBinaries, hostBinaryPath)
	if err != nil {
		//Log the error and move on
		log().Errorf("Probe validation/update failed but will continue to load %v", err)
	}
	log().Info("Probe validation Done")

	//Copy the latest binaries to /opt/cni/bin
	err = cp.InstallBPFBinaries(bpfBinaries, hostBinaryPath)
	if err != nil {
		//Log the error and move on
		log().Errorf("Failed to copy the eBPF binaries to host path....error: %v", err)
	}
	log().Info("Copied eBPF binaries to the host directory")

	var interfaceNametoIngressPinPath map[string]string
	var interfaceNametoEgressPinPath map[string]string
	eventBufferFD := 0
	isConntrackMapPresent, isPolicyEventsMapPresent, eventBufferFD, interfaceNametoIngressPinPath, interfaceNametoEgressPinPath, err = ebpfClient.recoverBPFState(ebpfClient.bpfTCClient, ebpfClient.bpfSDKClient, ebpfClient.policyEndpointeBPFContext,
		ebpfClient.globalMaps, ingressUpdateRequired, egressUpdateRequired, eventsUpdateRequired)
	if err != nil {
		log().Errorf("Failed to recover the BPF state error: %v", err)
		sdkAPIErr.WithLabelValues("RecoverBPFState").Inc()
		return nil, fmt.Errorf("failed to recover BPF state: %w", err)
	}
	log().Info("Successfully recovered BPF state")
	ebpfClient.interfaceNametoIngressPinPath = interfaceNametoIngressPinPath
	ebpfClient.interfaceNametoEgressPinPath = interfaceNametoEgressPinPath

	// Load the current events binary, if ..
	// - Current events binary packaged with network policy agent is different than the one installed
	//   during the previous installation (or)
	// - Either Conntrack Map (or) Events Map is currently missing on the node
	if eventsUpdateRequired || (!isConntrackMapPresent || !isPolicyEventsMapPresent) {
		log().Info("Install the default global maps")
		eventsProbe := EVENTS_BINARY
		if enableIPv6 {
			eventsProbe = EVENTS_V6_BINARY
		}
		var bpfSdkInputData goelf.BpfCustomData
		bpfSdkInputData.FilePath = eventsProbe
		bpfSdkInputData.CustomPinPath = "global"
		bpfSdkInputData.CustomMapSize = make(map[string]int)

		bpfSdkInputData.CustomMapSize[AWS_CONNTRACK_MAP] = conntrackTableSize

		log().Infof("Setting conntrack cache map size: max entries: %d", conntrackTableSize)

		_, globalMapInfo, err := ebpfClient.bpfSDKClient.LoadBpfFileWithCustomData(bpfSdkInputData)
		if err != nil {
			log().Errorf("Unable to load events binary. Required for policy enforcement, exiting..error: %v", err)
			sdkAPIErr.WithLabelValues("LoadBpfFileWithCustomData").Inc()
			return nil, err
		}
		log().Info("Successfully loaded events probe")

		for mapName, mapInfo := range globalMapInfo {
			if mapName == AWS_CONNTRACK_MAP {
				conntrackMap = mapInfo
			}
			if mapName == AWS_EVENTS_MAP {
				eventBufferFD = int(mapInfo.MapFD)
			}
		}
	}

	if isConntrackMapPresent {
		recoveredConntrackMap, ok := ebpfClient.globalMaps.Load(CONNTRACK_MAP_PIN_PATH)
		if ok {
			conntrackMap = recoveredConntrackMap.(goebpfmaps.BpfMap)
			log().Info("Derived existing ConntrackMap identifier")
		} else {
			log().Errorf("Unable to get conntrackMap post recovery..error: %v", err)
			sdkAPIErr.WithLabelValues("RecoveryFailed").Inc()
			return nil, err
		}
	}

	ebpfClient.conntrackClient = conntrack.NewConntrackClient(conntrackMap, enableIPv6)
	log().Info("Initialized Conntrack client")

	if enablePolicyEventLogs {
		err = events.ConfigurePolicyEventsLogging(enableCloudWatchLogs, eventBufferFD, enableIPv6, logLevel)
		if err != nil {
			log().Errorf("unable to initialize event buffer for Policy event exiting..error: %v", err)
			sdkAPIErr.WithLabelValues("ConfigurePolicyEventsLogging").Inc()
			return nil, err
		}
		log().Info("Configured event logging")
	} else {
		log().Info("Disabled event logging")
	}

	// Start Conntrack routines
	duration := time.Duration(conntrackTTL) * time.Second
	halfDuration := duration / 2
	if enableIPv6 {
		go wait.Forever(ebpfClient.conntrackClient.Cleanupv6ConntrackMap, halfDuration)
	} else {
		go wait.Forever(ebpfClient.conntrackClient.CleanupConntrackMap, halfDuration)
	}

	// Load ipam.json data only when multi-NIC is enabled for interface counts
	if ebpfClient.isMultiNICEnabled {
		err = ebpfClient.loadIPAMDataFromFile(IPAM_JSON_PATH)
		if err != nil {
			log().Errorf("Failed to load IPAM data: %v", err)
			return nil, err
		}
	}

	// Initializes prometheus metrics
	prometheusRegister()
	ebpfClient.startDeletedPodsCleanupRoutine(ctx)

	log().Info("BPF Client initialization done")
	return ebpfClient, nil
}

var _ BpfClient = (*bpfClient)(nil)

type inMemoryBPFMap interface {
	BulkRefresh(map[string][]byte) error
}

var (
	newInMemoryBpfMap = NewInMemoryBpfMap
	createBPFMapEntry = func(mapInfo goebpfmaps.BpfMap, key, value uintptr) error {
		return mapInfo.CreateMapEntry(key, value)
	}
	updateBPFMapEntry = func(mapInfo goebpfmaps.BpfMap, key, value uintptr, flags uint64) error {
		return mapInfo.CreateUpdateMapEntry(key, value, flags)
	}
)

type bpfClient struct {
	// Stores eBPF Ingress and Egress context per policyEndpoint resource
	policyEndpointeBPFContext *sync.Map
	// Stores the Ingress eBPF Prog FD per pod
	ingressPodToProgMap *sync.Map
	// Stores the Egress eBPF Prog FD per pod
	egressPodToProgMap *sync.Map
	// Stores info on the global maps the agent creates
	globalMaps *sync.Map
	// Ingress eBPF probe binary
	ingressBinary string
	// Egress eBPF probe binary
	egressBinary string
	// host IP Mask - will be initialized based on the IP family
	hostMask string
	// Conntrack client instance
	conntrackClient conntrack.ConntrackClient
	// eBPF SDK Client
	bpfSDKClient goelf.BpfSDKClient
	// eBPF TC Client
	bpfTCClient tc.BpfTc
	// Stores the Ingress eBPF Prog FD to pods mapping
	ingressProgToPodsMap *sync.Map
	// Stores the Egress eBPF Prog FD to pods mapping
	egressProgToPodsMap *sync.Map
	// Stores podIdentifier to operations lock mapping
	podIdentifierLock *sync.Map
	// This is only updated and used for probe binary updates during initialization
	interfaceNametoIngressPinPath map[string]string
	// This is only updated and used for probe binary updates during initialization
	interfaceNametoEgressPinPath map[string]string
	// network policy mode
	networkPolicyMode string
	// multi nic enabled flag
	isMultiNICEnabled bool
	// maps pod namespaced name to interface count
	// This is loaded once at startup and will not be up to date on new pod info
	podNameToInterfaceCount *sync.Map
	// FirewallRuleProcessor is used to convert firewall rules into ebpf Map content
	fwRuleProcessor *fwrp.FirewallRuleProcessor
	// This is in-memory map backed by ingressBpfMap (key: podIdentifier, value: InMemoryBpfMap pointer)
	ingressInMemoryMap *sync.Map
	// This is in-memory map backed by egressBpfMap (key: podIdentifier, value: InMemoryBpfMap pointer)
	egressInMemoryMap *sync.Map
	// This is in-memory map backed by clusterPolicyIngressBpfMap (key: podIdentifier, value: InMemoryBpfMap pointer)
	clusterPolicyIngressInMemoryMap *sync.Map
	// This is in-memory map backed by clusterPolicyEgressBpfMap (key: podIdentifier, value: InMemoryBpfMap pointer)
	clusterPolicyEgressInMemoryMap *sync.Map
	// This is in-memory map to track recently deleted pods (key: podNamespacedName, value: time added to map)
	deletedPods *sync.Map
}

// lockPodIdentifier serializes all operations that can change a pod's BPF
// handles, attachment indexes, or map shadows. The no-op path keeps small
// unit-test clients safe when they do not need concurrent state.
func (l *bpfClient) lockPodIdentifier(podIdentifier string) func() {
	if l.podIdentifierLock == nil {
		return func() {}
	}

	value, _ := l.podIdentifierLock.LoadOrStore(podIdentifier, &sync.Mutex{})
	podIdentifierLock, ok := value.(*sync.Mutex)
	if !ok {
		panic(fmt.Sprintf("unexpected pod identifier lock type %T", value))
	}
	podIdentifierLock.Lock()
	return podIdentifierLock.Unlock
}

func checkAndUpdateBPFBinaries(bpfTCClient tc.BpfTc, bpfBinaries []string, hostBinaryPath string) (bool, bool, bool, error) {
	updateIngressProbe, updateEgressProbe, updateEventsProbe := false, false, false
	var existingProbePath string

	for _, bpfProbe := range bpfBinaries {
		if bpfProbe == EKS_CLI_BINARY || bpfProbe == EKS_V6_CLI_BINARY {
			continue
		}

		log().Infof("Validating Probe: %s", bpfProbe)
		currentProbe, err := os.ReadFile(bpfProbe)
		if err != nil {
			log().Errorf("error opening Probe: %s error: %v", bpfProbe, err)
		}

		existingProbePath = hostBinaryPath + bpfProbe
		existingProbe, err := os.ReadFile(existingProbePath)
		if err != nil {
			log().Errorf("error opening Probe: %s error: %v", existingProbePath, err)
		}

		log().Info("comparing new and existing probes ...")
		isEqual := cmp.Equal(currentProbe, existingProbe)
		if !isEqual {
			if bpfProbe == EVENTS_BINARY || bpfProbe == EVENTS_V6_BINARY {
				// Ingress and Egress probes refer to Conntrack and Policy Events maps defined in
				// events binary. So, if the events binary changes, we will need to update all the existing
				// probes in the local node
				updateEventsProbe, updateIngressProbe, updateEgressProbe = true, true, true
				log().Info("change detected in event probe binaries..")
				break
			}
			if bpfProbe == TC_INGRESS_BINARY || bpfProbe == TC_V6_INGRESS_BINARY {
				log().Info("change detected in ingress probe binaries.. ")
				updateIngressProbe = true
			}
			if bpfProbe == TC_EGRESS_BINARY || bpfProbe == TC_V6_EGRESS_BINARY {
				log().Info("change detected in egress probe binaries..")
				updateEgressProbe = true
			}
		}
	}
	return updateIngressProbe, updateEgressProbe, updateEventsProbe, nil
}

func (l *bpfClient) recoverBPFState(bpfTCClient tc.BpfTc, eBPFSDKClient goelf.BpfSDKClient, policyEndpointeBPFContext *sync.Map, globalMaps *sync.Map, updateIngressProbe,
	updateEgressProbe, updateEventsProbe bool) (bool, bool, int, map[string]string, map[string]string, error) {
	isConntrackMapPresent, isPolicyEventsMapPresent := false, false
	eventsMapFD := 0
	var interfaceNametoIngressPinPath = make(map[string]string)
	var interfaceNametoEgressPinPath = make(map[string]string)

	// Rename legacy "-" separator pin files to the new "_" format using
	// VPC CNI's local pod inventory. Runs once per node, guarded by
	// formatV2MarkerPath.
	if err := migrateLegacyPinsFromCNIState(
		utils.BPF_PROGRAMS_PIN_PATH_DIRECTORY,
		utils.BPF_MAPS_PIN_PATH_DIRECTORY,
		cniIpamStatePath,
		formatV2MarkerPath,
	); err != nil {
		log().Errorf("legacy pin migration failed (non-fatal): %v", err)
	}

	// Recover global maps (Conntrack and Events) if there is no need to update
	// events binary
	if !updateEventsProbe {
		recoveredGlobalMaps, err := eBPFSDKClient.RecoverGlobalMaps()
		if err != nil {
			log().Errorf("failed to recover global maps %v", err)
			sdkAPIErr.WithLabelValues("RecoverGlobalMaps").Inc()
			return isConntrackMapPresent, isPolicyEventsMapPresent, eventsMapFD, interfaceNametoIngressPinPath, interfaceNametoEgressPinPath, nil
		}
		log().Infof("Total no of  global maps recovered count: %d", len(recoveredGlobalMaps))
		for globalMapName, globalMap := range recoveredGlobalMaps {
			log().Infof("Global Map.. Name: %s, updateEventsProbe: %v", globalMapName, updateEventsProbe)
			if globalMapName == CONNTRACK_MAP_PIN_PATH {
				log().Info("Conntrack Map is already present on the node")
				isConntrackMapPresent = true
				globalMaps.Store(globalMapName, globalMap)
			}
			if globalMapName == POLICY_EVENTS_MAP_PIN_PATH {
				isPolicyEventsMapPresent = true
				eventsMapFD = int(globalMap.MapFD)
				log().Infof("Policy event Map is already present on the node Recovered FD: %d", eventsMapFD)
			}
		}
	}

	// If no updates required to probes, Recover BPF Programs and Maps from BPF_FS. We only aim to recover programs and maps
	// created by aws-network-policy-agent (Located under /sys/fs/bpf/globals/aws)
	if !updateIngressProbe || !updateEgressProbe {
		bpfState, err := eBPFSDKClient.RecoverAllBpfProgramsAndMaps()
		if err != nil {
			log().Errorf("BPF State Recovery failed error: %v", err)
			sdkAPIErr.WithLabelValues("RecoverAllBpfProgramAndMaps").Inc()
			return isConntrackMapPresent, isPolicyEventsMapPresent, eventsMapFD, interfaceNametoIngressPinPath, interfaceNametoEgressPinPath, err
		}

		log().Infof("Number of probes/maps recovered - count: %d", len(bpfState))
		type recoveredPodState struct {
			ingress    goelf.BpfData
			hasIngress bool
			egress     goelf.BpfData
			hasEgress  bool
		}
		recoveredPods := make(map[string]*recoveredPodState)
		for pinPath, bpfEntry := range bpfState {
			podIdentifier, direction := utils.GetPodIdentifierFromBPFPinPath(pinPath)
			if direction != "ingress" && direction != "egress" {
				sdkAPIErr.WithLabelValues("RecoverAllBpfProgramAndMaps-UnsupportedDirection").Inc()
				return isConntrackMapPresent, isPolicyEventsMapPresent, eventsMapFD, interfaceNametoIngressPinPath, interfaceNametoEgressPinPath,
					fmt.Errorf("unsupported recovered BPF direction %q for pod %s at %s", direction, podIdentifier, pinPath)
			}

			podState, ok := recoveredPods[podIdentifier]
			if !ok {
				podState = &recoveredPodState{}
				recoveredPods[podIdentifier] = podState
			}

			shouldRecover := (direction == "ingress" && !updateIngressProbe) ||
				(direction == "egress" && !updateEgressProbe)
			if !shouldRecover {
				continue
			}
			if err := validateBPFProgramMapSet(bpfEntry, direction); err != nil {
				sdkAPIErr.WithLabelValues("RecoverAllBpfProgramAndMaps-IncompleteMapSet").Inc()
				return isConntrackMapPresent, isPolicyEventsMapPresent, eventsMapFD, interfaceNametoIngressPinPath, interfaceNametoEgressPinPath,
					fmt.Errorf("invalid recovered BPF state for pod %s at %s: %w", podIdentifier, pinPath, err)
			}

			switch direction {
			case "ingress":
				if podState.hasIngress {
					return isConntrackMapPresent, isPolicyEventsMapPresent, eventsMapFD, interfaceNametoIngressPinPath, interfaceNametoEgressPinPath,
						fmt.Errorf("duplicate recovered ingress BPF state for pod %s at %s", podIdentifier, pinPath)
				}
				podState.ingress = bpfEntry
				podState.hasIngress = true
			case "egress":
				if podState.hasEgress {
					return isConntrackMapPresent, isPolicyEventsMapPresent, eventsMapFD, interfaceNametoIngressPinPath, interfaceNametoEgressPinPath,
						fmt.Errorf("duplicate recovered egress BPF state for pod %s at %s", podIdentifier, pinPath)
				}
				podState.egress = bpfEntry
				podState.hasEgress = true
			}
		}

		// A recovered pod must have every direction that is not being replaced.
		// Publishing one direction as a complete context while silently treating
		// the other as absent would make later map writes target an unusable state.
		for podIdentifier, podState := range recoveredPods {
			if !updateIngressProbe && !podState.hasIngress {
				sdkAPIErr.WithLabelValues("RecoverAllBpfProgramAndMaps-MissingIngress").Inc()
				return isConntrackMapPresent, isPolicyEventsMapPresent, eventsMapFD, interfaceNametoIngressPinPath, interfaceNametoEgressPinPath,
					fmt.Errorf("recovered BPF state for pod %s is missing ingress direction", podIdentifier)
			}
			if !updateEgressProbe && !podState.hasEgress {
				sdkAPIErr.WithLabelValues("RecoverAllBpfProgramAndMaps-MissingEgress").Inc()
				return isConntrackMapPresent, isPolicyEventsMapPresent, eventsMapFD, interfaceNametoIngressPinPath, interfaceNametoEgressPinPath,
					fmt.Errorf("recovered BPF state for pod %s is missing egress direction", podIdentifier)
			}
		}

		podIdentifiers := make([]string, 0, len(recoveredPods))
		for podIdentifier := range recoveredPods {
			podIdentifiers = append(podIdentifiers, podIdentifier)
		}
		sort.Strings(podIdentifiers)
		unlockers := make([]func(), 0, len(podIdentifiers))
		for _, podIdentifier := range podIdentifiers {
			unlockers = append(unlockers, l.lockPodIdentifier(podIdentifier))
		}
		defer func() {
			for index := len(unlockers) - 1; index >= 0; index-- {
				unlockers[index]()
			}
		}()

		type pendingRecoveredMap struct {
			store         *sync.Map
			podIdentifier string
			value         inMemoryBPFMap
		}
		pendingMaps := make([]pendingRecoveredMap, 0)
		pendingContexts := make(map[string]BPFContext, len(recoveredPods))
		for _, podIdentifier := range podIdentifiers {
			podState := recoveredPods[podIdentifier]
			var recoveredContext BPFContext
			if value, ok := policyEndpointeBPFContext.Load(podIdentifier); ok {
				var contextOK bool
				recoveredContext, contextOK = value.(BPFContext)
				if !contextOK {
					return isConntrackMapPresent, isPolicyEventsMapPresent, eventsMapFD, interfaceNametoIngressPinPath, interfaceNametoEgressPinPath,
						fmt.Errorf("unexpected recovered BPF context type %T for pod %s", value, podIdentifier)
				}
			}

			if !updateIngressProbe {
				recoveredContext.ingressPgmInfo = podState.ingress
				mapNames, _ := utils.GetBPFMapNames("ingress")
				if _, ok := l.ingressInMemoryMap.Load(podIdentifier); !ok {
					mapInfo := podState.ingress.Maps[mapNames.NetworkPolicy]
					inMemMap, err := newInMemoryBpfMap(&mapInfo)
					if err != nil {
						sdkAPIErr.WithLabelValues("recoverBPFState-ingress").Inc()
						return isConntrackMapPresent, isPolicyEventsMapPresent, eventsMapFD, interfaceNametoIngressPinPath, interfaceNametoEgressPinPath,
							fmt.Errorf("hydrate recovered ingress map for pod %s: %w", podIdentifier, err)
					}
					pendingMaps = append(pendingMaps, pendingRecoveredMap{l.ingressInMemoryMap, podIdentifier, inMemMap})
				}
				if _, ok := l.clusterPolicyIngressInMemoryMap.Load(podIdentifier); !ok {
					mapInfo := podState.ingress.Maps[mapNames.ClusterNetworkPolicy]
					inMemMap, err := newInMemoryBpfMap(&mapInfo)
					if err != nil {
						sdkAPIErr.WithLabelValues("recoverBPFState-cluster-ingress").Inc()
						return isConntrackMapPresent, isPolicyEventsMapPresent, eventsMapFD, interfaceNametoIngressPinPath, interfaceNametoEgressPinPath,
							fmt.Errorf("hydrate recovered cluster ingress map for pod %s: %w", podIdentifier, err)
					}
					pendingMaps = append(pendingMaps, pendingRecoveredMap{l.clusterPolicyIngressInMemoryMap, podIdentifier, inMemMap})
				}
			}

			if !updateEgressProbe {
				recoveredContext.egressPgmInfo = podState.egress
				mapNames, _ := utils.GetBPFMapNames("egress")
				if _, ok := l.egressInMemoryMap.Load(podIdentifier); !ok {
					mapInfo := podState.egress.Maps[mapNames.NetworkPolicy]
					inMemMap, err := newInMemoryBpfMap(&mapInfo)
					if err != nil {
						sdkAPIErr.WithLabelValues("recoverBPFState-egress").Inc()
						return isConntrackMapPresent, isPolicyEventsMapPresent, eventsMapFD, interfaceNametoIngressPinPath, interfaceNametoEgressPinPath,
							fmt.Errorf("hydrate recovered egress map for pod %s: %w", podIdentifier, err)
					}
					pendingMaps = append(pendingMaps, pendingRecoveredMap{l.egressInMemoryMap, podIdentifier, inMemMap})
				}
				if _, ok := l.clusterPolicyEgressInMemoryMap.Load(podIdentifier); !ok {
					mapInfo := podState.egress.Maps[mapNames.ClusterNetworkPolicy]
					inMemMap, err := newInMemoryBpfMap(&mapInfo)
					if err != nil {
						sdkAPIErr.WithLabelValues("recoverBPFState-cluster-egress").Inc()
						return isConntrackMapPresent, isPolicyEventsMapPresent, eventsMapFD, interfaceNametoIngressPinPath, interfaceNametoEgressPinPath,
							fmt.Errorf("hydrate recovered cluster egress map for pod %s: %w", podIdentifier, err)
					}
					pendingMaps = append(pendingMaps, pendingRecoveredMap{l.clusterPolicyEgressInMemoryMap, podIdentifier, inMemMap})
				}
			}

			pendingContexts[podIdentifier] = recoveredContext
		}

		// Publish only after every recovered direction and shadow map has passed
		// validation/hydration. All affected pod locks remain held, so recovery
		// cannot overwrite a concurrent attach, teardown, or map write.
		for _, pendingMap := range pendingMaps {
			pendingMap.store.Store(pendingMap.podIdentifier, pendingMap.value)
		}
		for podIdentifier, recoveredContext := range pendingContexts {
			policyEndpointeBPFContext.Store(podIdentifier, recoveredContext)
			log().Infof("Recovered BPF context for pod %s", podIdentifier)
		}
	}

	//If update required, cleanup probes and gather data to re attach probes with new programs
	if updateIngressProbe || updateEgressProbe {
		// Get all loaded programs and maps
		bpfState, err := eBPFSDKClient.GetAllBpfProgramsAndMaps()
		if err != nil {
			log().Errorf("GetAllBpfProgramsAndMaps failed %v", err)
			sdkAPIErr.WithLabelValues("GetAllBpfProgramsAndMaps").Inc()
			return isConntrackMapPresent, isPolicyEventsMapPresent, eventsMapFD, interfaceNametoIngressPinPath, interfaceNametoEgressPinPath, err
		}
		log().Infof("GetAllBpfProgramsAndMaps returned %d", len(bpfState))
		progIdToPinPath := make(map[int]string)
		for pinPath, bpfData := range bpfState {
			progId := bpfData.Program.ProgID
			if progId > 0 {
				progIdToPinPath[progId] = pinPath
			}
		}

		// Get attached progIds
		interfaceToIngressProgIds, interfaceToEgressProgIds, err := bpfTCClient.GetAllAttachedProgIds()
		if err != nil {
			log().Errorf("GetAllAttachedProgIds failed %v", err)
			sdkAPIErr.WithLabelValues("GetAllAttachedProgIds").Inc()
			return isConntrackMapPresent, isPolicyEventsMapPresent, eventsMapFD, interfaceNametoIngressPinPath, interfaceNametoEgressPinPath, err
		}
		log().Infof("Got attached ingressprogIds: %d, egressprogIds: %d", len(interfaceToIngressProgIds), len(interfaceToEgressProgIds))

		//cleanup all existing filters
		cleanupErr := bpfTCClient.CleanupQdiscs(updateIngressProbe, updateEgressProbe)
		if cleanupErr != nil {
			// log the error and continue. Attaching new probes will cleanup the old ones
			log().Errorf("Probe cleanup failed error: %v", cleanupErr)
			sdkAPIErr.WithLabelValues("CleanupQdiscs").Inc()
		}

		for interfaceName, existingIngressProgId := range interfaceToIngressProgIds {
			pinPath, ok := progIdToPinPath[existingIngressProgId]
			if ok && updateIngressProbe {
				interfaceNametoIngressPinPath[interfaceName] = pinPath
			}
		}
		for interfaceName, existingEgressProgId := range interfaceToEgressProgIds {
			pinPath, ok := progIdToPinPath[existingEgressProgId]
			if ok && updateEgressProbe {
				interfaceNametoEgressPinPath[interfaceName] = pinPath
			}
		}
		log().Info("Collected all data for reattaching probes")
	}

	return isConntrackMapPresent, isPolicyEventsMapPresent, eventsMapFD, interfaceNametoIngressPinPath, interfaceNametoEgressPinPath, nil
}

func (l *bpfClient) ReAttachEbpfProbes() error {
	state := DEFAULT_ALLOW
	if utils.IsStrictMode(l.networkPolicyMode) {
		state = DEFAULT_DENY
	}

	for interfaceName, pinPath := range l.interfaceNametoIngressPinPath {
		podIdentifier, _ := utils.GetPodIdentifierFromBPFPinPath(pinPath)
		unlock := l.lockPodIdentifier(podIdentifier)
		log().Infof("ReattachEbpfProbes attaching ingress for %s interface %s", podIdentifier, interfaceName)
		_, err := l.attachIngressBPFProbe(interfaceName, podIdentifier)
		if err != nil {
			unlock()
			log().Errorf("Failed to Attach Ingress TC probe for interface: %s podIdentifier: %s error: %v", interfaceName, podIdentifier, err)
			sdkAPIErr.WithLabelValues("attachIngressBPFProbe").Inc()
			return fmt.Errorf("reattach ingress probe for pod %s on interface %s: %w", podIdentifier, interfaceName, err)
		}
		log().Infof("Updating ingress_pod_state map for podIdentifier: %s, networkPolicyMode: %s", podIdentifier, l.networkPolicyMode)
		err = l.updatePodStateEbpfMaps(podIdentifier, POD_STATE_MAP_KEY, state, true, false)
		if err != nil {
			unlock()
			log().Errorf("Map update(s) failed for podIdentifier %s error: %v", podIdentifier, err)
			return fmt.Errorf("reattach ingress pod state for pod %s: %w", podIdentifier, err)
		}
		err = l.updatePodStateEbpfMaps(podIdentifier, CLUSTER_POLICY_POD_STATE_MAP_KEY, state, true, false)
		unlock()
		if err != nil {
			log().Errorf("Map update(s) failed for podIdentifier %s error: %v", podIdentifier, err)
			return fmt.Errorf("reattach ingress cluster pod state for pod %s: %w", podIdentifier, err)
		}

	}

	for interfaceName, pinPath := range l.interfaceNametoEgressPinPath {
		podIdentifier, _ := utils.GetPodIdentifierFromBPFPinPath(pinPath)
		unlock := l.lockPodIdentifier(podIdentifier)
		log().Infof("ReattachEbpfProbes attaching egress for %s interface %s", podIdentifier, interfaceName)
		_, err := l.attachEgressBPFProbe(interfaceName, podIdentifier)
		if err != nil {
			unlock()
			log().Errorf("Failed to Attach Egress TC probe for interface: %s podIdentifier %s error: %v", interfaceName, podIdentifier, err)
			sdkAPIErr.WithLabelValues("attachEgressBPFProbe").Inc()
			return fmt.Errorf("reattach egress probe for pod %s on interface %s: %w", podIdentifier, interfaceName, err)
		}

		log().Infof("Updating egress_pod_state map for podIdentifier: %s, networkPolicyMode: %s", podIdentifier, l.networkPolicyMode)
		err = l.updatePodStateEbpfMaps(podIdentifier, POD_STATE_MAP_KEY, state, false, true)
		if err != nil {
			unlock()
			log().Errorf("Map update(s) failed for podIdentifier %s error: %v", podIdentifier, err)
			return fmt.Errorf("reattach egress pod state for pod %s: %w", podIdentifier, err)
		}

		err = l.updatePodStateEbpfMaps(podIdentifier, CLUSTER_POLICY_POD_STATE_MAP_KEY, state, false, true)
		unlock()
		if err != nil {
			log().Errorf("Map update(s) failed for podIdentifier %s error: %v", podIdentifier, err)
			return fmt.Errorf("reattach egress cluster pod state for pod %s: %w", podIdentifier, err)
		}
	}
	return nil
}

func (l *bpfClient) GetNetworkPolicyMode() string {
	return l.networkPolicyMode
}

// loadIPAMDataFromFile reads IPAM JSON file from specified path and caches pod to interface count mapping
func (l *bpfClient) loadIPAMDataFromFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read ipam.json file: %v", err)
	}

	var checkpointData datastore.CheckpointData
	if err := json.Unmarshal(data, &checkpointData); err != nil {
		return fmt.Errorf("failed to parse ipam.json: %v", err)
	}

	// Store interface count per pod from IPAM data
	for _, entry := range checkpointData.Allocations {
		// Skip entries with missing pod information
		if entry.Metadata.K8SPodName == "" || entry.Metadata.K8SPodNamespace == "" {
			continue
		}

		podNamespacedName := utils.GetPodNamespacedName(entry.Metadata.K8SPodName, entry.Metadata.K8SPodNamespace)
		if entry.Metadata.InterfacesCount > 0 {
			l.podNameToInterfaceCount.Store(podNamespacedName, entry.Metadata.InterfacesCount)
			log().Debugf("Cached interface count for pod %s: %d", podNamespacedName, entry.Metadata.InterfacesCount)
		}
	}

	log().Infof("Loaded IPAM data from %d allocations", len(checkpointData.Allocations))
	return nil
}

// getInterfaceCountFromBackupFile attempts to read interface count from ipam.json loaded in podNameToInterfaceCount cache
func (l *bpfClient) getInterfaceCountFromBackupFile(pod types.NamespacedName, podIdentifier string) (int, error) {
	podNamespacedName := utils.GetPodNamespacedName(pod.Name, pod.Namespace)
	if count, ok := l.podNameToInterfaceCount.Load(podNamespacedName); ok {
		return count.(int), nil
	}
	return 0, errors.New("interface count not found in podNameToInterfaceCount cache")
}

// getInterfaceCountForPod determines the number of interfaces for a pod
// Returns the interface count or an error if it cannot be determined
func (l *bpfClient) getInterfaceCountForPod(pod types.NamespacedName, podIdentifier string, providedCount int) (int, error) {
	// If interface count is provided (from RPC call), use it
	if providedCount > 0 {
		return providedCount, nil
	}

	// If multi-NIC is not enabled, default to 1 interface
	if !l.isMultiNICEnabled {
		return INTERFACE_COUNT_DEFAULT, nil
	}

	// Multi-NIC is enabled but we don't have interface count
	// Try to get interface count from podNameToInterfaceCount cache
	backupInterfaceCount, err := l.getInterfaceCountFromBackupFile(pod, podIdentifier)
	if err == nil && backupInterfaceCount > 0 {
		log().Infof("Found interface count %d from cache for pod %s", backupInterfaceCount, pod.Name)
		return backupInterfaceCount, nil
	}

	// No interface count available and multi-NIC enabled - skip attachment
	return 0, errors.New("Skipping probe attach: multiNIC enabled and interface count is unknown")
}

func (l *bpfClient) AttacheBPFProbes(pod types.NamespacedName, podIdentifier string, numInterfaces int) error {
	var ingressProgFD int
	var egressProgFD int

	podNamespacedName := utils.GetPodNamespacedName(pod.Name, pod.Namespace)

	if _, deleted := l.deletedPods.Load(podNamespacedName); deleted {
		log().Debugf("ignoring attaching ebpf probe to pod %s in namespace %s with pod identifier %s as it is already deleted", pod.Name, pod.Namespace, podIdentifier)
		return nil
	}

	// Two go routines can try to attach the probes at the same time. Locking
	// keeps the context and attachment indexes consistent.
	unlock := l.lockPodIdentifier(podIdentifier)
	log().Debugf("Got the podIdentifierLock for Pod: %s, Namespace: %s, PodIdentifier: %s", pod.Name, pod.Namespace, podIdentifier)
	defer unlock()

	// Check if an eBPF probe is already attached on both ingress and egress direction(s) for this pod.
	// If yes, then skip probe attach flow for this pod.
	isIngressProbeAttached, isEgressProbeAttached := l.isEBPFProbeAttached(pod.Name, pod.Namespace)
	if isIngressProbeAttached && isEgressProbeAttached {
		return nil
	}

	// Determine the actual number of interfaces to attach probes to
	actualInterfaceCount, err := l.getInterfaceCountForPod(pod, podIdentifier, numInterfaces)
	if err != nil {
		return err
	}

	numInterfaces = actualInterfaceCount

	for index := 0; index < numInterfaces; index++ {
		// We attach the TC probes to the hostVeth interfaces of the pod. Derive the hostVeth name from the Name and Namespace of the Pod.
		// Note: The below naming convention is tied to VPC CNI and isn't meant to be generic
		hostVethName, err := utils.GetHostVethName(pod.Name, pod.Namespace, index, []string{POD_VETH_PREFIX, BRANCH_ENI_VETH_PREFIX})
		if err != nil {
			log().Warnf("Failed to attach ebpf probes for pod %s in namespace %s. Pod might have been deleted", pod.Name, pod.Namespace)
			return err
		}

		log().Infof("AttacheBPFProbes for pod %s in namespace %s with hostVethName %s at interface %d", pod.Name, pod.Namespace, hostVethName, index)

		if !isIngressProbeAttached {
			start := time.Now()
			ingressProgFD, err = l.attachIngressBPFProbe(hostVethName, podIdentifier)
			duration := msSince(start)
			sdkAPILatency.WithLabelValues("attachIngressBPFProbe", fmt.Sprint(err != nil)).Observe(duration)
			if err != nil {
				log().Errorf("Failed to Attach Ingress TC probe for pod: %s in namespace %s at interface %d error: %v", pod.Name, pod.Namespace, index, err)
				sdkAPIErr.WithLabelValues("attachIngressBPFProbe").Inc()
				return err
			}
			log().Infof("Successfully attached Ingress TC probe for pod: %s in namespace %s at interface %d", pod.Name, pod.Namespace, index)
		}

		if !isEgressProbeAttached {
			start := time.Now()
			egressProgFD, err = l.attachEgressBPFProbe(hostVethName, podIdentifier)
			duration := msSince(start)
			sdkAPILatency.WithLabelValues("attachEgressBPFProbe", fmt.Sprint(err != nil)).Observe(duration)
			if err != nil {
				log().Errorf("Failed to Attach Egress TC probe for pod: %s in namespace %s at interface %d error: %v", pod.Name, pod.Namespace, index, err)
				sdkAPIErr.WithLabelValues("attachEgressBPFProbe").Inc()
				return err
			}
			log().Infof("Successfully attached Egress TC probe for pod: %s in namespace %s at interface %d", pod.Name, pod.Namespace, index)
		}
	}
	if !isIngressProbeAttached {
		l.ingressPodToProgMap.Store(podNamespacedName, ingressProgFD)
		currentPodSet, _ := l.ingressProgToPodsMap.LoadOrStore(ingressProgFD, make(map[string]struct{}))
		currentPodSet.(map[string]struct{})[podNamespacedName] = struct{}{}
	}

	if !isEgressProbeAttached {
		l.egressPodToProgMap.Store(podNamespacedName, egressProgFD)
		currentPodSet, _ := l.egressProgToPodsMap.LoadOrStore(egressProgFD, make(map[string]struct{}))
		currentPodSet.(map[string]struct{})[podNamespacedName] = struct{}{}
	}
	return nil
}

func (l *bpfClient) attachIngressBPFProbe(hostVethName string, podIdentifier string) (int, error) {
	// We will re-use the same eBPF program instance for pods belonging to same replicaset
	// Check if we've already loaded an ELF file for this PolicyEndpoint resource and re-use
	// if present, otherwise load a new instance and attach it

	var progFD int
	var err error
	var ingressProgInfo map[string]goelf.BpfData
	var peBPFContext BPFContext
	value, ok := l.policyEndpointeBPFContext.Load(podIdentifier)
	if ok {
		peBPFContext = value.(BPFContext)
	}

	if peBPFContext.ingressPgmInfo.Program.ProgFD > 0 {
		log().Info("Found an existing instance, let's derive the ingress context..")
		ingressEbpfProgEntry := peBPFContext.ingressPgmInfo
		progFD = ingressEbpfProgEntry.Program.ProgFD
	} else {
		ingressProgInfo, progFD, err = l.loadBPFProgram(l.ingressBinary, "ingress", podIdentifier)
		if err != nil {
			return 0, err
		}
		pinPath := utils.GetBPFPinPathFromPodIdentifier(podIdentifier, "ingress")
		peBPFContext.ingressPgmInfo = ingressProgInfo[pinPath]
		l.policyEndpointeBPFContext.Store(podIdentifier, peBPFContext)
	}

	log().Infof("Attempting to do an Ingress Attach with progFD: %d", progFD)
	err = l.bpfTCClient.TCEgressAttach(hostVethName, progFD, utils.TC_INGRESS_PROG)
	if err != nil {
		log().Errorf("Ingress Attach failed %v", err)
		return 0, err
	}
	return progFD, nil
}

func (l *bpfClient) attachEgressBPFProbe(hostVethName string, podIdentifier string) (int, error) {
	// We will re-use the same eBPF program instance for pods belonging to same replicaset
	// Check if we've already loaded an ELF file for this PolicyEndpoint resource and re-use
	// if present, otherwise load a new instance and attach it

	var progFD int
	var err error
	var egressProgInfo map[string]goelf.BpfData
	var peBPFContext BPFContext
	value, ok := l.policyEndpointeBPFContext.Load(podIdentifier)
	if ok {
		peBPFContext = value.(BPFContext)
	}

	if peBPFContext.egressPgmInfo.Program.ProgFD > 0 {
		log().Info("Found an existing instance, let's derive the egress context..")
		egressEbpfProgEntry := peBPFContext.egressPgmInfo
		progFD = egressEbpfProgEntry.Program.ProgFD
	} else {
		egressProgInfo, progFD, err = l.loadBPFProgram(l.egressBinary, "egress", podIdentifier)
		if err != nil {
			return 0, err
		}
		pinPath := utils.GetBPFPinPathFromPodIdentifier(podIdentifier, "egress")
		peBPFContext.egressPgmInfo = egressProgInfo[pinPath]
		l.policyEndpointeBPFContext.Store(podIdentifier, peBPFContext)
	}

	log().Infof("Attempting to do an Egress Attach with progFD: %d", progFD)
	err = l.bpfTCClient.TCIngressAttach(hostVethName, progFD, utils.TC_EGRESS_PROG)
	if err != nil {
		log().Errorf("Egress Attach failed %v", err)
		return 0, err
	}

	return progFD, nil
}

func (l *bpfClient) ClearDeletedPod(podNamespacedName string) {
	l.deletedPods.Delete(podNamespacedName)
}

func (l *bpfClient) DeleteBPFProbes(pod types.NamespacedName, podIdentifier string) error {
	unlock := l.lockPodIdentifier(podIdentifier)
	defer unlock()
	log().Debugf("Got the podIdentifierLock for Pod: %s Namespace: %s PodIdentifier: %s", pod.Name, pod.Namespace, podIdentifier)

	isProgFdShared, err := l.isProgFdShared(pod.Name, pod.Namespace)
	if err != nil {
		// Preserve the existing behavior for a pod that has no attachment index:
		// there is no safe program ownership proof from which to delete a shared
		// pod-identifier resource.
		l.deletedPods.Store(utils.GetPodNamespacedName(pod.Name, pod.Namespace), time.Now())
		return nil
	}

	if !isProgFdShared {
		if err := l.deleteBPFProbes(podIdentifier); err != nil {
			// Keep the attachment indexes and deleted marker intact so a retry can
			// find and finish any resources whose cleanup failed.
			log().Errorf("BPF programs and Maps delete failed for podIdentifier: %s, error: %v", podIdentifier, err)
			return err
		}
	}

	l.deletePodFromIngressProgPodCaches(pod.Name, pod.Namespace)
	l.deletePodFromEgressProgPodCaches(pod.Name, pod.Namespace)
	l.deletedPods.Store(utils.GetPodNamespacedName(pod.Name, pod.Namespace), time.Now())
	return nil
}

func (l *bpfClient) deleteBPFProbes(podIdentifier string) error {
	start := time.Now()
	ingressErr := l.deleteBPFProgramAndMaps(podIdentifier, "ingress")
	duration := msSince(start)
	sdkAPILatency.WithLabelValues("deleteBPFProgramAndMaps", fmt.Sprint(ingressErr != nil)).Observe(duration)
	if ingressErr != nil {
		log().Errorf("Error while deleting Ingress BPF Probe for podIdentifier: %s error: %v", podIdentifier, ingressErr)
		sdkAPIErr.WithLabelValues("deleteBPFProgramAndMaps").Inc()
	}

	start = time.Now()
	egressErr := l.deleteBPFProgramAndMaps(podIdentifier, "egress")
	duration = msSince(start)
	sdkAPILatency.WithLabelValues("deleteBPFProgramAndMaps", fmt.Sprint(egressErr != nil)).Observe(duration)
	if egressErr != nil {
		log().Errorf("Error while deleting Egress BPF Probe for podIdentifier: %s error: %v", podIdentifier, egressErr)
		sdkAPIErr.WithLabelValues("deleteBPFProgramAndMaps").Inc()
	}

	err := errors.Join(ingressErr, egressErr)
	if err == nil {
		l.ingressInMemoryMap.Delete(podIdentifier)
		l.egressInMemoryMap.Delete(podIdentifier)
		l.clusterPolicyIngressInMemoryMap.Delete(podIdentifier)
		l.clusterPolicyEgressInMemoryMap.Delete(podIdentifier)
		l.policyEndpointeBPFContext.Delete(podIdentifier)
	}
	return err
}

func (l *bpfClient) deleteBPFProgramAndMaps(podIdentifier string, direction string) error {
	mapNames, ok := utils.GetBPFMapNames(direction)
	if !ok {
		return fmt.Errorf("unsupported BPF program direction %q", direction)
	}

	var peBPFContext BPFContext
	value, ok := l.policyEndpointeBPFContext.Load(podIdentifier)
	if !ok {
		return fmt.Errorf("cannot delete %s BPF resources for pod %s: context is not registered", direction, podIdentifier)
	}
	var contextOK bool
	peBPFContext, contextOK = value.(BPFContext)
	if !contextOK {
		return fmt.Errorf("unexpected bpf context type %T for pod %s", value, podIdentifier)
	}

	pgmPinPath := utils.GetBPFPinPathFromPodIdentifier(podIdentifier, direction)
	mapPinPath := utils.GetBPFMapPinPathFromPodIdentifierAndMapName(podIdentifier, mapNames.NetworkPolicy)
	clusterPolicyMapPinPath := utils.GetBPFMapPinPathFromPodIdentifierAndMapName(podIdentifier, mapNames.ClusterNetworkPolicy)
	podStateMapPinPath := utils.GetBPFMapPinPathFromPodIdentifierAndMapName(podIdentifier, mapNames.PodState)

	log().Infof("Deleting: Program: %s Map: %s Map: %s", pgmPinPath, mapPinPath, podStateMapPinPath)

	pgmInfo := peBPFContext.ingressPgmInfo
	if direction == "egress" {
		pgmInfo = peBPFContext.egressPgmInfo
	}

	log().Infof("Found the Program and Map to delete - Program: %s Map: %s Map: %s", pgmPinPath, mapPinPath, podStateMapPinPath)
	var cleanupErr error
	if err := unpinAndCloseBPFProgram(&pgmInfo.Program, pgmPinPath); err != nil {
		log().Errorf("Failed to delete the Program: %v", err)
		cleanupErr = errors.Join(cleanupErr, fmt.Errorf("unpin program: %w", err))
	}
	if pgmInfo.Maps == nil {
		pgmInfo.Maps = make(map[string]goebpfmaps.BpfMap)
	}
	mapPinPaths := map[string]string{
		mapNames.NetworkPolicy:        mapPinPath,
		mapNames.ClusterNetworkPolicy: clusterPolicyMapPinPath,
		mapNames.PodState:             podStateMapPinPath,
	}
	for _, mapName := range mapNames.Required() {
		pinPath := mapPinPaths[mapName]
		mapToDelete := pgmInfo.Maps[mapName]
		if err := unpinAndCloseBPFMap(&mapToDelete, pinPath); err != nil {
			log().Errorf("Failed to delete map %s: %v", mapName, err)
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("unpin map %s: %w", mapName, err))
		}
		pgmInfo.Maps[mapName] = mapToDelete
	}

	if direction == "ingress" {
		peBPFContext.ingressPgmInfo = pgmInfo
	} else {
		peBPFContext.egressPgmInfo = pgmInfo
	}
	l.policyEndpointeBPFContext.Store(podIdentifier, peBPFContext)
	return cleanupErr
}

func (l *bpfClient) loadBPFProgram(fileName string, direction string,
	podIdentifier string) (map[string]goelf.BpfData, int, error) {

	start := time.Now()
	log().Info("Load the eBPF program")
	// Load a new instance of the program
	progInfo, loadedMapData, err := l.bpfSDKClient.LoadBpfFile(fileName, podIdentifier)
	duration := msSince(start)
	sdkAPILatency.WithLabelValues("LoadBpfFile", fmt.Sprint(err != nil)).Observe(duration)
	if err != nil {
		sdkAPIErr.WithLabelValues("LoadBpfFile").Inc()
		log().Errorf("Load BPF failed err: %v", err)
		return nil, -1, errors.Join(err, cleanupLoadedBPFData(podIdentifier, direction, progInfo, loadedMapData))
	}
	cleanupAndReturn := func(loadErr error) (map[string]goelf.BpfData, int, error) {
		cleanupErr := cleanupLoadedBPFData(podIdentifier, direction, progInfo, loadedMapData)
		if cleanupErr != nil {
			loadErr = errors.Join(loadErr, fmt.Errorf("cleanup resources from rejected BPF load: %w", cleanupErr))
		}
		return nil, -1, loadErr
	}

	// Validate the loaded program before returning it. A successful LoadBpfFile
	// must yield a program with a valid FD and its associated maps linked.
	pinPath := utils.GetBPFPinPathFromPodIdentifier(podIdentifier, direction)
	bpfData, ok := progInfo[pinPath]
	if !ok {
		sdkAPIErr.WithLabelValues("LoadBpfFile-NoPinPath").Inc()
		return cleanupAndReturn(fmt.Errorf("no program data found at pinPath %s for pod %s direction %s", pinPath, podIdentifier, direction))
	}

	progFD := bpfData.Program.ProgFD
	if progFD <= 0 {
		sdkAPIErr.WithLabelValues("LoadBpfFile-InvalidFD").Inc()
		return cleanupAndReturn(fmt.Errorf("program loaded with invalid FD %d for pod %s direction %s", progFD, podIdentifier, direction))
	}

	if err := validateBPFProgramMapSet(bpfData, direction); err != nil {
		sdkAPIErr.WithLabelValues("LoadBpfFile-IncompleteMapSet").Inc()
		return cleanupAndReturn(fmt.Errorf("invalid BPF program for pod %s: %w", podIdentifier, err))
	}

	log().Infof("Prog Load Succeeded for %s, progFD: %d, pinpath: %s, maps: %d", direction, progFD, pinPath, len(bpfData.Maps))

	return progInfo, progFD, nil
}

// cleanupLoadedBPFData releases the pod-scoped resources returned by a load
// that cannot be used. The SDK returns all loaded maps separately from each
// program's associated map view; using that second result avoids missing maps
// when the program result is incomplete. Shared global maps are deliberately
// excluded because their ownership is not local to this load.
func cleanupLoadedBPFData(podIdentifier, direction string, progInfo map[string]goelf.BpfData,
	loadedMapData map[string]goebpfmaps.BpfMap) error {
	mapNames, ok := utils.GetBPFMapNames(direction)
	if !ok {
		return fmt.Errorf("unsupported BPF program direction %q", direction)
	}

	var cleanupErr error
	programPrefix := utils.BPF_PROGRAMS_PIN_PATH_DIRECTORY + podIdentifier + "_"
	programSuffix := utils.TC_INGRESS_PROG
	if direction == "egress" {
		programSuffix = utils.TC_EGRESS_PROG
	}
	for pinPath, bpfData := range progInfo {
		if !strings.HasPrefix(pinPath, programPrefix) || !strings.HasSuffix(pinPath, programSuffix) {
			continue
		}
		if err := unpinAndCloseBPFProgram(&bpfData.Program, pinPath); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("unpin program %s: %w", pinPath, err))
		}
	}

	for _, mapName := range mapNames.Required() {
		mapInfo, found := loadedMapData[mapName]
		if !found {
			continue
		}
		pinPath := utils.GetBPFMapPinPathFromPodIdentifierAndMapName(podIdentifier, mapName)
		if err := unpinAndCloseBPFMap(&mapInfo, pinPath); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("unpin map %s: %w", mapName, err))
		}
	}
	return cleanupErr
}

// unpinAndCloseBPFProgram separates unpinning from closing so a close error
// cannot cause a later retry to close a potentially reused descriptor twice.
// The SDK version used by this agent does not clear the descriptor itself.
func unpinAndCloseBPFProgram(program *goebpfprogs.BpfProgram, pinPath string) error {
	if err := goebpfutils.UnPinObject(pinPath); err != nil {
		return err
	}
	fd := program.ProgFD
	program.ProgFD = 0
	if fd <= 0 {
		return nil
	}
	return unix.Close(fd)
}

// unpinAndCloseBPFMap is the map equivalent of unpinAndCloseBPFProgram.
func unpinAndCloseBPFMap(mapInfo *goebpfmaps.BpfMap, pinPath string) error {
	if err := goebpfutils.UnPinObject(pinPath); err != nil {
		return err
	}
	fd := mapInfo.MapFD
	mapInfo.MapFD = 0
	if fd == 0 {
		return nil
	}
	return unix.Close(int(fd))
}

// validateBPFProgramMapSet verifies that the SDK returned every map associated
// with the requested namespaced TC program. A missing map is represented by a
// zero-valued BpfMap when indexed later, so accepting an incomplete set would
// defer the failure until a kernel map update.
func validateBPFProgramMapSet(bpfData goelf.BpfData, direction string) error {
	mapNames, ok := utils.GetBPFMapNames(direction)
	if !ok {
		return fmt.Errorf("unsupported BPF program direction %q", direction)
	}
	if bpfData.Program.ProgFD <= 0 {
		return fmt.Errorf("program has invalid FD %d for direction %q", bpfData.Program.ProgFD, direction)
	}

	missingMapNames := make([]string, 0)
	for _, mapName := range mapNames.Required() {
		mapInfo, found := bpfData.Maps[mapName]
		if !found || mapInfo.MapFD == 0 {
			missingMapNames = append(missingMapNames, mapName)
		}
	}
	if len(missingMapNames) != 0 {
		return fmt.Errorf("incomplete map set for direction %q; missing required maps: %v", direction, missingMapNames)
	}
	return nil
}

func validateBPFContext(peBPFContext BPFContext, podIdentifier string, validateIngress, validateEgress bool) error {
	var validationErr error
	if validateIngress {
		if err := validateBPFProgramMapSet(peBPFContext.ingressPgmInfo, "ingress"); err != nil {
			validationErr = errors.Join(validationErr, fmt.Errorf("invalid ingress BPF context for pod %s: %w", podIdentifier, err))
		}
	}
	if validateEgress {
		if err := validateBPFProgramMapSet(peBPFContext.egressPgmInfo, "egress"); err != nil {
			validationErr = errors.Join(validationErr, fmt.Errorf("invalid egress BPF context for pod %s: %w", podIdentifier, err))
		}
	}
	return validationErr
}

// UpdateEbpfMaps writes the namespaced-policy ingress and egress firewall rule
// sets for podIdentifier into the kernel TC_INGRESS_MAP / TC_EGRESS_MAP, hydrating
// the userspace shadow map on first use. Ingress and egress are attempted
// independently and any errors are returned joined.
func (l *bpfClient) UpdateEbpfMaps(podIdentifier string, ingressFirewallRules []fwrp.EbpfFirewallRules,
	egressFirewallRules []fwrp.EbpfFirewallRules) error {

	unlock := l.lockPodIdentifier(podIdentifier)
	defer unlock()

	start := time.Now()
	var ingressErr, egressErr error
	value, ok := l.policyEndpointeBPFContext.Load(podIdentifier)
	if !ok {
		sdkAPIErr.WithLabelValues("updateEbpfMap-no-context").Inc()
		return fmt.Errorf("no bpf context registered for pod %s", podIdentifier)
	}
	peBPFContext, ok := value.(BPFContext)
	if !ok {
		sdkAPIErr.WithLabelValues("updateEbpfMap-bad-context-type").Inc()
		return fmt.Errorf("unexpected bpf context type %T for pod %s", value, podIdentifier)
	}
	ingressProgInfo := peBPFContext.ingressPgmInfo
	egressProgInfo := peBPFContext.egressPgmInfo
	if err := validateBPFContext(peBPFContext, podIdentifier, true, true); err != nil {
		sdkAPIErr.WithLabelValues("updateEbpfMap-invalid-context").Inc()
		return err
	}

	if ingressProgInfo.Program.ProgFD > 0 {
		ingressProgFD := ingressProgInfo.Program.ProgFD
		mapToUpdate := ingressProgInfo.Maps[utils.TC_INGRESS_MAP]
		log().Infof("Pod has an Ingress hook attached. Update the corresponding map progFD: %d, mapName: %s", ingressProgFD, utils.TC_INGRESS_MAP)

		inMemVal, exists := l.ingressInMemoryMap.Load(podIdentifier)
		if !exists {
			log().Infof("Ingress in-mem map not found for %v", podIdentifier)
			inMemMap, err := newInMemoryBpfMap(&mapToUpdate)
			if err != nil {
				ingressErr = fmt.Errorf("ingress in-mem map hydrate: %w", err)
			} else {
				l.ingressInMemoryMap.Store(podIdentifier, inMemMap)
				log().Infof("ingress map for %v loaded successfully", podIdentifier)
				inMemVal = inMemMap
			}
		}

		if ingressErr == nil {
			inMemMap, typeOk := inMemVal.(inMemoryBPFMap)
			if !typeOk {
				ingressErr = fmt.Errorf("ingress in-mem map: unexpected type %T", inMemVal)
			} else {
				writeErr := l.updateEbpfMap(ingressFirewallRules, inMemMap)
				duration := msSince(start)
				sdkAPILatency.WithLabelValues("updateEbpfMap-ingress", fmt.Sprint(writeErr != nil)).Observe(duration)
				if writeErr != nil {
					ingressErr = fmt.Errorf("ingress map write: %w", writeErr)
				}
			}
		}
		if ingressErr != nil {
			log().Errorf("Ingress Map update failed: %v", ingressErr)
			sdkAPIErr.WithLabelValues("updateEbpfMap-ingress").Inc()
		}
	}
	if egressProgInfo.Program.ProgFD > 0 {
		egressProgFD := egressProgInfo.Program.ProgFD
		mapToUpdate := egressProgInfo.Maps[utils.TC_EGRESS_MAP]

		log().Infof("Pod has an Egress hook attached. Update the corresponding map progFD: %d, mapName: %s", egressProgFD, utils.TC_EGRESS_MAP)

		inMemVal, exists := l.egressInMemoryMap.Load(podIdentifier)
		if !exists {
			log().Infof("didn't find egress in-mem map for %v", podIdentifier)
			inMemMap, err := newInMemoryBpfMap(&mapToUpdate)
			if err != nil {
				egressErr = fmt.Errorf("egress in-mem map hydrate: %w", err)
			} else {
				l.egressInMemoryMap.Store(podIdentifier, inMemMap)
				log().Infof("egress map for %v loaded successfully", podIdentifier)
				inMemVal = inMemMap
			}
		}

		if egressErr == nil {
			inMemMap, typeOk := inMemVal.(inMemoryBPFMap)
			if !typeOk {
				egressErr = fmt.Errorf("egress in-mem map: unexpected type %T", inMemVal)
			} else {
				writeErr := l.updateEbpfMap(egressFirewallRules, inMemMap)
				duration := msSince(start)
				sdkAPILatency.WithLabelValues("updateEbpfMap-egress", fmt.Sprint(writeErr != nil)).Observe(duration)
				if writeErr != nil {
					egressErr = fmt.Errorf("egress map write: %w", writeErr)
				}
			}
		}
		if egressErr != nil {
			log().Errorf("Egress Map update failed: %v", egressErr)
			sdkAPIErr.WithLabelValues("updateEbpfMap-egress").Inc()
		}
	}
	return errors.Join(ingressErr, egressErr)
}

// UpdateClusterPolicyEbpfMaps writes the cluster-policy ingress and egress
// firewall rule sets for podIdentifier into the kernel
// TC_CLUSTER_POLICY_INGRESS_MAP / TC_CLUSTER_POLICY_EGRESS_MAP, hydrating the
// userspace shadow map on first use. Ingress and egress are attempted
// independently and any errors are returned joined.
func (l *bpfClient) UpdateClusterPolicyEbpfMaps(podIdentifier string, ingressFirewallRules []fwrp.EbpfFirewallRules,
	egressFirewallRules []fwrp.EbpfFirewallRules) error {

	unlock := l.lockPodIdentifier(podIdentifier)
	defer unlock()

	var ingressProgFD, egressProgFD int
	start := time.Now()
	var ingressErr, egressErr error
	value, ok := l.policyEndpointeBPFContext.Load(podIdentifier)
	if !ok {
		sdkAPIErr.WithLabelValues("updateClusterPolicyEbpfMap-no-context").Inc()
		return fmt.Errorf("no bpf context registered for pod %s", podIdentifier)
	}
	peBPFContext, ok := value.(BPFContext)
	if !ok {
		sdkAPIErr.WithLabelValues("updateClusterPolicyEbpfMap-bad-context-type").Inc()
		return fmt.Errorf("unexpected bpf context type %T for pod %s", value, podIdentifier)
	}
	ingressProgInfo := peBPFContext.ingressPgmInfo
	egressProgInfo := peBPFContext.egressPgmInfo
	if err := validateBPFContext(peBPFContext, podIdentifier, true, true); err != nil {
		sdkAPIErr.WithLabelValues("updateClusterPolicyEbpfMap-invalid-context").Inc()
		return err
	}

	if ingressProgInfo.Program.ProgFD > 0 {
		ingressProgFD = ingressProgInfo.Program.ProgFD
		mapToUpdate := ingressProgInfo.Maps[utils.TC_CLUSTER_POLICY_INGRESS_MAP]
		log().Infof("Pod has a ClusterPolicyIngress hook attached. Update the corresponding map progFD: %d, mapName: %s", ingressProgFD, utils.TC_CLUSTER_POLICY_INGRESS_MAP)

		inMemVal, exists := l.clusterPolicyIngressInMemoryMap.Load(podIdentifier)
		if !exists {
			log().Infof("Cluster Policy Ingress in-mem map not found for %v", podIdentifier)
			inMemMap, err := newInMemoryBpfMap(&mapToUpdate)
			if err != nil {
				ingressErr = fmt.Errorf("cluster policy ingress in-mem map hydrate: %w", err)
			} else {
				l.clusterPolicyIngressInMemoryMap.Store(podIdentifier, inMemMap)
				log().Infof("cluster policy ingress map for %v loaded successfully", podIdentifier)
				inMemVal = inMemMap
			}
		}
		if ingressErr == nil {
			inMemMap, typeOk := inMemVal.(inMemoryBPFMap)
			if !typeOk {
				ingressErr = fmt.Errorf("cluster policy ingress in-mem map: unexpected type %T", inMemVal)
			} else {
				writeErr := l.updateClusterPolicyEbpfMap(ingressFirewallRules, inMemMap)
				duration := msSince(start)
				sdkAPILatency.WithLabelValues("updateClusterPolicyEbpfMap-ingress", fmt.Sprint(writeErr != nil)).Observe(duration)
				if writeErr != nil {
					ingressErr = fmt.Errorf("cluster policy ingress map write: %w", writeErr)
				}
			}
		}
		if ingressErr != nil {
			log().Errorf("Ingress Map update failed: %v", ingressErr)
			sdkAPIErr.WithLabelValues("updateClusterPolicyEbpfMap-ingress").Inc()
		}
	}
	if egressProgInfo.Program.ProgFD > 0 {
		egressProgFD = egressProgInfo.Program.ProgFD
		mapToUpdate := egressProgInfo.Maps[utils.TC_CLUSTER_POLICY_EGRESS_MAP]

		log().Infof("Pod has an Egress hook attached. Update the corresponding map progFD: %d, mapName: %s", egressProgFD, utils.TC_CLUSTER_POLICY_EGRESS_MAP)

		inMemVal, exists := l.clusterPolicyEgressInMemoryMap.Load(podIdentifier)
		if !exists {
			log().Infof("didn't find cluster policy egress in-mem map for %v", podIdentifier)
			inMemMap, err := newInMemoryBpfMap(&mapToUpdate)
			if err != nil {
				egressErr = fmt.Errorf("cluster policy egress in-mem map hydrate: %w", err)
			} else {
				l.clusterPolicyEgressInMemoryMap.Store(podIdentifier, inMemMap)
				log().Infof("cluster policy egress map for %v loaded successfully", podIdentifier)
				inMemVal = inMemMap
			}
		}

		if egressErr == nil {
			inMemMap, typeOk := inMemVal.(inMemoryBPFMap)
			if !typeOk {
				egressErr = fmt.Errorf("cluster policy egress in-mem map: unexpected type %T", inMemVal)
			} else {
				writeErr := l.updateClusterPolicyEbpfMap(egressFirewallRules, inMemMap)
				duration := msSince(start)
				sdkAPILatency.WithLabelValues("updateClusterPolicyEbpfMap-egress", fmt.Sprint(writeErr != nil)).Observe(duration)
				if writeErr != nil {
					egressErr = fmt.Errorf("cluster policy egress map write: %w", writeErr)
				}
			}
		}
		if egressErr != nil {
			log().Errorf("Cluster Policy Egress Map update failed: %v", egressErr)
			sdkAPIErr.WithLabelValues("updateClusterPolicyEbpfMap-egress").Inc()
		}
	}
	return errors.Join(ingressErr, egressErr)
}

// CreatePodStateEbpfEntryIfNotExists seeds the initial pod-state map entry for
// podIdentifier under both the ingress and egress hooks. Used at probe-attach
// time to put the pod into a defined default state (DEFAULT_ALLOW or
// DEFAULT_DENY) before any policy rules are programmed.
func (l *bpfClient) CreatePodStateEbpfEntryIfNotExists(podIdentifier string, key int, state int) error {
	unlock := l.lockPodIdentifier(podIdentifier)
	defer unlock()

	keyval := uint32(key)
	value, ok := l.policyEndpointeBPFContext.Load(podIdentifier)
	if !ok {
		sdkAPIErr.WithLabelValues("createPodStateEntry-no-context").Inc()
		return fmt.Errorf("no bpf context registered for pod %s", podIdentifier)
	}
	peBPFContext, ok := value.(BPFContext)
	if !ok {
		sdkAPIErr.WithLabelValues("createPodStateEntry-bad-context-type").Inc()
		return fmt.Errorf("unexpected bpf context type %T for pod %s", value, podIdentifier)
	}
	ingressProgInfo := peBPFContext.ingressPgmInfo
	egressProgInfo := peBPFContext.egressPgmInfo
	if err := validateBPFContext(peBPFContext, podIdentifier, true, true); err != nil {
		sdkAPIErr.WithLabelValues("createPodStateEntry-invalid-context").Inc()
		return err
	}
	podStateValue := pod_state{state: uint8(state)}
	var ingressErr, egressErr error
	// CreateMapEntry uses BPF_NOEXIST and the SDK swallows EEXIST as nil,
	// so repeated calls are no-ops and this function stays idempotent.
	if ingressProgInfo.Program.ProgFD > 0 {
		mapToUpdate, found := ingressProgInfo.Maps[utils.TC_INGRESS_POD_STATE_MAP]
		if !found || mapToUpdate.MapFD == 0 {
			sdkAPIErr.WithLabelValues("createPodStateEntry-ingress-no-map").Inc()
			ingressErr = fmt.Errorf("map %s absent from bpf context for pod %s", utils.TC_INGRESS_POD_STATE_MAP, podIdentifier)
			log().Errorf("Ingress Pod State entry create failed: %v", ingressErr)
		} else if err := createBPFMapEntry(mapToUpdate, uintptr(unsafe.Pointer(&keyval)), uintptr(unsafe.Pointer(&podStateValue))); err != nil {
			log().Errorf("Ingress Pod State entry create failed: %v", err)
			sdkAPIErr.WithLabelValues("createPodStateEntry-ingress").Inc()
			ingressErr = fmt.Errorf("ingress pod state entry create: %w", err)
		}
	}
	if egressProgInfo.Program.ProgFD > 0 {
		mapToUpdate, found := egressProgInfo.Maps[utils.TC_EGRESS_POD_STATE_MAP]
		if !found || mapToUpdate.MapFD == 0 {
			sdkAPIErr.WithLabelValues("createPodStateEntry-egress-no-map").Inc()
			egressErr = fmt.Errorf("map %s absent from bpf context for pod %s", utils.TC_EGRESS_POD_STATE_MAP, podIdentifier)
			log().Errorf("Egress Pod State entry create failed: %v", egressErr)
		} else if err := createBPFMapEntry(mapToUpdate, uintptr(unsafe.Pointer(&keyval)), uintptr(unsafe.Pointer(&podStateValue))); err != nil {
			log().Errorf("Egress Pod State entry create failed: %v", err)
			sdkAPIErr.WithLabelValues("createPodStateEntry-egress").Inc()
			egressErr = fmt.Errorf("egress pod state entry create: %w", err)
		}
	}

	return errors.Join(ingressErr, egressErr)
}

// UpdatePodStateEbpfMaps writes the pod-state value (DEFAULT_ALLOW,
// DEFAULT_DENY, or POLICIES_APPLIED) for podIdentifier into the
// TC_INGRESS_POD_STATE_MAP and/or TC_EGRESS_POD_STATE_MAP, gated by the
// updateIngress and updateEgress flags. Ingress and egress are attempted
// independently and any errors are returned joined.
func (l *bpfClient) UpdatePodStateEbpfMaps(podIdentifier string, key int, state int, updateIngress bool, updateEgress bool) error {
	unlock := l.lockPodIdentifier(podIdentifier)
	defer unlock()
	return l.updatePodStateEbpfMaps(podIdentifier, key, state, updateIngress, updateEgress)
}

func (l *bpfClient) updatePodStateEbpfMaps(podIdentifier string, key int, state int, updateIngress bool, updateEgress bool) error {
	var ingressProgFD, egressProgFD int
	var ingressErr, egressErr error
	keyval := uint32(key)
	value, ok := l.policyEndpointeBPFContext.Load(podIdentifier)
	if !ok {
		sdkAPIErr.WithLabelValues("updateEbpfMap-podstate-no-context").Inc()
		return fmt.Errorf("no bpf context registered for pod %s", podIdentifier)
	}
	peBPFContext, ok := value.(BPFContext)
	if !ok {
		sdkAPIErr.WithLabelValues("updateEbpfMap-podstate-bad-context-type").Inc()
		return fmt.Errorf("unexpected bpf context type %T for pod %s", value, podIdentifier)
	}
	ingressProgInfo := peBPFContext.ingressPgmInfo
	egressProgInfo := peBPFContext.egressPgmInfo
	if err := validateBPFContext(peBPFContext, podIdentifier, updateIngress, updateEgress); err != nil {
		sdkAPIErr.WithLabelValues("updateEbpfMap-podstate-invalid-context").Inc()
		return err
	}
	podStateValue := pod_state{state: uint8(state)}

	if updateIngress && ingressProgInfo.Program.ProgFD > 0 {
		ingressProgFD = ingressProgInfo.Program.ProgFD
		mapToUpdate, found := ingressProgInfo.Maps[utils.TC_INGRESS_POD_STATE_MAP]
		if !found || mapToUpdate.MapFD == 0 {
			sdkAPIErr.WithLabelValues("updateEbpfMap-ingress-podstate-no-map").Inc()
			ingressErr = fmt.Errorf("map %s absent from bpf context for pod %s", utils.TC_INGRESS_POD_STATE_MAP, podIdentifier)
			log().Errorf("Ingress Pod State Map update failed: %v", ingressErr)
		} else {
			log().Infof("Pod has an Ingress hook attached. Update the corresponding map progFD: %d, mapName: %s, key: %d, value: %d", ingressProgFD, utils.TC_INGRESS_POD_STATE_MAP, keyval, podStateValue.state)
			start := time.Now()
			ingressErr = updateBPFMapEntry(mapToUpdate, uintptr(unsafe.Pointer(&keyval)), uintptr(unsafe.Pointer(&podStateValue)), 0)
			sdkAPILatency.WithLabelValues("updateEbpfMap-ingress-podstate", fmt.Sprint(ingressErr != nil)).Observe(msSince(start))
			if ingressErr != nil {
				log().Errorf("Ingress Pod State Map update failed: %v", ingressErr)
				sdkAPIErr.WithLabelValues("updateEbpfMap-ingress-podstate").Inc()
				ingressErr = fmt.Errorf("ingress pod state map write: %w", ingressErr)
			}
		}
	}
	if updateEgress && egressProgInfo.Program.ProgFD > 0 {
		egressProgFD = egressProgInfo.Program.ProgFD
		mapToUpdate, found := egressProgInfo.Maps[utils.TC_EGRESS_POD_STATE_MAP]
		if !found || mapToUpdate.MapFD == 0 {
			sdkAPIErr.WithLabelValues("updateEbpfMap-egress-podstate-no-map").Inc()
			egressErr = fmt.Errorf("map %s absent from bpf context for pod %s", utils.TC_EGRESS_POD_STATE_MAP, podIdentifier)
			log().Errorf("Egress Pod State Map update failed: %v", egressErr)
		} else {
			log().Infof("Pod has an Egress hook attached. Update the corresponding map progFD: %d, mapName: %s, key: %d, value: %d", egressProgFD, utils.TC_EGRESS_POD_STATE_MAP, keyval, podStateValue.state)
			start := time.Now()
			egressErr = updateBPFMapEntry(mapToUpdate, uintptr(unsafe.Pointer(&keyval)), uintptr(unsafe.Pointer(&podStateValue)), 0)
			sdkAPILatency.WithLabelValues("updateEbpfMap-egress-podstate", fmt.Sprint(egressErr != nil)).Observe(msSince(start))
			if egressErr != nil {
				log().Errorf("Egress Pod State Map update failed: %v", egressErr)
				sdkAPIErr.WithLabelValues("updateEbpfMap-egress-podstate").Inc()
				egressErr = fmt.Errorf("egress pod state map write: %w", egressErr)
			}
		}
	}

	return errors.Join(ingressErr, egressErr)
}

func (l *bpfClient) isEBPFProbeAttached(podName string, podNamespace string) (bool, bool) {
	ingress, egress := false, false
	if _, ok := l.ingressPodToProgMap.Load(utils.GetPodNamespacedName(podName, podNamespace)); ok {
		log().Infof("Pod already has Ingress Probe attached - Name: %s, Namespace: %s", podName, podNamespace)
		ingress = true
	}
	if _, ok := l.egressPodToProgMap.Load(utils.GetPodNamespacedName(podName, podNamespace)); ok {
		log().Infof("Pod already has Egress Probe attached - Name: %s, Namespace: %s", podName, podNamespace)
		egress = true
	}
	return ingress, egress
}

func (l *bpfClient) IsFirstPodInPodIdentifier(podIdentifier string) bool {
	firstPodInPodIdentifier := false
	if value, ok := l.policyEndpointeBPFContext.Load(podIdentifier); !ok {
		log().Info("No map instance found")
		firstPodInPodIdentifier = true
	} else {
		peBPFContext := value.(BPFContext)
		ingressProgInfo := peBPFContext.ingressPgmInfo
		egressProgInfo := peBPFContext.egressPgmInfo
		// If we don't find ingress or egress program info we should load missing bpf prog
		// and also update maps for the new bpf program added
		if ingressProgInfo.Program.ProgFD <= 0 || egressProgInfo.Program.ProgFD <= 0 {
			log().Info("No ingress or egress program found")
			firstPodInPodIdentifier = true
		}
	}
	return firstPodInPodIdentifier
}

func (l *bpfClient) isProgFdShared(targetPodName string, targetPodNamespace string) (bool, error) {
	targetpodNamespacedName := utils.GetPodNamespacedName(targetPodName, targetPodNamespace)
	// check ingress caches
	if targetProgFD, ok := l.ingressPodToProgMap.Load(targetpodNamespacedName); ok {
		if currentList, ok := l.ingressProgToPodsMap.Load(targetProgFD); ok {
			podsList, ok := currentList.(map[string]struct{})
			if ok {
				if len(podsList) > 1 {
					log().Debugf("Found shared ingress progFD for target: %s, progFD: %d", targetPodName, targetProgFD)
					return true, nil
				}
				return false, nil // Not shared (only one pod)
			}
		}
	}

	// Check Egress Maps if not found in Ingress
	if targetProgFD, ok := l.egressPodToProgMap.Load(targetpodNamespacedName); ok {
		if currentList, ok := l.egressProgToPodsMap.Load(targetProgFD); ok {
			podsList, ok := currentList.(map[string]struct{})
			if ok {
				if len(podsList) > 1 {
					log().Debugf("Found shared egress progFD for target: %s, progFD: %d", targetPodName, targetProgFD)
					return true, nil
				}
				return false, nil // Not shared (only one pod)
			}
		}
	}

	// If not found in both maps, return an error
	log().Debugf("Pod not found in either IngressPodToProgMap or EgressPodToProgMap: %s", targetpodNamespacedName)
	return false, fmt.Errorf("pod not found in either IngressPodToProgMap or EgressPodToProgMap: %s", targetpodNamespacedName)
}

func (l *bpfClient) updateEbpfMap(firewallRules []fwrp.EbpfFirewallRules, inMemMap inMemoryBPFMap) error {
	start := time.Now()
	duration := msSince(start)
	mapEntries, err := l.fwRuleProcessor.ComputeMapEntriesFromEndpointRules(firewallRules)
	if err != nil {
		log().Errorf("Trie entry creation/validation failed %v", err)
		return err
	}

	err = inMemMap.BulkRefresh(mapEntries)
	sdkAPILatency.WithLabelValues("BulkRefreshMapEntries", fmt.Sprint(err != nil)).Observe(duration)
	if err != nil {
		log().Errorf("BPF map update failed %v", err)
		sdkAPIErr.WithLabelValues("BulkRefreshMapEntries").Inc()
		return err
	}
	return nil
}

func (l *bpfClient) updateClusterPolicyEbpfMap(firewallRules []fwrp.EbpfFirewallRules, inMemMap inMemoryBPFMap) error {
	start := time.Now()
	duration := msSince(start)
	mapEntries, err := l.fwRuleProcessor.ComputeClusterPolicyMapEntriesFromEndpointRules(firewallRules)
	if err != nil {
		log().Errorf("Trie entry creation/validation failed %v", err)
		return err
	}

	err = inMemMap.BulkRefresh(mapEntries)
	sdkAPILatency.WithLabelValues("BulkRefreshMapEntries", fmt.Sprint(err != nil)).Observe(duration)
	if err != nil {
		log().Errorf("BPF map update failed %v", err)
		sdkAPIErr.WithLabelValues("BulkRefreshMapEntries").Inc()
		return err
	}
	return nil
}

func (l *bpfClient) deletePodFromIngressProgPodCaches(podName string, podNamespace string) {
	podNamespacedName := utils.GetPodNamespacedName(podName, podNamespace)
	if progFD, ok := l.ingressPodToProgMap.Load(podNamespacedName); ok {
		l.ingressPodToProgMap.Delete(podNamespacedName)
		if currentSet, ok := l.ingressProgToPodsMap.Load(progFD); ok {
			set := currentSet.(map[string]struct{})
			delete(set, podNamespacedName)
			if len(set) == 0 {
				l.ingressProgToPodsMap.Delete(progFD)
			}
		}
	}
}

func (l *bpfClient) deletePodFromEgressProgPodCaches(podName string, podNamespace string) {
	podNamespacedName := utils.GetPodNamespacedName(podName, podNamespace)
	if progFD, ok := l.egressPodToProgMap.Load(podNamespacedName); ok {
		l.egressPodToProgMap.Delete(podNamespacedName)
		if currentSet, ok := l.egressProgToPodsMap.Load(progFD); ok {
			set := currentSet.(map[string]struct{})
			delete(set, podNamespacedName)
			if len(set) == 0 {
				l.egressProgToPodsMap.Delete(progFD)
			}
		}
	}
}

// startDeletedPodsCleanupRoutine cleans up entries from the deletedPods map that are older than deletedPodsMinAge.
func (l *bpfClient) startDeletedPodsCleanupRoutine(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(deletedPodsMinAge / 2)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				l.cleanupDeletedPodsIfNeeded()
			}
		}
	}()
}

func (l *bpfClient) cleanupDeletedPodsIfNeeded() {
	now := time.Now()
	cleaned := 0
	l.deletedPods.Range(func(key, value any) bool {
		ts, ok := value.(time.Time)
		if !ok {
			log().Warnf("unexpected type for timestamp, got %T, expected time.Time", value)
			l.deletedPods.Delete(key)
			cleaned++
			return true
		}
		if now.Sub(ts) > deletedPodsMinAge {
			l.deletedPods.Delete(key)
			cleaned++
		}
		return true
	})
	log().Debugf("deletedPods cleanup complete, removed %d entries", cleaned)
}

package ebpf

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"sync"
	"time"
	"unsafe"

	corev1 "k8s.io/api/core/v1"

	"github.com/aws/amazon-vpc-cni-k8s/pkg/ipamd/datastore"
	goelf "github.com/aws/aws-ebpf-sdk-go/pkg/elfparser"
	goebpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	"github.com/aws/aws-ebpf-sdk-go/pkg/tc"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf/conntrack"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf/events"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/aws/aws-network-policy-agent/pkg/utils/cp"
	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	TC_INGRESS_BINARY                          = "tc.v4ingress.bpf.o"
	TC_EGRESS_BINARY                           = "tc.v4egress.bpf.o"
	TC_V6_INGRESS_BINARY                       = "tc.v6ingress.bpf.o"
	TC_V6_EGRESS_BINARY                        = "tc.v6egress.bpf.o"
	EVENTS_BINARY                              = "v4events.bpf.o"
	EVENTS_V6_BINARY                           = "v6events.bpf.o"
	TC_INGRESS_PROG                            = "handle_ingress"
	TC_EGRESS_PROG                             = "handle_egress"
	TC_INGRESS_MAP                             = "ingress_map"
	TC_EGRESS_MAP                              = "egress_map"
	TC_INGRESS_POD_STATE_MAP                   = "ingress_pod_state_map"
	TC_EGRESS_POD_STATE_MAP                    = "egress_pod_state_map"
	AWS_CONNTRACK_MAP                          = "aws_conntrack_map"
	AWS_EVENTS_MAP                             = "policy_events"
	EKS_CLI_BINARY                             = "aws-eks-na-cli"
	EKS_V6_CLI_BINARY                          = "aws-eks-na-cli-v6"
	hostBinaryPath                             = "/host/opt/cni/bin/"
	IPv4_HOST_MASK                             = "/32"
	IPv6_HOST_MASK                             = "/128"
	CONNTRACK_MAP_PIN_PATH                     = "/sys/fs/bpf/globals/aws/maps/global_aws_conntrack_map"
	POLICY_EVENTS_MAP_PIN_PATH                 = "/sys/fs/bpf/globals/aws/maps/global_policy_events"
	CATCH_ALL_PROTOCOL         corev1.Protocol = "ANY_IP_PROTOCOL"
	POD_VETH_PREFIX                            = "eni"
	POLICIES_APPLIED                           = 0
	DEFAULT_ALLOW                              = 1
	DEFAULT_DENY                               = 2
	POD_STATE_MAP_KEY                          = 0
	BRANCH_ENI_VETH_PREFIX                     = "vlan"
	INTERFACE_COUNT_UNKNOWN                    = -1 // Used when caller doesn't know interface count
	INTERFACE_COUNT_DEFAULT                    = 1  // Default single interface
	IPAM_JSON_PATH                             = "/var/run/aws-node/ipam.json"
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
	AttacheBPFProbes(pod types.NamespacedName, policyEndpoint string, numInterfaces int) error
	UpdateEbpfMaps(podIdentifier string, ingressFirewallRules []fwrp.EbpfFirewallRules, egressFirewallRules []fwrp.EbpfFirewallRules) error
	UpdatePodStateEbpfMaps(podIdentifier string, state int, updateIngress bool, updateEgress bool) error
	IsEBPFProbeAttached(podName string, podNamespace string) (bool, bool)
	IsFirstPodInPodIdentifier(podIdentifier string) bool
	GetIngressPodToProgMap() *sync.Map
	GetEgressPodToProgMap() *sync.Map
	GetIngressProgToPodsMap() *sync.Map
	GetEgressProgToPodsMap() *sync.Map
	DeletePodFromIngressProgPodCaches(podName string, podNamespace string)
	DeletePodFromEgressProgPodCaches(podName string, podNamespace string)
	ReAttachEbpfProbes() error
	DeleteBPFProgramAndMaps(podIdentifier string) error
	GetDeletePodIdentifierLockMap() *sync.Map
	GetNetworkPolicyMode() string
}

type BPFContext struct {
	ingressPgmInfo   goelf.BpfData
	egressPgmInfo    goelf.BpfData
	conntrackMapInfo goebpfmaps.BpfMap
}

func NewBpfClient(nodeIP string, enablePolicyEventLogs, enableCloudWatchLogs bool,
	enableIPv6 bool, conntrackTTL int, conntrackTableSize int, networkPolicyMode string, isMultiNICEnabled bool) (*bpfClient, error) {
	var conntrackMap goebpfmaps.BpfMap

	ebpfClient := &bpfClient{
		// Maps PolicyEndpoint resource to it's eBPF context
		policyEndpointeBPFContext: new(sync.Map),
		IngressPodToProgMap:       new(sync.Map),
		EgressPodToProgMap:        new(sync.Map),
		GlobalMaps:                new(sync.Map),
		IngressProgToPodsMap:      new(sync.Map),
		EgressProgToPodsMap:       new(sync.Map),
		AttachProbesToPodLock:     new(sync.Map),
		DeletePodIdentifierLock:   new(sync.Map),
		podNameToInterfaceCount:   new(sync.Map),
		networkPolicyMode:         networkPolicyMode,
		isMultiNICEnabled:         isMultiNICEnabled,
		ingressInMemoryMap:        new(sync.Map),
		egressInMemoryMap:         new(sync.Map),
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

	ebpfClient.bpfSDKClient = goelf.New()
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
		ebpfClient.GlobalMaps, ingressUpdateRequired, egressUpdateRequired, eventsUpdateRequired)
	if err != nil {
		//Log the error and move on
		log().Errorf("Failed to recover the BPF state error: %v", err)
		sdkAPIErr.WithLabelValues("RecoverBPFState").Inc()
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
		recoveredConntrackMap, ok := ebpfClient.GlobalMaps.Load(CONNTRACK_MAP_PIN_PATH)
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
		err = events.ConfigurePolicyEventsLogging(enableCloudWatchLogs, eventBufferFD, enableIPv6)
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

	log().Info("BPF Client initialization done")
	return ebpfClient, nil
}

var _ BpfClient = (*bpfClient)(nil)

type bpfClient struct {
	// Stores eBPF Ingress and Egress context per policyEndpoint resource
	policyEndpointeBPFContext *sync.Map
	// Stores the Ingress eBPF Prog FD per pod
	IngressPodToProgMap *sync.Map
	// Stores the Egress eBPF Prog FD per pod
	EgressPodToProgMap *sync.Map
	// Stores info on the global maps the agent creates
	GlobalMaps *sync.Map
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
	IngressProgToPodsMap *sync.Map
	// Stores the Egress eBPF Prog FD to pods mapping
	EgressProgToPodsMap *sync.Map
	// Stores podIdentifier to attachprobes lock mapping
	AttachProbesToPodLock *sync.Map
	// This is only updated and used for probe binary updates during initialization
	interfaceNametoIngressPinPath map[string]string
	// This is only updated and used for probe binary updates during initialization
	interfaceNametoEgressPinPath map[string]string
	// Stores podIdentifier to deletepod lock mapping
	DeletePodIdentifierLock *sync.Map
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
			//Log it and move on. We will overwrite and recreate the maps/programs
			log().Errorf("BPF State Recovery failed error: %v", err)
			sdkAPIErr.WithLabelValues("RecoverAllBpfProgramAndMaps").Inc()
		}

		log().Infof("Number of probes/maps recovered - count: %d", len(bpfState))
		for pinPath, bpfEntry := range bpfState {
			podIdentifier, direction := utils.GetPodIdentifierFromBPFPinPath(pinPath)
			log().Infof("Recovered program Identifier: Pin Path: %s PodIdentifier: %s direction: %s", pinPath, podIdentifier, direction)
			var peBPFContext BPFContext
			value, ok := policyEndpointeBPFContext.Load(podIdentifier)
			if ok {
				peBPFContext = value.(BPFContext)
			}
			if direction == "ingress" && !updateIngressProbe {
				peBPFContext.ingressPgmInfo = bpfEntry
				val, found := bpfEntry.Maps[TC_INGRESS_MAP]
				if found {
					log().Infof("found ingress ebpf map for %v, map %+v", podIdentifier, val)

					_, ok := l.ingressInMemoryMap.Load(podIdentifier)
					if !ok {
						inMemMap, err := NewInMemoryBpfMap(&val)
						if err != nil {
							log().Errorf("got err for ingress in-mem map for %v, err %v", podIdentifier, err)
						} else {
							l.ingressInMemoryMap.Store(podIdentifier, inMemMap)
							log().Infof("ingress map for %v loaded successfully", podIdentifier)
						}
					}
				}
			} else if direction == "egress" && !updateEgressProbe {
				peBPFContext.egressPgmInfo = bpfEntry
				val, found := bpfEntry.Maps[TC_EGRESS_MAP]
				if found {
					log().Infof("found egress ebpf map for %v, map %+v", podIdentifier, val)

					_, ok := l.egressInMemoryMap.Load(podIdentifier)
					if !ok {
						inMemMap, err := NewInMemoryBpfMap(&val)
						if err != nil {
							log().Errorf("got err for egress in-mem map for %v, err %v", podIdentifier, err)
						} else {
							l.egressInMemoryMap.Store(podIdentifier, inMemMap)
							log().Infof("egress map for %v loaded successfully", podIdentifier)
						}
					}
				}
			}
			policyEndpointeBPFContext.Store(podIdentifier, peBPFContext)
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
		log().Infof("ReattachEbpfProbes attaching ingress for %s interface %s", podIdentifier, interfaceName)
		_, err := l.attachIngressBPFProbe(interfaceName, podIdentifier)
		if err != nil {
			log().Errorf("Failed to Attach Ingress TC probe for interface: %s podIdentifier: %s error: %v", interfaceName, podIdentifier, err)
			sdkAPIErr.WithLabelValues("attachIngressBPFProbe").Inc()
		}
		log().Infof("Updating ingress_pod_state map for podIdentifier: %s, networkPolicyMode: %s", podIdentifier, l.networkPolicyMode)
		err = l.UpdatePodStateEbpfMaps(podIdentifier, state, true, false)
		if err != nil {
			log().Errorf("Map update(s) failed for podIdentifier %s error: %v", podIdentifier, err)
		}
	}

	for interfaceName, pinPath := range l.interfaceNametoEgressPinPath {
		podIdentifier, _ := utils.GetPodIdentifierFromBPFPinPath(pinPath)
		log().Infof("ReattachEbpfProbes attaching egress for %s interface %s", podIdentifier, interfaceName)
		_, err := l.attachEgressBPFProbe(interfaceName, podIdentifier)
		if err != nil {
			log().Errorf("Failed to Attach Egress TC probe for interface: %s podIdentifier %s error: %v", interfaceName, podIdentifier, err)
			sdkAPIErr.WithLabelValues("attachEgressBPFProbe").Inc()
		}

		log().Infof("Updating egress_pod_state map for podIdentifier: %s, networkPolicyMode: %s", podIdentifier, l.networkPolicyMode)
		err = l.UpdatePodStateEbpfMaps(podIdentifier, state, false, true)
		if err != nil {
			log().Errorf("Map update(s) failed for podIdentifier %s error: %v", podIdentifier, err)
		}
	}
	return nil
}

func (l *bpfClient) GetIngressPodToProgMap() *sync.Map {
	return l.IngressPodToProgMap
}

func (l *bpfClient) GetEgressPodToProgMap() *sync.Map {
	return l.EgressPodToProgMap
}

func (l *bpfClient) GetIngressProgToPodsMap() *sync.Map {
	return l.IngressProgToPodsMap
}

func (l *bpfClient) GetEgressProgToPodsMap() *sync.Map {
	return l.EgressProgToPodsMap
}

func (l *bpfClient) GetDeletePodIdentifierLockMap() *sync.Map {
	return l.DeletePodIdentifierLock
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

	// Two go routines can try to attach the probes at the same time
	// Locking will help updating all the datastructures correctly
	value, _ := l.AttachProbesToPodLock.LoadOrStore(podIdentifier, &sync.Mutex{})
	attachProbesLock := value.(*sync.Mutex)
	attachProbesLock.Lock()
	log().Debugf("Got the attachProbesLock for Pod: %s, Namespace: %s, PodIdentifier: %s", pod.Name, pod.Namespace, podIdentifier)
	defer attachProbesLock.Unlock()

	// Check if an eBPF probe is already attached on both ingress and egress direction(s) for this pod.
	// If yes, then skip probe attach flow for this pod.
	isIngressProbeAttached, isEgressProbeAttached := l.IsEBPFProbeAttached(pod.Name, pod.Namespace)
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
		l.IngressPodToProgMap.Store(podNamespacedName, ingressProgFD)
		currentPodSet, _ := l.IngressProgToPodsMap.LoadOrStore(ingressProgFD, make(map[string]struct{}))
		currentPodSet.(map[string]struct{})[podNamespacedName] = struct{}{}
	}

	if !isEgressProbeAttached {
		l.EgressPodToProgMap.Store(podNamespacedName, egressProgFD)
		currentPodSet, _ := l.EgressProgToPodsMap.LoadOrStore(egressProgFD, make(map[string]struct{}))
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

	if peBPFContext.ingressPgmInfo.Program.ProgFD != 0 {
		log().Info("Found an existing instance, let's derive the ingress context..")
		ingressEbpfProgEntry := peBPFContext.ingressPgmInfo
		progFD = ingressEbpfProgEntry.Program.ProgFD
	} else {
		ingressProgInfo, progFD, err = l.loadBPFProgram(l.ingressBinary, "ingress", podIdentifier)
		pinPath := utils.GetBPFPinPathFromPodIdentifier(podIdentifier, "ingress")
		peBPFContext.ingressPgmInfo = ingressProgInfo[pinPath]
		l.policyEndpointeBPFContext.Store(podIdentifier, peBPFContext)
	}

	log().Infof("Attempting to do an Ingress Attach with progFD: %d", progFD)
	err = l.bpfTCClient.TCEgressAttach(hostVethName, progFD, TC_INGRESS_PROG)
	if err != nil && !utils.IsFileExistsError(err.Error()) {
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

	if peBPFContext.egressPgmInfo.Program.ProgFD != 0 {
		log().Info("Found an existing instance, let's derive the egress context..")
		egressEbpfProgEntry := peBPFContext.egressPgmInfo
		progFD = egressEbpfProgEntry.Program.ProgFD
	} else {
		egressProgInfo, progFD, err = l.loadBPFProgram(l.egressBinary, "egress", podIdentifier)
		pinPath := utils.GetBPFPinPathFromPodIdentifier(podIdentifier, "egress")
		peBPFContext.egressPgmInfo = egressProgInfo[pinPath]
		l.policyEndpointeBPFContext.Store(podIdentifier, peBPFContext)
	}

	log().Infof("Attempting to do an Egress Attach with progFD: %d", progFD)
	err = l.bpfTCClient.TCIngressAttach(hostVethName, progFD, TC_EGRESS_PROG)
	if err != nil && !utils.IsFileExistsError(err.Error()) {
		log().Errorf("Egress Attach failed %v", err)
		return 0, err
	}

	return progFD, nil
}

func (l *bpfClient) DeleteBPFProgramAndMaps(podIdentifier string) error {
	start := time.Now()
	err := l.deleteBPFProgramAndMaps(podIdentifier, "ingress")
	duration := msSince(start)
	sdkAPILatency.WithLabelValues("deleteBPFProgramAndMaps", fmt.Sprint(err != nil)).Observe(duration)
	if err != nil {
		log().Errorf("Error while deleting Ingress BPF Probe for podIdentifier: %s error: %v", podIdentifier, err)
		sdkAPIErr.WithLabelValues("deleteBPFProgramAndMaps").Inc()
	}

	start = time.Now()
	err = l.deleteBPFProgramAndMaps(podIdentifier, "egress")
	duration = msSince(start)
	sdkAPILatency.WithLabelValues("deleteBPFProgramAndMaps", fmt.Sprint(err != nil)).Observe(duration)
	if err != nil {
		log().Errorf("Error while deleting Egress BPF Probe for podIdentifier: %s error: %v", podIdentifier, err)
		sdkAPIErr.WithLabelValues("deleteBPFProgramAndMaps").Inc()
	}

	l.ingressInMemoryMap.Delete(podIdentifier)
	l.egressInMemoryMap.Delete(podIdentifier)
	l.policyEndpointeBPFContext.Delete(podIdentifier)
	if _, ok := l.AttachProbesToPodLock.Load(podIdentifier); ok {
		l.AttachProbesToPodLock.Delete(podIdentifier)
	}
	return nil
}

func (l *bpfClient) deleteBPFProgramAndMaps(podIdentifier string, direction string) error {
	var err error
	var peBPFContext BPFContext
	value, ok := l.policyEndpointeBPFContext.Load(podIdentifier)
	if ok {
		peBPFContext = value.(BPFContext)
	}

	pgmPinPath := utils.GetBPFPinPathFromPodIdentifier(podIdentifier, direction)
	mapPinpath := utils.GetBPFMapPinPathFromPodIdentifier(podIdentifier, direction)
	podStateMapPinPath := utils.GetPodStateBPFMapPinPathFromPodIdentifier(podIdentifier, direction)

	log().Infof("Deleting: Program: %s Map: %s Map: %s", pgmPinPath, mapPinpath, podStateMapPinPath)

	pgmInfo := peBPFContext.ingressPgmInfo
	mapToDelete := pgmInfo.Maps[TC_INGRESS_MAP]
	podStateMapToDelete := pgmInfo.Maps[TC_INGRESS_POD_STATE_MAP]
	if direction == "egress" {
		pgmInfo = peBPFContext.egressPgmInfo
		mapToDelete = pgmInfo.Maps[TC_EGRESS_MAP]
		podStateMapToDelete = pgmInfo.Maps[TC_EGRESS_POD_STATE_MAP]
	}

	if pgmInfo.Program.ProgFD != 0 {
		log().Infof("Found the Program and Map to delete - Program: %s Map: %s Map: %s", pgmPinPath, mapPinpath, podStateMapPinPath)
		err = pgmInfo.Program.UnPinProg(pgmPinPath)
		if err != nil {
			log().Errorf("Failed to delete the Program: %v", err)
		}
		err = mapToDelete.UnPinMap(mapPinpath)
		if err != nil {
			log().Errorf("Failed to delete the Map: %v", err)
		}
		err = podStateMapToDelete.UnPinMap(podStateMapPinPath)
		if err != nil {
			log().Errorf("Failed to delete PodState Map: %v", err)
		}
	}
	return nil
}

func (l *bpfClient) loadBPFProgram(fileName string, direction string,
	podIdentifier string) (map[string]goelf.BpfData, int, error) {

	start := time.Now()
	log().Info("Load the eBPF program")
	// Load a new instance of the program
	progInfo, _, err := l.bpfSDKClient.LoadBpfFile(fileName, podIdentifier)
	duration := msSince(start)
	sdkAPILatency.WithLabelValues("LoadBpfFile", fmt.Sprint(err != nil)).Observe(duration)
	if err != nil {
		sdkAPIErr.WithLabelValues("LoadBpfFile").Inc()
		log().Errorf("Load BPF failed err: %v", err)
		return nil, -1, err
	}

	pinPath := utils.GetBPFPinPathFromPodIdentifier(podIdentifier, direction)
	progFD := progInfo[pinPath].Program.ProgFD

	log().Infof("Prog Load Succeeded for %s, progFD: %d, pinpath: %s", direction, progFD, pinPath)

	return progInfo, progFD, nil
}

func (l *bpfClient) UpdateEbpfMaps(podIdentifier string, ingressFirewallRules []fwrp.EbpfFirewallRules,
	egressFirewallRules []fwrp.EbpfFirewallRules) error {

	start := time.Now()
	value, ok := l.policyEndpointeBPFContext.Load(podIdentifier)

	if ok {
		peBPFContext := value.(BPFContext)
		ingressProgInfo := peBPFContext.ingressPgmInfo
		egressProgInfo := peBPFContext.egressPgmInfo

		if ingressProgInfo.Program.ProgFD != 0 {
			ingressProgFD := ingressProgInfo.Program.ProgFD
			mapToUpdate := ingressProgInfo.Maps[TC_INGRESS_MAP]
			log().Infof("Pod has an Ingress hook attached. Update the corresponding map progFD: %d, mapName: %s", ingressProgFD, TC_INGRESS_MAP)

			inMemVal, exists := l.ingressInMemoryMap.Load(podIdentifier)
			if !exists {
				log().Infof("Ingress in-mem map not found for %v", podIdentifier)
				inMemMap, err := NewInMemoryBpfMap(&mapToUpdate)
				if err != nil {
					log().Errorf("got err for ingress in-mem map for %v, err %v", podIdentifier, err)
				} else {
					l.ingressInMemoryMap.Store(podIdentifier, inMemMap)
					log().Infof("ingress map for %v loaded successfully", podIdentifier)
					inMemVal = inMemMap
				}
			}

			err := l.updateEbpfMap(ingressFirewallRules, inMemVal.(*InMemoryBpfMap))
			duration := msSince(start)
			sdkAPILatency.WithLabelValues("updateEbpfMap-ingress", fmt.Sprint(err != nil)).Observe(duration)
			if err != nil {
				log().Errorf("Ingress Map update failed: %v", err)
				sdkAPIErr.WithLabelValues("updateEbpfMap-ingress").Inc()
			}
		}
		if egressProgInfo.Program.ProgFD != 0 {
			egressProgFD := egressProgInfo.Program.ProgFD
			mapToUpdate := egressProgInfo.Maps[TC_EGRESS_MAP]

			log().Infof("Pod has an Egress hook attached. Update the corresponding map progFD: %d, mapName: %s", egressProgFD, TC_EGRESS_MAP)

			inMemVal, exists := l.egressInMemoryMap.Load(podIdentifier)
			if !exists {
				log().Infof("didn't find egress in-mem map for %v", podIdentifier)
				inMemMap, err := NewInMemoryBpfMap(&mapToUpdate)
				if err != nil {
					log().Errorf("got err for egress in-mem map for %v, err %v", podIdentifier, err)
				} else {
					l.egressInMemoryMap.Store(podIdentifier, inMemMap)
					log().Infof("egress map for %v loaded successfully", podIdentifier)
					inMemVal = inMemMap
				}
			}

			err := l.updateEbpfMap(egressFirewallRules, inMemVal.(*InMemoryBpfMap))
			duration := msSince(start)
			sdkAPILatency.WithLabelValues("updateEbpfMap-egress", fmt.Sprint(err != nil)).Observe(duration)
			if err != nil {
				log().Errorf("Egress Map update failed: %v", err)
				sdkAPIErr.WithLabelValues("updateEbpfMap-egress").Inc()
			}
		}
		err := l.UpdatePodStateEbpfMaps(podIdentifier, POLICIES_APPLIED, true, true)
		if err != nil {
			log().Errorf("Pod State Map update failed: %v", err)
		}
	}
	return nil
}

func (l *bpfClient) UpdatePodStateEbpfMaps(podIdentifier string, state int, updateIngress bool, updateEgress bool) error {

	var ingressProgFD, egressProgFD int
	var mapToUpdate goebpfmaps.BpfMap
	start := time.Now()
	value, ok := l.policyEndpointeBPFContext.Load(podIdentifier)

	if ok {
		peBPFContext := value.(BPFContext)
		ingressProgInfo := peBPFContext.ingressPgmInfo
		egressProgInfo := peBPFContext.egressPgmInfo
		key := uint32(POD_STATE_MAP_KEY)        // pod_state_map key
		value := pod_state{state: uint8(state)} // pod_state_map value

		if updateIngress && ingressProgInfo.Program.ProgFD != 0 {
			ingressProgFD = ingressProgInfo.Program.ProgFD
			mapToUpdate = ingressProgInfo.Maps[TC_INGRESS_POD_STATE_MAP]
			log().Infof("Pod has an Ingress hook attached. Update the corresponding map progFD: %d, mapName: %s", ingressProgFD, TC_INGRESS_POD_STATE_MAP)
			err := mapToUpdate.CreateUpdateMapEntry(uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&value)), 0)
			duration := msSince(start)
			sdkAPILatency.WithLabelValues("updateEbpfMap-ingress-podstate", fmt.Sprint(err != nil)).Observe(duration)
			if err != nil {
				log().Errorf("Ingress Pod State Map update failed: %v", err)
				sdkAPIErr.WithLabelValues("updateEbpfMap-ingress-podstate").Inc()
			}
		}
		if updateEgress && egressProgInfo.Program.ProgFD != 0 {
			egressProgFD = egressProgInfo.Program.ProgFD
			mapToUpdate = egressProgInfo.Maps[TC_EGRESS_POD_STATE_MAP]

			log().Infof("Pod has an Egress hook attached. Update the corresponding map progFD: %d, mapName: %s", egressProgFD, TC_EGRESS_POD_STATE_MAP)
			err := mapToUpdate.CreateUpdateMapEntry(uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&value)), 0)
			duration := msSince(start)
			sdkAPILatency.WithLabelValues("updateEbpfMap-egress-podstate", fmt.Sprint(err != nil)).Observe(duration)
			if err != nil {
				log().Errorf("Egress Map update failed: %v", err)
				sdkAPIErr.WithLabelValues("updateEbpfMap-egress-podstate").Inc()
			}
		}
	}
	return nil
}

func (l *bpfClient) IsEBPFProbeAttached(podName string, podNamespace string) (bool, bool) {
	ingress, egress := false, false
	if _, ok := l.IngressPodToProgMap.Load(utils.GetPodNamespacedName(podName, podNamespace)); ok {
		log().Infof("Pod already has Ingress Probe attached - Name: %s, Namespace: %s", podName, podNamespace)
		ingress = true
	}
	if _, ok := l.EgressPodToProgMap.Load(utils.GetPodNamespacedName(podName, podNamespace)); ok {
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
		if ingressProgInfo.Program.ProgFD == 0 || egressProgInfo.Program.ProgFD == 0 {
			log().Info("No ingress or egress program found")
			firstPodInPodIdentifier = true
		}
	}
	return firstPodInPodIdentifier
}

func (l *bpfClient) updateEbpfMap(firewallRules []fwrp.EbpfFirewallRules, inMemMap *InMemoryBpfMap) error {
	start := time.Now()
	duration := msSince(start)
	mapEntries, err := l.fwRuleProcessor.ComputeMapEntriesFromEndpointRules(firewallRules)
	if err != nil {
		log().Errorf("Trie entry creation/validation failed %v", err)
		return err
	}

	log().Infof("ID of map to update: ID: %d", inMemMap.GetUnderlyingMap().MapID)
	err = inMemMap.BulkRefresh(mapEntries)
	sdkAPILatency.WithLabelValues("BulkRefreshMapEntries", fmt.Sprint(err != nil)).Observe(duration)
	if err != nil {
		log().Errorf("BPF map update failed %v", err)
		sdkAPIErr.WithLabelValues("BulkRefreshMapEntries").Inc()
		return err
	}
	return nil
}

func (l *bpfClient) DeletePodFromIngressProgPodCaches(podName string, podNamespace string) {
	podNamespacedName := utils.GetPodNamespacedName(podName, podNamespace)
	if progFD, ok := l.IngressPodToProgMap.Load(podNamespacedName); ok {
		l.IngressPodToProgMap.Delete(podNamespacedName)
		if currentSet, ok := l.IngressProgToPodsMap.Load(progFD); ok {
			set := currentSet.(map[string]struct{})
			delete(set, podNamespacedName)
			if len(set) == 0 {
				l.IngressProgToPodsMap.Delete(progFD)
			}
		}
	}
}

func (l *bpfClient) DeletePodFromEgressProgPodCaches(podName string, podNamespace string) {
	podNamespacedName := utils.GetPodNamespacedName(podName, podNamespace)
	if progFD, ok := l.EgressPodToProgMap.Load(podNamespacedName); ok {
		l.EgressPodToProgMap.Delete(podNamespacedName)
		if currentSet, ok := l.EgressProgToPodsMap.Load(progFD); ok {
			set := currentSet.(map[string]struct{})
			delete(set, podNamespacedName)
			if len(set) == 0 {
				l.EgressProgToPodsMap.Delete(progFD)
			}
		}
	}
}

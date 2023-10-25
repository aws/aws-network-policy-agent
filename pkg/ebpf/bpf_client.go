package ebpf

import (
	"fmt"
	"io/ioutil"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	corev1 "k8s.io/api/core/v1"

	goelf "github.com/aws/aws-ebpf-sdk-go/pkg/elfparser"
	goebpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	"github.com/aws/aws-ebpf-sdk-go/pkg/tc"
	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf/conntrack"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf/events"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/aws/aws-network-policy-agent/pkg/utils/cp"
	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	ctrl "sigs.k8s.io/controller-runtime"
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
)

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

func msSince(start time.Time) float64 {
	return float64(time.Since(start) / time.Millisecond)
}

func prometheusRegister() {
	if !prometheusRegistered {
		prometheus.MustRegister(sdkAPILatency)
		prometheus.MustRegister(sdkAPIErr)
		prometheusRegistered = true
	}
}

type BpfClient interface {
	AttacheBPFProbes(pod types.NamespacedName, policyEndpoint string, ingress bool, egress bool) error
	DetacheBPFProbes(pod types.NamespacedName, ingress bool, egress bool) error
	UpdateEbpfMaps(podIdentifier string, ingressFirewallRules []EbpfFirewallRules, egressFirewallRules []EbpfFirewallRules) error
	IsEBPFProbeAttached(podName string, podNamespace string) (bool, bool)
}

type EvProgram struct {
	wg sync.WaitGroup
}

type BPFContext struct {
	ingressPgmInfo   goelf.BpfData
	egressPgmInfo    goelf.BpfData
	conntrackMapInfo goebpfmaps.BpfMap
}

type EbpfFirewallRules struct {
	IPCidr v1alpha1.NetworkAddress
	Except []v1alpha1.NetworkAddress
	L4Info []v1alpha1.Port
}

func NewBpfClient(policyEndpointeBPFContext *sync.Map, nodeIP string, enablePolicyEventLogs, enableCloudWatchLogs bool,
	enableIPv6 bool, conntrackTTL time.Duration) (*bpfClient, error) {
	var conntrackMap goebpfmaps.BpfMap

	ebpfClient := &bpfClient{
		policyEndpointeBPFContext: policyEndpointeBPFContext,
		IngressProgPodMap:         new(sync.Map),
		EgressProgPodMap:          new(sync.Map),
		nodeIP:                    nodeIP,
		enableIPv6:                enableIPv6,
		GlobalMaps:                new(sync.Map),
	}
	ebpfClient.logger = ctrl.Log.WithName("ebpf-client")

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
	ebpfClient.bpfTCClient = tc.New(POD_VETH_PREFIX)

	//Set RLIMIT
	err = ebpfClient.bpfSDKClient.IncreaseRlimit()
	if err != nil {
		//No need to error out from here. We should be good to proceed.
		ebpfClient.logger.Info("Failed to increase RLIMIT on the node....but moving forward")
	}

	//Compare BPF binaries
	ingressUpdateRequired, egressUpdateRequired, eventsUpdateRequired, err := checkAndUpdateBPFBinaries(ebpfClient.bpfTCClient,
		bpfBinaries, hostBinaryPath)
	if err != nil {
		//Log the error and move on
		ebpfClient.logger.Error(err, "Probe validation/update failed but will continue to load")
	}
	ebpfClient.logger.Info("Probe validation Done")

	//Copy the latest binaries to /opt/cni/bin
	err = cp.InstallBPFBinaries(bpfBinaries, hostBinaryPath)
	if err != nil {
		//Log the error and move on
		ebpfClient.logger.Info("Failed to copy the eBPF binaries to host path....", "error", err)
	}
	ebpfClient.logger.Info("Copied eBPF binaries to the host directory")

	eventBufferFD := 0
	isConntrackMapPresent, isPolicyEventsMapPresent, eventBufferFD, err = recoverBPFState(ebpfClient.bpfSDKClient, policyEndpointeBPFContext,
		ebpfClient.GlobalMaps, ingressUpdateRequired, egressUpdateRequired, eventsUpdateRequired)
	if err != nil {
		//Log the error and move on
		ebpfClient.logger.Info("Failed to recover the BPF state: ", "error ", err)
		sdkAPIErr.WithLabelValues("RecoverBPFState").Inc()
	}
	ebpfClient.logger.Info("Successfully recovered BPF state")

	// Load the current events binary, if ..
	// - Current events binary packaged with network policy agent is different than the one installed
	//   during the previous installation (or)
	// - Either Conntrack Map (or) Events Map is currently missing on the node
	if eventsUpdateRequired || (!isConntrackMapPresent || !isPolicyEventsMapPresent) {
		ebpfClient.logger.Info("Install the default global maps")
		eventsProbe := EVENTS_BINARY
		if enableIPv6 {
			eventsProbe = EVENTS_V6_BINARY
		}
		_, globalMapInfo, err := ebpfClient.bpfSDKClient.LoadBpfFile(eventsProbe, "global")
		if err != nil {
			ebpfClient.logger.Error(err, "Unable to load events binary. Required for policy enforcement, exiting..")
			sdkAPIErr.WithLabelValues("LoadBpfFile").Inc()
			return nil, err
		}
		ebpfClient.logger.Info("Successfully loaded events probe")

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
			ebpfClient.logger.Info("Derived existing ConntrackMap identifier")
		} else {
			ebpfClient.logger.Error(err, "Unable to get conntrackMap post recovery..")
			sdkAPIErr.WithLabelValues("RecoveryFailed").Inc()
			return nil, err
		}
	}

	ebpfClient.conntrackClient = conntrack.NewConntrackClient(conntrackMap, enableIPv6, ebpfClient.logger)
	ebpfClient.logger.Info("Initialized Conntrack client")

	if enablePolicyEventLogs {
		err = events.ConfigurePolicyEventsLogging(ebpfClient.logger, enableCloudWatchLogs, eventBufferFD, enableIPv6)
		if err != nil {
			ebpfClient.logger.Error(err, "unable to initialize event buffer for Policy events, exiting..")
			sdkAPIErr.WithLabelValues("ConfigurePolicyEventsLogging").Inc()
			return nil, err
		}
		ebpfClient.logger.Info("Configured event logging")
	} else {
		ebpfClient.logger.Info("Disabled event logging")
	}

	// Start Conntrack routines
	if enableIPv6 {
		go wait.Forever(ebpfClient.conntrackClient.Cleanupv6ConntrackMap, conntrackTTL*time.Second)
	} else {
		go wait.Forever(ebpfClient.conntrackClient.CleanupConntrackMap, conntrackTTL*time.Second)
	}

	// Initializes prometheus metrics
	prometheusRegister()

	ebpfClient.logger.Info("BPF Client initialization done")
	return ebpfClient, nil
}

var _ BpfClient = (*bpfClient)(nil)

type bpfClient struct {
	// Stores eBPF Ingress and Egress context per policyEndpoint resource
	policyEndpointeBPFContext *sync.Map
	// Stores the Ingress eBPF Prog FD per pod
	IngressProgPodMap *sync.Map
	// Stores the Egress eBPF Prog FD per pod
	EgressProgPodMap *sync.Map
	// Stores info on the global maps the agent creates
	GlobalMaps *sync.Map
	// Primary IP of the node
	nodeIP string
	// Flag to track the IPv6 mode
	enableIPv6 bool
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
	// Logger instance
	logger logr.Logger
}

type Event_t struct {
	SourceIP   uint32
	SourcePort uint32
	DestIP     uint32
	DestPort   uint32
	Protocol   uint32
	Verdict    uint32
}

func checkAndUpdateBPFBinaries(bpfTCClient tc.BpfTc, bpfBinaries []string, hostBinaryPath string) (bool, bool, bool, error) {
	log := ctrl.Log.WithName("ebpf-client-init") //TODO - reuse the logger
	updateIngressProbe, updateEgressProbe, updateEventsProbe := false, false, false
	var existingProbePath string

	for _, bpfProbe := range bpfBinaries {
		if bpfProbe == EKS_CLI_BINARY || bpfProbe == EKS_V6_CLI_BINARY {
			continue
		}

		log.Info("Validating ", "Probe: ", bpfProbe)
		currentProbe, err := ioutil.ReadFile(bpfProbe)
		if err != nil {
			log.Info("error opening  ", "Probe: ", bpfProbe, "error", err)
		}

		existingProbePath = hostBinaryPath + bpfProbe
		existingProbe, err := ioutil.ReadFile(existingProbePath)
		if err != nil {
			log.Info("error opening  ", "Probe: ", existingProbePath, "error", err)
		}

		log.Info("comparing new and existing probes ...")
		isEqual := cmp.Equal(currentProbe, existingProbe)
		if !isEqual {
			if bpfProbe == EVENTS_BINARY || bpfProbe == EVENTS_V6_BINARY {
				// Ingress and Egress probes refer to Conntrack and Policy Events maps defined in
				// events binary. So, if the events binary changes, we will need to update all the existing
				// probes in the local node
				updateEventsProbe, updateIngressProbe, updateEgressProbe = true, true, true
				log.Info("change detected in event probe binaries..")
				break
			}
			if bpfProbe == TC_INGRESS_BINARY || bpfProbe == TC_V6_INGRESS_BINARY {
				log.Info("change detected in ingress probe binaries.. ")
				updateIngressProbe = true
			}
			if bpfProbe == TC_EGRESS_BINARY || bpfProbe == TC_V6_EGRESS_BINARY {
				log.Info("change detected in egress probe binaries..")
				updateEgressProbe = true
			}
		}
	}

	//Clean up probes
	if updateIngressProbe || updateEgressProbe {
		err := bpfTCClient.CleanupQdiscs(updateIngressProbe, updateEgressProbe)
		if err != nil {
			log.Error(err, "Probe cleanup failed")
			sdkAPIErr.WithLabelValues("CleanupQdiscs").Inc()
			return updateIngressProbe, updateEgressProbe, updateEventsProbe, err
		}
	}

	return updateIngressProbe, updateEgressProbe, updateEventsProbe, nil
}

func recoverBPFState(eBPFSDKClient goelf.BpfSDKClient, policyEndpointeBPFContext *sync.Map, globalMaps *sync.Map, updateIngressProbe,
	updateEgressProbe, updateEventsProbe bool) (bool, bool, int, error) {
	log := ctrl.Log.WithName("ebpf-client") //TODO reuse logger
	isConntrackMapPresent, isPolicyEventsMapPresent := false, false
	eventsMapFD := 0

	// Recover global maps (Conntrack and Events) if there is no need to update
	// events binary
	if !updateEventsProbe {
		recoveredGlobalMaps, err := eBPFSDKClient.RecoverGlobalMaps()
		if err != nil {
			log.Error(err, "failed to recover global maps..")
			sdkAPIErr.WithLabelValues("RecoverGlobalMaps").Inc()
			return isConntrackMapPresent, isPolicyEventsMapPresent, eventsMapFD, nil
		}
		log.Info("Total no.of  global maps recovered...", "count: ", len(recoveredGlobalMaps))
		for globalMapName, globalMap := range recoveredGlobalMaps {
			log.Info("Global Map..", "Name: ", globalMapName, "updateEventsProbe: ", updateEventsProbe)
			if globalMapName == CONNTRACK_MAP_PIN_PATH {
				log.Info("Conntrack Map is already present on the node")
				isConntrackMapPresent = true
				globalMaps.Store(globalMapName, globalMap)
			}
			if globalMapName == POLICY_EVENTS_MAP_PIN_PATH {
				isPolicyEventsMapPresent = true
				eventsMapFD = int(globalMap.MapFD)
				log.Info("Policy event Map is already present on the node ", "Recovered FD", eventsMapFD)
			}
		}
	}

	// Recover BPF Programs and Maps from BPF_FS. We only aim to recover programs and maps
	// created by aws-network-policy-agent (Located under /sys/fs/bpf/globals/aws)
	if !updateIngressProbe || !updateEgressProbe {
		bpfState, err := eBPFSDKClient.RecoverAllBpfProgramsAndMaps()
		var peBPFContext BPFContext
		if err != nil {
			//Log it and move on. We will overwrite and recreate the maps/programs
			log.Info("BPF State Recovery failed: ", "error: ", err)
			sdkAPIErr.WithLabelValues("RecoverAllBpfProgramAndMaps").Inc()
		}

		log.Info("Number of probes/maps recovered - ", "count: ", len(bpfState))
		for pinPath, bpfEntry := range bpfState {
			log.Info("Recovered program Identifier: ", "Pin Path: ", pinPath)
			podIdentifier, direction := utils.GetPodIdentifierFromBPFPinPath(pinPath)
			log.Info("PinPath: ", "podIdentifier: ", podIdentifier, "direction: ", direction)
			value, ok := policyEndpointeBPFContext.Load(podIdentifier)
			if ok {
				peBPFContext = value.(BPFContext)
			}
			if direction == "ingress" && !updateIngressProbe {
				peBPFContext.ingressPgmInfo = bpfEntry
			} else if direction == "egress" && !updateEgressProbe {
				peBPFContext.egressPgmInfo = bpfEntry
			}
			policyEndpointeBPFContext.Store(podIdentifier, peBPFContext)
		}
	}

	return isConntrackMapPresent, isPolicyEventsMapPresent, eventsMapFD, nil
}

func (l *bpfClient) AttacheBPFProbes(pod types.NamespacedName, podIdentifier string, ingress bool, egress bool) error {
	start := time.Now()
	// We attach the TC probes to the hostVeth interface of the pod. Derive the hostVeth
	// name from the Name and Namespace of the Pod.
	// Note: The below naming convention is tied to VPC CNI and isn't meant to be generic
	hostVethName := utils.GetHostVethName(pod.Name, pod.Namespace)
	l.logger.Info("AttacheBPFProbes for", "pod", pod.Name, " in namespace", pod.Namespace, " with hostVethName", hostVethName)

	if ingress {
		progFD, err := l.attachIngressBPFProbe(hostVethName, podIdentifier)
		duration := msSince(start)
		sdkAPILatency.WithLabelValues("attachIngressBPFProbe", fmt.Sprint(err != nil)).Observe(duration)
		if err != nil {
			l.logger.Info("Failed to Attach Ingress TC probe for", "pod: ", pod.Name, " in namespace", pod.Namespace)
			sdkAPIErr.WithLabelValues("attachIngressBPFProbe").Inc()
			return err
		}
		l.logger.Info("Successfully attached Ingress TC probe for", "pod: ", pod.Name, " in namespace", pod.Namespace)
		l.IngressProgPodMap.Store(utils.GetPodNamespacedName(pod.Name, pod.Namespace), progFD)
	}

	if egress {
		progFD, err := l.attachEgressBPFProbe(hostVethName, podIdentifier)
		duration := msSince(start)
		sdkAPILatency.WithLabelValues("attachEgressBPFProbe", fmt.Sprint(err != nil)).Observe(duration)
		if err != nil {
			l.logger.Info("Failed to Attach Egress TC probe for", "pod: ", pod.Name, " in namespace", pod.Namespace)
			sdkAPIErr.WithLabelValues("attachEgressBPFProbe").Inc()
			return err
		}
		l.logger.Info("Successfully attached Egress TC probe for", "pod: ", pod.Name, " in namespace", pod.Namespace)
		l.EgressProgPodMap.Store(utils.GetPodNamespacedName(pod.Name, pod.Namespace), progFD)
	}

	return nil
}

func (l *bpfClient) DetacheBPFProbes(pod types.NamespacedName, ingress bool, egress bool) error {
	start := time.Now()
	hostVethName := utils.GetHostVethName(pod.Name, pod.Namespace)
	l.logger.Info("DetacheBPFProbes for", "pod", pod.Name, " in namespace", pod.Namespace, " with hostVethName", hostVethName)
	podIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
	if ingress {
		err := l.detachIngressBPFProbe(hostVethName)
		duration := msSince(start)
		sdkAPILatency.WithLabelValues("detachIngressBPFProbe", fmt.Sprint(err != nil)).Observe(duration)
		if err != nil {
			l.logger.Info("Failed to Detach Ingress TC probe for", "pod: ", pod.Name, " in namespace", pod.Namespace)
			sdkAPIErr.WithLabelValues("detachIngressBPFProbe").Inc()
		}
		l.logger.Info("Successfully detached Ingress TC probe for", "pod: ", pod.Name, " in namespace", pod.Namespace)
		err = l.deleteBPFProgramAndMaps(podIdentifier, "ingress")
		duration = msSince(start)
		sdkAPILatency.WithLabelValues("deleteBPFProgramAndMaps", fmt.Sprint(err != nil)).Observe(duration)
		if err != nil {
			l.logger.Info("Error while deleting Ingress BPF Probe for ", "podIdentifier: ", podIdentifier)
		}
		l.IngressProgPodMap.Delete(utils.GetPodNamespacedName(pod.Name, pod.Namespace))
	}

	if egress {
		err := l.detachEgressBPFProbe(hostVethName)
		duration := msSince(start)
		sdkAPILatency.WithLabelValues("detachIngressBPFProbe", fmt.Sprint(err != nil)).Observe(duration)
		if err != nil {
			l.logger.Info("Failed to Detach Egress TC probe for", "pod: ", pod.Name, " in namespace", pod.Namespace)
			sdkAPIErr.WithLabelValues("attachEgressBPFProbe").Inc()
		}
		l.logger.Info("Successfully detached Egress TC probe for", "pod: ", pod.Name, " in namespace", pod.Namespace)
		err = l.deleteBPFProgramAndMaps(podIdentifier, "egress")
		duration = msSince(start)
		sdkAPILatency.WithLabelValues("deleteBPFProgramAndMaps", fmt.Sprint(err != nil)).Observe(duration)
		if err != nil {
			l.logger.Info("Error while deleting Egress BPF Probe for ", "podIdentifier: ", podIdentifier)
			sdkAPIErr.WithLabelValues("deleteBPFProgramAndMaps").Inc()
		}
		l.policyEndpointeBPFContext.Delete(podIdentifier)
		l.EgressProgPodMap.Delete(utils.GetPodNamespacedName(pod.Name, pod.Namespace))
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
		l.logger.Info("Found an existing instance, let's derive the ingress context..")
		ingressEbpfProgEntry := peBPFContext.ingressPgmInfo
		progFD = ingressEbpfProgEntry.Program.ProgFD
	} else {
		ingressProgInfo, progFD, err = l.loadBPFProgram(l.ingressBinary, "ingress", podIdentifier)
		pinPath := utils.GetBPFPinPathFromPodIdentifier(podIdentifier, "ingress")
		peBPFContext.ingressPgmInfo = ingressProgInfo[pinPath]
		l.policyEndpointeBPFContext.Store(podIdentifier, peBPFContext)
	}

	l.logger.Info("Attempting to do an Ingress Attach")
	err = l.bpfTCClient.TCEgressAttach(hostVethName, progFD, TC_INGRESS_PROG)
	if err != nil && !utils.IsFileExistsError(err.Error()) {
		l.logger.Info("Ingress Attach failed:", "error", err)
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
		l.logger.Info("Found an existing instance, let's derive the egress context..")
		egressEbpfProgEntry := peBPFContext.egressPgmInfo
		progFD = egressEbpfProgEntry.Program.ProgFD
	} else {
		egressProgInfo, progFD, err = l.loadBPFProgram(l.egressBinary, "egress", podIdentifier)
		pinPath := utils.GetBPFPinPathFromPodIdentifier(podIdentifier, "egress")
		peBPFContext.egressPgmInfo = egressProgInfo[pinPath]
		l.policyEndpointeBPFContext.Store(podIdentifier, peBPFContext)
	}

	l.logger.Info("Attempting to do an Egress Attach")
	err = l.bpfTCClient.TCIngressAttach(hostVethName, progFD, TC_EGRESS_PROG)
	if err != nil && !utils.IsFileExistsError(err.Error()) {
		l.logger.Error(err, "Egress Attach failed")
		return 0, err
	}

	return progFD, nil
}

func (l *bpfClient) detachIngressBPFProbe(hostVethName string) error {
	l.logger.Info("Attempting to do an Ingress Detach")
	var err error
	err = l.bpfTCClient.TCEgressDetach(hostVethName)
	if err != nil &&
		!utils.IsMissingFilterError(err.Error()) {
		l.logger.Info("Ingress Detach failed:", "error", err)
		return err
	}
	return nil
}

func (l *bpfClient) detachEgressBPFProbe(hostVethName string) error {
	l.logger.Info("Attempting to do an Egress Detach")
	var err error
	err = l.bpfTCClient.TCIngressDetach(hostVethName)
	if err != nil &&
		!utils.IsMissingFilterError(err.Error()) {
		l.logger.Info("Ingress Detach failed:", "error", err)
		return err
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

	l.logger.Info("Deleting: ", "Program: ", pgmPinPath, "Map: ", mapPinpath)

	pgmInfo := peBPFContext.ingressPgmInfo
	mapToDelete := pgmInfo.Maps[TC_INGRESS_MAP]
	if direction == "egress" {
		l.logger.Info("Egress delete flow for ", "Program: ", pgmPinPath, "Map: ", mapPinpath)
		pgmInfo = peBPFContext.egressPgmInfo
		mapToDelete = pgmInfo.Maps[TC_EGRESS_MAP]
	}

	if pgmInfo.Program.ProgFD != 0 {
		l.logger.Info("Found the Program and Map to delete - ", "Program: ", pgmPinPath, "Map: ", mapPinpath)
		err = pgmInfo.Program.UnPinProg(pgmPinPath)
		if err != nil {
			l.logger.Info("Failed to delete the Program: ", err)
		}
		mapToDelete.UnPinMap(mapPinpath)
		if err != nil {
			l.logger.Info("Failed to delete the Map: ", err)
		}
	}
	return nil
}

func (l *bpfClient) loadBPFProgram(fileName string, direction string,
	podIdentifier string) (map[string]goelf.BpfData, int, error) {

	start := time.Now()
	l.logger.Info("Load the eBPF program")
	// Load a new instance of the ingres program
	progInfo, _, err := l.bpfSDKClient.LoadBpfFile(fileName, podIdentifier)
	duration := msSince(start)
	sdkAPILatency.WithLabelValues("LoadBpfFile", fmt.Sprint(err != nil)).Observe(duration)
	if err != nil {
		sdkAPIErr.WithLabelValues("LoadBpfFile").Inc()
		l.logger.Info("Load BPF failed", "err:", err)
		return nil, -1, err
	}

	for k, _ := range progInfo {
		l.logger.Info("Prog Info: ", "Pin Path: ", k)
	}

	pinPath := utils.GetBPFPinPathFromPodIdentifier(podIdentifier, direction)
	l.logger.Info("PinPath for this pod: ", "PinPath: ", pinPath)
	progFD := progInfo[pinPath].Program.ProgFD

	l.logger.Info("Prog Load Succeeded", "for ", direction, "progFD: ", progFD)

	return progInfo, progFD, nil
}

func (l *bpfClient) UpdateEbpfMaps(podIdentifier string, ingressFirewallRules []EbpfFirewallRules,
	egressFirewallRules []EbpfFirewallRules) error {

	var ingressProgFD, egressProgFD int
	var mapToUpdate goebpfmaps.BpfMap
	start := time.Now()
	value, ok := l.policyEndpointeBPFContext.Load(podIdentifier)

	if ok {
		peBPFContext := value.(BPFContext)
		ingressProgInfo := peBPFContext.ingressPgmInfo
		egressProgInfo := peBPFContext.egressPgmInfo

		if ingressProgInfo.Program.ProgFD != 0 {
			ingressProgFD = ingressProgInfo.Program.ProgFD
			mapToUpdate = ingressProgInfo.Maps[TC_INGRESS_MAP]
			l.logger.Info("Pod has an Ingress hook attached. Update the corresponding map", "progFD: ", ingressProgFD,
				"mapName: ", TC_INGRESS_MAP)
			err := l.updateEbpfMap(mapToUpdate, ingressFirewallRules)
			duration := msSince(start)
			sdkAPILatency.WithLabelValues("updateEbpfMap-ingress", fmt.Sprint(err != nil)).Observe(duration)
			if err != nil {
				l.logger.Info("Ingress Map update failed: ", "error: ", err)
				sdkAPIErr.WithLabelValues("updateEbpfMap-ingress").Inc()
			}
		}
		if egressProgInfo.Program.ProgFD != 0 {
			egressProgFD = egressProgInfo.Program.ProgFD
			mapToUpdate = egressProgInfo.Maps[TC_EGRESS_MAP]

			l.logger.Info("Pod has an Egress hook attached. Update the corresponding map", "progFD: ", egressProgFD,
				"mapName: ", TC_EGRESS_MAP)
			err := l.updateEbpfMap(mapToUpdate, egressFirewallRules)
			duration := msSince(start)
			sdkAPILatency.WithLabelValues("updateEbpfMap-egress", fmt.Sprint(err != nil)).Observe(duration)
			if err != nil {
				l.logger.Info("Egress Map update failed: ", "error: ", err)
				sdkAPIErr.WithLabelValues("updateEbpfMap-egress").Inc()
			}
		}
	}
	return nil
}

func (l *bpfClient) IsEBPFProbeAttached(podName string, podNamespace string) (bool, bool) {
	ingress, egress := false, false
	if _, ok := l.IngressProgPodMap.Load(utils.GetPodNamespacedName(podName, podNamespace)); ok {
		l.logger.Info("Pod already has Ingress Probe attached - ", "Name: ", podName, "Namespace: ", podNamespace)
		ingress = true
	}
	if _, ok := l.EgressProgPodMap.Load(utils.GetPodNamespacedName(podName, podNamespace)); ok {
		l.logger.Info("Pod already has Egress Probe attached - ", "Name: ", podName, "Namespace: ", podNamespace)
		egress = true
	}
	return ingress, egress
}

func (l *bpfClient) updateEbpfMap(mapToUpdate goebpfmaps.BpfMap, firewallRules []EbpfFirewallRules) error {
	start := time.Now()
	duration := msSince(start)
	mapEntries, err := l.computeMapEntriesFromEndpointRules(firewallRules)
	if err != nil {
		l.logger.Info("Trie entry creation/validation failed ", "error: ", err)
		return err
	}

	l.logger.Info("ID of map to update: ", "ID: ", mapToUpdate.MapID)
	err = mapToUpdate.BulkRefreshMapEntries(mapEntries)
	sdkAPILatency.WithLabelValues("BulkRefreshMapEntries", fmt.Sprint(err != nil)).Observe(duration)
	if err != nil {
		l.logger.Info("BPF map update failed", "error: ", err)
		sdkAPIErr.WithLabelValues("BulkRefreshMapEntries").Inc()
		return err
	}
	return nil
}

func sortFirewallRulesByPrefixLength(rules []EbpfFirewallRules, defaultPrefixLen int) {
	sort.Slice(rules, func(i, j int) bool {
		prefixIp1 := strings.Split(string(rules[i].IPCidr), "/")
		prefixIp2 := strings.Split(string(rules[j].IPCidr), "/")

		prefixLenIp1 := defaultPrefixLen
		prefixLenIp2 := defaultPrefixLen

		if len(prefixIp1) == 2 {
			prefixLenIp1, _ = strconv.Atoi(prefixIp1[1])
		}

		if len(prefixIp2) == 2 {
			prefixLenIp2, _ = strconv.Atoi(prefixIp2[1])
		}
		return prefixLenIp1 < prefixLenIp2
	})
}

func (l *bpfClient) computeMapEntriesFromEndpointRules(firewallRules []EbpfFirewallRules) (map[string]uintptr, error) {
	mapEntries := make(map[string]uintptr)
	ipCIDRs := make(map[string][]v1alpha1.Port)
	nonHostCIDRs := make(map[string][]v1alpha1.Port)
	isCatchAllIPEntryPresent, allowAll := false, false
	var catchAllIPPorts []v1alpha1.Port

	//Traffic from the local node should always be allowed. Add NodeIP by default to map entries.
	_, mapKey, _ := net.ParseCIDR(l.nodeIP + l.hostMask)
	key := utils.ComputeTrieKey(*mapKey, l.enableIPv6)
	value := utils.ComputeTrieValue([]v1alpha1.Port{}, l.logger, true, false)
	mapEntries[string(key)] = uintptr(unsafe.Pointer(&value[0]))

	//Sort the rules
	defaultPrefixLen := 32
	if l.enableIPv6 {
		defaultPrefixLen = 128
	}
	sortFirewallRulesByPrefixLength(firewallRules, defaultPrefixLen)

	//Check and aggregate L4 Port Info for Catch All Entries.
	catchAllIPPorts, isCatchAllIPEntryPresent, allowAll = l.checkAndDeriveCatchAllIPPorts(firewallRules)
	if isCatchAllIPEntryPresent {
		//Add the Catch All IP entry
		_, mapKey, _ = net.ParseCIDR("0.0.0.0/0")
		key = utils.ComputeTrieKey(*mapKey, l.enableIPv6)
		value = utils.ComputeTrieValue(catchAllIPPorts, l.logger, allowAll, false)
		mapEntries[string(key)] = uintptr(unsafe.Pointer(&value[0]))
	}

	for _, firewallRule := range firewallRules {
		var cidrL4Info []v1alpha1.Port

		if !strings.Contains(string(firewallRule.IPCidr), "/") {
			firewallRule.IPCidr += v1alpha1.NetworkAddress(l.hostMask)
		}

		if utils.IsNodeIP(l.nodeIP, string(firewallRule.IPCidr)) {
			continue
		}

		if !utils.IsCatchAllIPEntry(string(firewallRule.IPCidr)) {
			if len(firewallRule.L4Info) == 0 {
				l.logger.Info("No L4 specified. Add Catch all entry: ", "CIDR: ", firewallRule.IPCidr)
				l.addCatchAllL4Entry(&firewallRule)
				l.logger.Info("Total L4 entries ", "count: ", len(firewallRule.L4Info))
			}
			if utils.IsNonHostCIDR(string(firewallRule.IPCidr)) {
				existingL4Info, ok := nonHostCIDRs[string(firewallRule.IPCidr)]
				if ok {
					firewallRule.L4Info = append(firewallRule.L4Info, existingL4Info...)
				} else {
					// Check if the /m entry is part of any /n CIDRs that we've encountered so far
					// If found, we need to include the port and protocol combination against the current entry as well since
					// we use LPM TRIE map and the /m will always win out.
					cidrL4Info = l.checkAndDeriveL4InfoFromAnyMatchingCIDRs(string(firewallRule.IPCidr), nonHostCIDRs)
					if len(cidrL4Info) > 0 {
						firewallRule.L4Info = append(firewallRule.L4Info, cidrL4Info...)
					}
				}
				nonHostCIDRs[string(firewallRule.IPCidr)] = firewallRule.L4Info
			} else {
				if existingL4Info, ok := ipCIDRs[string(firewallRule.IPCidr)]; ok {
					firewallRule.L4Info = append(firewallRule.L4Info, existingL4Info...)
				}
				// Check if the /32 entry is part of any non host CIDRs that we've encountered so far
				// If found, we need to include the port and protocol combination against the current entry as well since
				// we use LPM TRIE map and the /32 will always win out.
				cidrL4Info = l.checkAndDeriveL4InfoFromAnyMatchingCIDRs(string(firewallRule.IPCidr), nonHostCIDRs)
				if len(cidrL4Info) > 0 {
					firewallRule.L4Info = append(firewallRule.L4Info, cidrL4Info...)
				}
				ipCIDRs[string(firewallRule.IPCidr)] = firewallRule.L4Info
			}
			//Include port and protocol combination paired with catch all entries
			firewallRule.L4Info = append(firewallRule.L4Info, catchAllIPPorts...)

			l.logger.Info("Updating Map with ", "IP Key:", firewallRule.IPCidr)
			_, mapKey, _ = net.ParseCIDR(string(firewallRule.IPCidr))
			// Key format: Prefix length (4 bytes) followed by 4/16byte IP address
			key = utils.ComputeTrieKey(*mapKey, l.enableIPv6)
			value = utils.ComputeTrieValue(firewallRule.L4Info, l.logger, allowAll, false)
			mapEntries[string(key)] = uintptr(unsafe.Pointer(&value[0]))
		}
		if firewallRule.Except != nil {
			for _, exceptCIDR := range firewallRule.Except {
				_, mapKey, _ = net.ParseCIDR(string(exceptCIDR))
				key = utils.ComputeTrieKey(*mapKey, l.enableIPv6)
				l.logger.Info("Parsed Except CIDR", "IP Key: ", mapKey)
				value = utils.ComputeTrieValue(firewallRule.L4Info, l.logger, false, true)
				mapEntries[string(key)] = uintptr(unsafe.Pointer(&value[0]))
			}
		}
	}
	return mapEntries, nil
}

func (l *bpfClient) checkAndDeriveCatchAllIPPorts(firewallRules []EbpfFirewallRules) ([]v1alpha1.Port, bool, bool) {
	var catchAllL4Info []v1alpha1.Port
	isCatchAllIPEntryPresent := false
	allowAllPortAndProtocols := false
	for _, firewallRule := range firewallRules {
		if !strings.Contains(string(firewallRule.IPCidr), "/") {
			firewallRule.IPCidr += v1alpha1.NetworkAddress(l.hostMask)
		}
		if !l.enableIPv6 && strings.Contains(string(firewallRule.IPCidr), "::") {
			l.logger.Info("IPv6 catch all entry in IPv4 mode - skip ")
			continue
		}
		if utils.IsCatchAllIPEntry(string(firewallRule.IPCidr)) {
			catchAllL4Info = append(catchAllL4Info, firewallRule.L4Info...)
			isCatchAllIPEntryPresent = true
			if len(firewallRule.L4Info) == 0 {
				//All ports and protocols
				allowAllPortAndProtocols = true
			}
		}
		l.logger.Info("Current L4 entry count for catch all entry: ", "count: ", len(catchAllL4Info))
	}
	l.logger.Info("Total L4 entry count for catch all entry: ", "count: ", len(catchAllL4Info))
	return catchAllL4Info, isCatchAllIPEntryPresent, allowAllPortAndProtocols
}

func (l *bpfClient) checkAndDeriveL4InfoFromAnyMatchingCIDRs(firewallRule string,
	nonHostCIDRs map[string][]v1alpha1.Port) []v1alpha1.Port {
	var matchingCIDRL4Info []v1alpha1.Port

	_, ipToCheck, _ := net.ParseCIDR(firewallRule)
	for nonHostCIDR, l4Info := range nonHostCIDRs {
		_, cidrEntry, _ := net.ParseCIDR(nonHostCIDR)
		l.logger.Info("CIDR match: ", "for IP: ", firewallRule, "in CIDR: ", nonHostCIDR)
		if cidrEntry.Contains(ipToCheck.IP) {
			l.logger.Info("Found a CIDR match: ", "for IP: ", firewallRule, "in CIDR: ", nonHostCIDR)
			matchingCIDRL4Info = append(matchingCIDRL4Info, l4Info...)
		}
	}
	return matchingCIDRL4Info
}

func (l *bpfClient) addCatchAllL4Entry(firewallRule *EbpfFirewallRules) {
	catchAllL4Entry := v1alpha1.Port{
		Protocol: &CATCH_ALL_PROTOCOL,
	}
	firewallRule.L4Info = append(firewallRule.L4Info, catchAllL4Entry)
}

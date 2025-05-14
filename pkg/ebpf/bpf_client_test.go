package ebpf

import (
	"net"
	"sort"
	"sync"
	"testing"

	goelf "github.com/aws/aws-ebpf-sdk-go/pkg/elfparser"
	goebpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	goebpfprogs "github.com/aws/aws-ebpf-sdk-go/pkg/progs"

	mock_bpfclient "github.com/aws/aws-ebpf-sdk-go/pkg/elfparser/mocks"
	mock_bpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps/mocks"
	"github.com/aws/aws-ebpf-sdk-go/pkg/tc"
	mock_tc "github.com/aws/aws-ebpf-sdk-go/pkg/tc/mocks"
	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/go-logr/logr"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
	// "unsafe"
)

func TestBpfClient_computeMapEntriesFromEndpointRules(t *testing.T) {
	test_bpfClientLogger := ctrl.Log.WithName("ebpf-client")
	protocolTCP := corev1.ProtocolTCP
	//protocolUDP := corev1.ProtocolUDP
	//protocolSCTP := corev1.ProtocolSCTP

	var testIP v1alpha1.NetworkAddress
	var gotKeys []string

	nodeIP := "10.1.1.1"
	_, nodeIPCIDR, _ := net.ParseCIDR(nodeIP + "/32")
	nodeIPKey := utils.ComputeTrieKey(*nodeIPCIDR, false)
	// nodeIPValue := utils.ComputeTrieValue([]v1alpha1.Port{}, test_bpfClientLogger, true, false)

	var testPort int32
	testPort = 80
	testIP = "10.1.1.2/32"
	_, testIPCIDR, _ := net.ParseCIDR(string(testIP))

	testIPKey := utils.ComputeTrieKey(*testIPCIDR, false)
	//      cidrWithPPValue := utils.ComputeTrieValue(testL4Info, test_bpfClientLogger, false, false)
	type args struct {
		firewallRules []EbpfFirewallRules
	}

	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr error
	}{
		{
			name: "CIDR with Port and Protocol",
			args: args{
				[]EbpfFirewallRules{
					{
						IPCidr: "10.1.1.2/32",
						L4Info: []v1alpha1.Port{
							{
								Protocol: &protocolTCP,
								Port:     &testPort,
							},
						},
					},
				},
			},
			want: []string{string(nodeIPKey), string(testIPKey)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			test_bpfClient := &bpfClient{
				nodeIP:     "10.1.1.1",
				logger:     test_bpfClientLogger,
				enableIPv6: false,
				hostMask:   "/32",
			}
			got, err := test_bpfClient.computeMapEntriesFromEndpointRules(tt.args.firewallRules)
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				for key, _ := range got {
					gotKeys = append(gotKeys, key)
				}
				sort.Strings(tt.want)
				sort.Strings(gotKeys)
				assert.Equal(t, tt.want, gotKeys)
			}
		})
	}
}

func TestBpfClient_IsEBPFProbeAttached(t *testing.T) {
	ingressProgFD, egressProgFD := 12, 13
	type want struct {
		ingress bool
		egress  bool
	}

	tests := []struct {
		name            string
		podName         string
		podNamespace    string
		ingressAttached bool
		egressAttached  bool
		want            want
	}{
		{
			name:            "Ingress and Egress probes attached",
			podName:         "foo",
			podNamespace:    "bar",
			ingressAttached: true,
			egressAttached:  true,
			want: want{
				ingress: true,
				egress:  true,
			},
		},
		{
			name:            "Only Ingress Probe attached",
			podName:         "foo",
			podNamespace:    "bar",
			ingressAttached: true,
			egressAttached:  false,
			want: want{
				ingress: true,
				egress:  false,
			},
		},
		{
			name:            "Only Egress Probe attached",
			podName:         "foo",
			podNamespace:    "bar",
			ingressAttached: false,
			egressAttached:  true,
			want: want{
				ingress: false,
				egress:  true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testBpfClient := &bpfClient{
				nodeIP:              "10.1.1.1",
				logger:              logr.New(&log.NullLogSink{}),
				enableIPv6:          false,
				hostMask:            "/32",
				IngressPodToProgMap: new(sync.Map),
				EgressPodToProgMap:  new(sync.Map),
			}

			if tt.ingressAttached {
				podIdentifier := utils.GetPodNamespacedName(tt.podName, tt.podNamespace)
				testBpfClient.IngressPodToProgMap.Store(podIdentifier, ingressProgFD)
			}
			if tt.egressAttached {
				podIdentifier := utils.GetPodNamespacedName(tt.podName, tt.podNamespace)
				testBpfClient.EgressPodToProgMap.Store(podIdentifier, egressProgFD)
			}
			gotIngress, gotEgress := testBpfClient.IsEBPFProbeAttached(tt.podName, tt.podNamespace)
			assert.Equal(t, tt.want.ingress, gotIngress)
			assert.Equal(t, tt.want.egress, gotEgress)
		})
	}
}

func TestBpfClient_CheckAndDeriveCatchAllIPPorts(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	var port80 int32 = 80

	type want struct {
		catchAllL4Info           []v1alpha1.Port
		isCatchAllIPEntryPresent bool
		allowAllPortAndProtocols bool
	}

	l4InfoWithCatchAllEntry := []EbpfFirewallRules{
		{
			IPCidr: "0.0.0.0/0",
			L4Info: []v1alpha1.Port{
				{
					Protocol: &protocolTCP,
					Port:     &port80,
				},
			},
		},
	}

	l4InfoWithNoCatchAllEntry := []EbpfFirewallRules{
		{
			IPCidr: "1.1.1.1/32",
			L4Info: []v1alpha1.Port{
				{
					Protocol: &protocolTCP,
					Port:     &port80,
				},
			},
		},
	}

	l4InfoWithCatchAllEntryAndAllProtocols := []EbpfFirewallRules{
		{
			IPCidr: "0.0.0.0/0",
		},
	}

	tests := []struct {
		name          string
		firewallRules []EbpfFirewallRules
		want          want
	}{
		{
			name:          "Catch All Entry present",
			firewallRules: l4InfoWithCatchAllEntry,
			want: want{
				catchAllL4Info: []v1alpha1.Port{
					{
						Protocol: &protocolTCP,
						Port:     &port80,
					},
				},
				isCatchAllIPEntryPresent: true,
				allowAllPortAndProtocols: false,
			},
		},

		{
			name:          "No Catch All Entry present",
			firewallRules: l4InfoWithNoCatchAllEntry,
			want: want{
				isCatchAllIPEntryPresent: false,
				allowAllPortAndProtocols: false,
			},
		},

		{
			name:          "Catch All Entry With no Port info",
			firewallRules: l4InfoWithCatchAllEntryAndAllProtocols,
			want: want{
				isCatchAllIPEntryPresent: true,
				allowAllPortAndProtocols: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testBpfClient := &bpfClient{
				nodeIP:              "10.1.1.1",
				logger:              logr.New(&log.NullLogSink{}),
				enableIPv6:          false,
				hostMask:            "/32",
				IngressPodToProgMap: new(sync.Map),
				EgressPodToProgMap:  new(sync.Map),
			}
			gotCatchAllL4Info, gotIsCatchAllIPEntryPresent, gotAllowAllPortAndProtocols := testBpfClient.checkAndDeriveCatchAllIPPorts(tt.firewallRules)
			assert.Equal(t, tt.want.catchAllL4Info, gotCatchAllL4Info)
			assert.Equal(t, tt.want.isCatchAllIPEntryPresent, gotIsCatchAllIPEntryPresent)
			assert.Equal(t, tt.want.allowAllPortAndProtocols, gotAllowAllPortAndProtocols)
		})
	}
}

func TestBpfClient_CheckAndDeriveL4InfoFromAnyMatchingCIDRs(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	var port80 int32 = 80

	type want struct {
		matchingCIDRL4Info []v1alpha1.Port
	}

	sampleNonHostCIDRs := map[string][]v1alpha1.Port{
		"1.1.1.0/24": {
			{
				Protocol: &protocolTCP,
				Port:     &port80,
			},
		},
	}

	tests := []struct {
		name         string
		firewallRule string
		nonHostCIDRs map[string][]v1alpha1.Port
		want         want
	}{
		{
			name:         "Match Present",
			firewallRule: "1.1.1.2/32",
			nonHostCIDRs: sampleNonHostCIDRs,
			want: want{
				matchingCIDRL4Info: []v1alpha1.Port{
					{
						Protocol: &protocolTCP,
						Port:     &port80,
					},
				},
			},
		},

		{
			name:         "No Match",
			firewallRule: "2.1.1.2/32",
			nonHostCIDRs: sampleNonHostCIDRs,
			want:         want{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testBpfClient := &bpfClient{
				nodeIP:              "10.1.1.1",
				logger:              logr.New(&log.NullLogSink{}),
				enableIPv6:          false,
				hostMask:            "/32",
				IngressPodToProgMap: new(sync.Map),
				EgressPodToProgMap:  new(sync.Map),
			}
			gotMatchingCIDRL4Info := testBpfClient.checkAndDeriveL4InfoFromAnyMatchingCIDRs(tt.firewallRule, tt.nonHostCIDRs)
			assert.Equal(t, tt.want.matchingCIDRL4Info, gotMatchingCIDRL4Info)
		})
	}
}

func TestBpfClient_AddCatchAllL4Entry(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	var port80 int32 = 80

	l4InfoWithNoCatchAllEntry := EbpfFirewallRules{
		IPCidr: "1.1.1.1/32",
		L4Info: []v1alpha1.Port{
			{
				Protocol: &protocolTCP,
				Port:     &port80,
			},
		},
	}

	l4InfoWithCatchAllL4Info := EbpfFirewallRules{
		IPCidr: "1.1.1.1/32",
		L4Info: []v1alpha1.Port{
			{
				Protocol: &protocolTCP,
				Port:     &port80,
			},
			{
				Protocol: &CATCH_ALL_PROTOCOL,
			},
		},
	}

	tests := []struct {
		name          string
		firewallRules EbpfFirewallRules
	}{
		{
			name:          "Append Catch All Entry",
			firewallRules: l4InfoWithNoCatchAllEntry,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testBpfClient := &bpfClient{
				nodeIP:              "10.1.1.1",
				logger:              logr.New(&log.NullLogSink{}),
				enableIPv6:          false,
				hostMask:            "/32",
				IngressPodToProgMap: new(sync.Map),
				EgressPodToProgMap:  new(sync.Map),
			}
			testBpfClient.addCatchAllL4Entry(&tt.firewallRules)
			assert.Equal(t, tt.firewallRules, l4InfoWithCatchAllL4Info)
		})
	}
}

func TestLoadBPFProgram(t *testing.T) {
	var wantErr error
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBpfClient := mock_bpfclient.NewMockBpfSDKClient(ctrl)
	testBpfClient := &bpfClient{
		nodeIP:       "10.1.1.1",
		logger:       logr.New(&log.NullLogSink{}),
		enableIPv6:   false,
		bpfSDKClient: mockBpfClient,
	}

	mockBpfClient.EXPECT().LoadBpfFile(gomock.Any(), gomock.Any()).AnyTimes()
	_, _, gotErr := testBpfClient.loadBPFProgram("handle_ingress", "ingress", "test-abcd")
	assert.Equal(t, gotErr, wantErr)
}

func TestBpfClient_UpdateEbpfMaps(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	var port80 int32 = 80
	ingressMapFD, ingressMapID, egressMapFD, egressMapID := 11, 12, 13, 14

	sampleIngressFirewalls := []EbpfFirewallRules{
		{
			IPCidr: "10.1.1.2/32",
			L4Info: []v1alpha1.Port{
				{
					Protocol: &protocolTCP,
					Port:     &port80,
				},
			},
		},
	}

	sampleEgressFirewalls := []EbpfFirewallRules{
		{
			IPCidr: "10.1.1.2/32",
			L4Info: []v1alpha1.Port{
				{
					Protocol: &protocolTCP,
					Port:     &port80,
				},
			},
		},
	}

	sampleIngressPgmInfo := goelf.BpfData{
		Maps: map[string]goebpfmaps.BpfMap{
			TC_INGRESS_MAP: {
				MapFD: uint32(ingressMapFD),
				MapID: uint32(ingressMapID),
			},
		},
	}
	sampleEgressPgmInfo := goelf.BpfData{
		Maps: map[string]goebpfmaps.BpfMap{
			TC_EGRESS_MAP: {
				MapFD: uint32(egressMapFD),
				MapID: uint32(egressMapID),
			},
		},
	}

	tests := []struct {
		name                 string
		podIdentifier        string
		ingressFirewallRules []EbpfFirewallRules
		egressFirewallRules  []EbpfFirewallRules
		wantErr              error
	}{
		{
			name:                 "Sample Map Update",
			ingressFirewallRules: sampleIngressFirewalls,
			egressFirewallRules:  sampleEgressFirewalls,
			wantErr:              nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testBpfClient := &bpfClient{
				nodeIP:                    "10.1.1.1",
				logger:                    logr.New(&log.NullLogSink{}),
				enableIPv6:                false,
				hostMask:                  "/32",
				policyEndpointeBPFContext: new(sync.Map),
			}

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockMapClient := mock_bpfmaps.NewMockBpfMapAPIs(ctrl)
			mockMapClient.EXPECT().BulkRefreshMapEntries(gomock.Any()).AnyTimes()

			sampleBPFContext := BPFContext{
				ingressPgmInfo: sampleIngressPgmInfo,
				egressPgmInfo:  sampleEgressPgmInfo,
			}
			testBpfClient.policyEndpointeBPFContext.Store(tt.podIdentifier, sampleBPFContext)
			gotErr := testBpfClient.UpdateEbpfMaps(tt.podIdentifier, tt.ingressFirewallRules,
				tt.egressFirewallRules)
			assert.Equal(t, gotErr, tt.wantErr)
		})
	}
}

func TestBpfClient_UpdatePodStateEbpfMaps(t *testing.T) {
	ingressPodStateMapFD, ingressPodStateMapID, egressPodStateMapFD, egressPodStateMapID := 11, 12, 13, 14

	sampleIngressPgmInfo := goelf.BpfData{
		Maps: map[string]goebpfmaps.BpfMap{
			TC_INGRESS_POD_STATE_MAP: {
				MapFD: uint32(ingressPodStateMapFD),
				MapID: uint32(ingressPodStateMapID),
			},
		},
	}
	sampleEgressPgmInfo := goelf.BpfData{
		Maps: map[string]goebpfmaps.BpfMap{
			TC_EGRESS_POD_STATE_MAP: {
				MapFD: uint32(egressPodStateMapFD),
				MapID: uint32(egressPodStateMapID),
			},
		},
	}

	tests := []struct {
		name          string
		podIdentifier string
		state         int
		wantErr       error
	}{
		{
			name:          "Sample Pod State Map Update",
			podIdentifier: "sample_pod_identifier",
			state:         DEFAULT_ALLOW,
			wantErr:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testBpfClient := &bpfClient{
				nodeIP:                    "10.1.1.1",
				logger:                    logr.New(&log.NullLogSink{}),
				enableIPv6:                false,
				hostMask:                  "/32",
				policyEndpointeBPFContext: new(sync.Map),
			}

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockMapClient := mock_bpfmaps.NewMockBpfMapAPIs(ctrl)
			mockMapClient.EXPECT().CreateUpdateMapEntry(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

			sampleBPFContext := BPFContext{
				ingressPgmInfo: sampleIngressPgmInfo,
				egressPgmInfo:  sampleEgressPgmInfo,
			}
			testBpfClient.policyEndpointeBPFContext.Store(tt.podIdentifier, sampleBPFContext)
			gotErr := testBpfClient.UpdatePodStateEbpfMaps(tt.podIdentifier, tt.state, true, true)
			assert.Equal(t, gotErr, tt.wantErr)
		})
	}
}

func TestCheckAndUpdateBPFBinaries(t *testing.T) {
	testBpfBinaries := []string{TC_INGRESS_BINARY, TC_EGRESS_BINARY, EVENTS_BINARY}

	type want struct {
		updateIngressProbe bool
		updateEgressProbe  bool
		updateEventsProbe  bool
	}

	tests := []struct {
		name           string
		bpfBinaries    []string
		hostBinaryPath string
		want           want
		wantErr        error
	}{
		{
			name:           "No change in binaries",
			bpfBinaries:    testBpfBinaries,
			hostBinaryPath: "./test_files/same_files/",
			want: want{
				updateIngressProbe: false,
				updateEgressProbe:  false,
				updateEventsProbe:  false,
			},
			wantErr: nil,
		},
		/*
			{
				name:           "Change in Ingress binary",
				bpfBinaries:    testBpfBinaries,
				hostBinaryPath: "./pkg/ebpf/test_files/diff_files/",
				want: want{
					updateIngressProbe: true,
					updateEgressProbe:  true,
					updateEventsProbe:  false,
				},
				wantErr: nil,
			},
		*/
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bpfTCClient := tc.New([]string{POD_VETH_PREFIX})
			gotUpdateIngressProbe, gotUpdateEgressProbe, gotUpdateEventsProbe, gotError := checkAndUpdateBPFBinaries(bpfTCClient, tt.bpfBinaries, tt.hostBinaryPath)
			assert.Equal(t, tt.want.updateIngressProbe, gotUpdateIngressProbe)
			assert.Equal(t, tt.want.updateEgressProbe, gotUpdateEgressProbe)
			assert.Equal(t, tt.want.updateEventsProbe, gotUpdateEventsProbe)
			assert.Equal(t, tt.wantErr, gotError)
		})
	}
}

func TestBpfClient_AttacheBPFProbes(t *testing.T) {
	sampleIngressPgmInfo := goelf.BpfData{
		Program: goebpfprogs.BpfProgram{
			ProgID: 2,
			ProgFD: 3,
		},
	}
	sampleEgressPgmInfo := goelf.BpfData{
		Program: goebpfprogs.BpfProgram{
			ProgID: 4,
			ProgFD: 5,
		},
	}

	testPod := types.NamespacedName{
		Name:      "testPod",
		Namespace: "testNS",
	}

	tests := []struct {
		name          string
		testPod       types.NamespacedName
		podIdentifier string
		wantErr       error
	}{
		{
			name:          "Ingress and Egress Attach - Existing probes",
			testPod:       testPod,
			podIdentifier: utils.GetPodIdentifier(testPod.Name, testPod.Namespace, logr.New(&log.NullLogSink{})),
			wantErr:       nil,
		},
		{
			name:    "Ingress and Egress Attach - New probes",
			testPod: testPod,
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockTCClient := mock_tc.NewMockBpfTc(ctrl)
		mockTCClient.EXPECT().TCIngressAttach(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
		mockTCClient.EXPECT().TCEgressAttach(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		mockBpfClient := mock_bpfclient.NewMockBpfSDKClient(ctrl)
		mockBpfClient.EXPECT().LoadBpfFile(gomock.Any(), gomock.Any()).AnyTimes()

		testBpfClient := &bpfClient{
			nodeIP:                    "10.1.1.1",
			logger:                    logr.New(&log.NullLogSink{}),
			enableIPv6:                false,
			hostMask:                  "/32",
			policyEndpointeBPFContext: new(sync.Map),
			bpfSDKClient:              mockBpfClient,
			bpfTCClient:               mockTCClient,
			IngressPodToProgMap:       new(sync.Map),
			EgressPodToProgMap:        new(sync.Map),
			IngressProgToPodsMap:      new(sync.Map),
			EgressProgToPodsMap:       new(sync.Map),
			AttachProbesToPodLock:     new(sync.Map),
		}

		sampleBPFContext := BPFContext{
			ingressPgmInfo: sampleIngressPgmInfo,
			egressPgmInfo:  sampleEgressPgmInfo,
		}
		testBpfClient.policyEndpointeBPFContext.Store(tt.podIdentifier, sampleBPFContext)

		utils.GetHostVethName = func(podName, podNamespace string, prefixes []string, logger logr.Logger) (string, error) {
			return "mockedveth0", nil
		}

		t.Run(tt.name, func(t *testing.T) {
			gotError := testBpfClient.AttacheBPFProbes(tt.testPod, tt.podIdentifier)
			assert.Equal(t, tt.wantErr, gotError)
		})
	}
}

func TestRecoverBPFState(t *testing.T) {
	sampleConntrackMap := goebpfmaps.BpfMap{
		MapFD: 2,
	}
	sampleEventsMap := goebpfmaps.BpfMap{
		MapFD: 3,
	}

	ConntrackandEventMaps := map[string]goebpfmaps.BpfMap{
		CONNTRACK_MAP_PIN_PATH:     sampleConntrackMap,
		POLICY_EVENTS_MAP_PIN_PATH: sampleEventsMap,
	}

	OnlyConntrackMap := map[string]goebpfmaps.BpfMap{
		CONNTRACK_MAP_PIN_PATH: sampleConntrackMap,
	}

	OnlyEventsMap := map[string]goebpfmaps.BpfMap{
		POLICY_EVENTS_MAP_PIN_PATH: sampleEventsMap,
	}

	type want struct {
		isConntrackMapPresent    bool
		isPolicyEventsMapPresent bool
		eventsMapFD              int
	}

	tests := []struct {
		name                      string
		policyEndpointeBPFContext *sync.Map
		currentGlobalMaps         map[string]goebpfmaps.BpfMap
		updateIngressProbe        bool
		updateEgressProbe         bool
		updateEventsProbe         bool
		want                      want
		wantErr                   error
	}{
		{
			name:               "Conntrack and Events map are already present",
			updateIngressProbe: false,
			updateEgressProbe:  false,
			updateEventsProbe:  false,
			currentGlobalMaps:  ConntrackandEventMaps,
			want: want{
				isPolicyEventsMapPresent: true,
				isConntrackMapPresent:    true,
				eventsMapFD:              3,
			},
			wantErr: nil,
		},
		{
			name:               "Conntrack Map present while Events map is missing",
			updateIngressProbe: false,
			updateEgressProbe:  false,
			updateEventsProbe:  false,
			currentGlobalMaps:  OnlyConntrackMap,
			want: want{
				isPolicyEventsMapPresent: false,
				isConntrackMapPresent:    true,
				eventsMapFD:              0,
			},
			wantErr: nil,
		},
		{
			name:               "Conntrack Map missing while Events map is present",
			updateIngressProbe: false,
			updateEgressProbe:  false,
			updateEventsProbe:  false,
			currentGlobalMaps:  OnlyEventsMap,
			want: want{
				isPolicyEventsMapPresent: true,
				isConntrackMapPresent:    false,
				eventsMapFD:              3,
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockBpfClient := mock_bpfclient.NewMockBpfSDKClient(ctrl)
		mockTCClient := mock_tc.NewMockBpfTc(ctrl)

		mockBpfClient.EXPECT().RecoverGlobalMaps().DoAndReturn(
			func() (map[string]goebpfmaps.BpfMap, error) {
				return tt.currentGlobalMaps, nil
			},
		).AnyTimes()
		mockBpfClient.EXPECT().RecoverAllBpfProgramsAndMaps().AnyTimes()

		policyEndpointeBPFContext := new(sync.Map)
		globapMaps := new(sync.Map)

		t.Run(tt.name, func(t *testing.T) {
			gotIsConntrackMapPresent, gotIsPolicyEventsMapPresent, gotEventsMapFD, _, _, gotError := recoverBPFState(mockTCClient, mockBpfClient, policyEndpointeBPFContext, globapMaps,
				tt.updateIngressProbe, tt.updateEgressProbe, tt.updateEventsProbe)
			assert.Equal(t, tt.want.isConntrackMapPresent, gotIsConntrackMapPresent)
			assert.Equal(t, tt.want.isPolicyEventsMapPresent, gotIsPolicyEventsMapPresent)
			assert.Equal(t, tt.want.eventsMapFD, gotEventsMapFD)
			assert.Equal(t, tt.wantErr, gotError)
		})
	}

}

func TestMergeDuplicateL4Info(t *testing.T) {
	type mergeDuplicatePortsTestCase struct {
		Name     string
		Ports    []v1alpha1.Port
		Expected []v1alpha1.Port
	}
	protocolTCP := corev1.ProtocolTCP
	protocolUDP := corev1.ProtocolUDP

	testCases := []mergeDuplicatePortsTestCase{
		{
			Name: "Merge Duplicate Ports with nil Protocol",
			Ports: []v1alpha1.Port{
				{Protocol: &protocolTCP, Port: Int32Ptr(80), EndPort: Int32Ptr(8080)},
				{Protocol: nil, Port: Int32Ptr(53), EndPort: Int32Ptr(53)},
				{Protocol: nil, Port: Int32Ptr(53), EndPort: Int32Ptr(53)},
				{Protocol: &protocolTCP, Port: Int32Ptr(80), EndPort: Int32Ptr(8080)},
				{Protocol: &protocolTCP, Port: Int32Ptr(8081), EndPort: Int32Ptr(8081)},
			},
			Expected: []v1alpha1.Port{
				{Protocol: &protocolTCP, Port: Int32Ptr(80), EndPort: Int32Ptr(8080)},
				{Protocol: nil, Port: Int32Ptr(53), EndPort: Int32Ptr(53)},
				{Protocol: &protocolTCP, Port: Int32Ptr(8081), EndPort: Int32Ptr(8081)},
			},
		},
		{
			Name: "Merge Duplicate Ports with nil EndPort",
			Ports: []v1alpha1.Port{
				{Protocol: &protocolUDP, Port: Int32Ptr(53), EndPort: nil},
				{Protocol: &protocolUDP, Port: Int32Ptr(53), EndPort: nil},
			},
			Expected: []v1alpha1.Port{
				{Protocol: &protocolUDP, Port: Int32Ptr(53), EndPort: nil},
			},
		},
		{
			Name: "Merge Duplicate Ports with nil Port",
			Ports: []v1alpha1.Port{
				{Protocol: &protocolTCP, Port: nil, EndPort: Int32Ptr(8080)},
				{Protocol: &protocolTCP, Port: nil, EndPort: Int32Ptr(8080)},
			},
			Expected: []v1alpha1.Port{
				{Protocol: &protocolTCP, Port: nil, EndPort: Int32Ptr(8080)},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			mergedPorts := mergeDuplicateL4Info(tc.Ports)
			assert.Equal(t, len(tc.Expected), len(mergedPorts))
		})
	}
}

func TestIsFirstPodInPodIdentifier(t *testing.T) {
	sampleIngressPgmInfo := goelf.BpfData{
		Program: goebpfprogs.BpfProgram{
			ProgID: 2,
			ProgFD: 3,
		},
	}
	sampleEgressPgmInfo := goelf.BpfData{
		Program: goebpfprogs.BpfProgram{
			ProgID: 4,
			ProgFD: 5,
		},
	}

	tests := []struct {
		name                    string
		podIdentifier           string
		isIngressPgmInfoPresent bool
		isEgressPgmInfoPresent  bool
		want                    bool
	}{
		{
			name:                    "PodIdentifier with existing maps",
			podIdentifier:           "foo-bar",
			isIngressPgmInfoPresent: true,
			isEgressPgmInfoPresent:  true,
			want:                    false,
		},
		{
			name:          "PodIdentifier without existing maps",
			podIdentifier: "foo-bar",
			want:          true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testBpfClient := &bpfClient{
				nodeIP:                    "10.1.1.1",
				logger:                    logr.New(&log.NullLogSink{}),
				enableIPv6:                false,
				hostMask:                  "/32",
				policyEndpointeBPFContext: new(sync.Map),
			}

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			if tt.isIngressPgmInfoPresent || tt.isEgressPgmInfoPresent {
				sampleBPFContext := BPFContext{
					ingressPgmInfo: sampleIngressPgmInfo,
					egressPgmInfo:  sampleEgressPgmInfo,
				}
				testBpfClient.policyEndpointeBPFContext.Store(tt.podIdentifier, sampleBPFContext)
			}
			gotIsMapUpdateRequired := testBpfClient.IsFirstPodInPodIdentifier(tt.podIdentifier)
			assert.Equal(t, tt.want, gotIsMapUpdateRequired)
		})
	}

}

func Int32Ptr(i int32) *int32 {
	return &i
}

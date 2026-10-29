package ebpf

import (
	"fmt"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	goelf "github.com/aws/aws-ebpf-sdk-go/pkg/elfparser"
	goebpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	goebpfprogs "github.com/aws/aws-ebpf-sdk-go/pkg/progs"
	"github.com/samber/lo"

	mock_bpfclient "github.com/aws/aws-ebpf-sdk-go/pkg/elfparser/mocks"
	mock_bpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps/mocks"
	"github.com/aws/aws-ebpf-sdk-go/pkg/tc"
	mock_tc "github.com/aws/aws-ebpf-sdk-go/pkg/tc/mocks"
	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	// "unsafe"
)

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
				hostMask:            "/32",
				ingressPodToProgMap: new(sync.Map),
				egressPodToProgMap:  new(sync.Map),
			}

			if tt.ingressAttached {
				podIdentifier := utils.GetPodNamespacedName(tt.podName, tt.podNamespace)
				testBpfClient.ingressPodToProgMap.Store(podIdentifier, ingressProgFD)
			}
			if tt.egressAttached {
				podIdentifier := utils.GetPodNamespacedName(tt.podName, tt.podNamespace)
				testBpfClient.egressPodToProgMap.Store(podIdentifier, egressProgFD)
			}
			gotIngress, gotEgress := testBpfClient.isEBPFProbeAttached(tt.podName, tt.podNamespace)
			assert.Equal(t, tt.want.ingress, gotIngress)
			assert.Equal(t, tt.want.egress, gotEgress)
		})
	}
}

// Pre-attach pod ("ab", "c") and verify pod ("a", "bc") does not inherit
// attachment state — the buggy raw concatenation aliased these to the same key.
func TestBpfClient_IsEBPFProbeAttached_NoCollisionAcrossPods(t *testing.T) {
	ingressProgFD, egressProgFD := 12, 13
	testBpfClient := &bpfClient{
		hostMask:            "/32",
		ingressPodToProgMap: new(sync.Map),
		egressPodToProgMap:  new(sync.Map),
	}

	// Pod A: ("ab", "c") is the first pod attached.
	attachedKey := utils.GetPodNamespacedName("ab", "c")
	testBpfClient.ingressPodToProgMap.Store(attachedKey, ingressProgFD)
	testBpfClient.egressPodToProgMap.Store(attachedKey, egressProgFD)

	// Pod B: ("a", "bc") arrives next; under the buggy concatenation both
	// pods produced key "abc" and Pod B inherited Pod A's attachment state.
	gotIngress, gotEgress := testBpfClient.isEBPFProbeAttached("a", "bc")
	assert.False(t, gotIngress, "pod (a, bc) must not see pod (ab, c)'s ingress attachment")
	assert.False(t, gotEgress, "pod (a, bc) must not see pod (ab, c)'s egress attachment")
}

func TestLoadBPFProgram(t *testing.T) {
	pinPath := utils.GetBPFPinPathFromPodIdentifier("test-abcd", "ingress")

	tests := []struct {
		name       string
		loadReturn map[string]goelf.BpfData
		wantErr    bool
		wantProgFD int
	}{
		{
			name: "success with associated maps",
			loadReturn: map[string]goelf.BpfData{
				pinPath: {
					Program: goebpfprogs.BpfProgram{ProgFD: 7},
					Maps: map[string]goebpfmaps.BpfMap{
						utils.TC_INGRESS_MAP:           {MapFD: 100},
						utils.TC_INGRESS_POD_STATE_MAP: {MapFD: 101},
					},
				},
			},
			wantErr:    false,
			wantProgFD: 7,
		},
		{
			name: "program loaded but no associated maps",
			loadReturn: map[string]goelf.BpfData{
				pinPath: {
					Program: goebpfprogs.BpfProgram{ProgFD: 7},
					Maps:    map[string]goebpfmaps.BpfMap{},
				},
			},
			wantErr: true,
		},
		{
			name: "program loaded with invalid FD",
			loadReturn: map[string]goelf.BpfData{
				pinPath: {
					Program: goebpfprogs.BpfProgram{ProgFD: 0},
					Maps: map[string]goebpfmaps.BpfMap{
						utils.TC_INGRESS_MAP: {MapFD: 100},
					},
				},
			},
			wantErr: true,
		},
		{
			name:       "no program data at pinPath",
			loadReturn: map[string]goelf.BpfData{},
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockBpfClient := mock_bpfclient.NewMockBpfSDKClient(ctrl)
			testBpfClient := &bpfClient{
				bpfSDKClient: mockBpfClient,
			}

			mockBpfClient.EXPECT().LoadBpfFile(gomock.Any(), gomock.Any()).Return(
				tt.loadReturn, map[string]goebpfmaps.BpfMap{}, nil).Times(1)

			_, gotProgFD, gotErr := testBpfClient.loadBPFProgram("handle_ingress", "ingress", "test-abcd")
			if tt.wantErr {
				assert.Error(t, gotErr)
			} else {
				assert.NoError(t, gotErr)
				assert.Equal(t, tt.wantProgFD, gotProgFD)
			}
		})
	}
}

func TestBpfClient_UpdateEbpfMaps(t *testing.T) {
	protocolTCP := corev1.ProtocolTCP
	var port80 int32 = 80
	ingressMapFD, ingressMapID, egressMapFD, egressMapID := 11, 12, 13, 14

	sampleIngressFirewalls := []fwrp.EbpfFirewallRules{
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

	sampleEgressFirewalls := []fwrp.EbpfFirewallRules{
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
			utils.TC_INGRESS_MAP: {
				MapFD: uint32(ingressMapFD),
				MapID: uint32(ingressMapID),
			},
		},
	}
	sampleEgressPgmInfo := goelf.BpfData{
		Maps: map[string]goebpfmaps.BpfMap{
			utils.TC_EGRESS_MAP: {
				MapFD: uint32(egressMapFD),
				MapID: uint32(egressMapID),
			},
		},
	}

	tests := []struct {
		name                 string
		podIdentifier        string
		ingressFirewallRules []fwrp.EbpfFirewallRules
		egressFirewallRules  []fwrp.EbpfFirewallRules
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
				hostMask:                  "/32",
				fwRuleProcessor:           fwrp.NewFirewallRuleProcessor("10.1.1.1", "/32", false),
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
			utils.TC_INGRESS_POD_STATE_MAP: {
				MapFD: uint32(ingressPodStateMapFD),
				MapID: uint32(ingressPodStateMapID),
			},
		},
	}
	sampleEgressPgmInfo := goelf.BpfData{
		Maps: map[string]goebpfmaps.BpfMap{
			utils.TC_EGRESS_POD_STATE_MAP: {
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
			gotErr := testBpfClient.UpdatePodStateEbpfMaps(tt.podIdentifier, POD_STATE_MAP_KEY, tt.state, true, true)
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
		name              string
		testPod           types.NamespacedName
		podIdentifier     string
		numInterfaces     int
		isMultiNICEnabled bool
		wantErr           error
		wantTCAttachCalls int
	}{
		{
			name:              "Single interface - existing probes",
			testPod:           testPod,
			podIdentifier:     utils.GetPodIdentifier(testPod.Name, testPod.Namespace),
			numInterfaces:     1,
			isMultiNICEnabled: false,
			wantErr:           nil,
			wantTCAttachCalls: 2,
		},
		{
			name:              "Multiple interfaces - 3 interfaces",
			testPod:           testPod,
			podIdentifier:     "test-pod-multi",
			numInterfaces:     3,
			isMultiNICEnabled: true,
			wantErr:           nil,
			wantTCAttachCalls: 6,
		},
		{
			name:              "Multi-NIC enabled but no interface count",
			testPod:           testPod,
			podIdentifier:     "test-pod-skip",
			numInterfaces:     0,
			isMultiNICEnabled: true,
			wantErr:           ErrProbeAttachSkipped,
			wantTCAttachCalls: 0,
		},
		{
			name:              "Multi-NIC disabled defaults to single interface",
			testPod:           testPod,
			podIdentifier:     "test-pod-default",
			numInterfaces:     0,
			isMultiNICEnabled: false,
			wantErr:           nil,
			wantTCAttachCalls: 2,
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
			hostMask:                  "/32",
			policyEndpointeBPFContext: new(sync.Map),
			bpfSDKClient:              mockBpfClient,
			bpfTCClient:               mockTCClient,
			ingressPodToProgMap:       new(sync.Map),
			egressPodToProgMap:        new(sync.Map),
			ingressProgToPodsMap:      new(sync.Map),
			egressProgToPodsMap:       new(sync.Map),
			deletedPods:               new(sync.Map),
		}

		sampleBPFContext := BPFContext{
			ingressPgmInfo: sampleIngressPgmInfo,
			egressPgmInfo:  sampleEgressPgmInfo,
		}
		testBpfClient.policyEndpointeBPFContext.Store(tt.podIdentifier, sampleBPFContext)

		utils.GetHostVethName = func(podName, podNamespace string, interfaceIndex int, interfacePrefixes []string) (string, error) {
			return "mockedveth0", nil
		}

		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockTCClient := mock_tc.NewMockBpfTc(ctrl)
			mockTCClient.EXPECT().TCIngressAttach(gomock.Any(), gomock.Any(), gomock.Any()).Times(tt.wantTCAttachCalls / 2)
			mockTCClient.EXPECT().TCEgressAttach(gomock.Any(), gomock.Any(), gomock.Any()).Times(tt.wantTCAttachCalls / 2)

			mockBpfClient := mock_bpfclient.NewMockBpfSDKClient(ctrl)
			mockBpfClient.EXPECT().LoadBpfFile(gomock.Any(), gomock.Any()).AnyTimes()

			testBpfClient := &bpfClient{
				hostMask:                  "/32",
				policyEndpointeBPFContext: new(sync.Map),
				bpfSDKClient:              mockBpfClient,
				bpfTCClient:               mockTCClient,
				ingressPodToProgMap:       new(sync.Map),
				egressPodToProgMap:        new(sync.Map),
				ingressProgToPodsMap:      new(sync.Map),
				egressProgToPodsMap:       new(sync.Map),
				isMultiNICEnabled:         tt.isMultiNICEnabled,
				podNameToInterfaceCount:   new(sync.Map),
				deletedPods:               new(sync.Map),
			}

			sampleBPFContext := BPFContext{
				ingressPgmInfo: sampleIngressPgmInfo,
				egressPgmInfo:  sampleEgressPgmInfo,
			}
			testBpfClient.policyEndpointeBPFContext.Store(tt.podIdentifier, sampleBPFContext)

			utils.GetHostVethName = func(podName, podNamespace string, interfaceIndex int, interfacePrefixes []string) (string, error) {
				return fmt.Sprintf("mockedveth%d", interfaceIndex), nil
			}

			_, gotError := testBpfClient.AttacheBPFProbes(tt.testPod, tt.podIdentifier, tt.numInterfaces, false)
			assert.ErrorIs(t, gotError, tt.wantErr)
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

	ProgramAndMap := map[string]goelf.BpfData{
		"/sys/fs/bpf/globals/aws/programs/hello-udp-748dc8d996-default_handle_ingress": {
			Program: goebpfprogs.BpfProgram{
				ProgFD: 1,
			},
			Maps: make(map[string]goebpfmaps.BpfMap),
		},
		"/sys/fs/bpf/globals/aws/programs/hello-udp-748dc8d996-default_handle_egress": {
			Program: goebpfprogs.BpfProgram{
				ProgFD: 2,
			},
			Maps: make(map[string]goebpfmaps.BpfMap),
		},
	}

	type bpfContextValidation struct {
		ingressProbeFd int
		egressProbeFd  int
	}

	type want struct {
		isConntrackMapPresent    bool
		isPolicyEventsMapPresent bool
		eventsMapFD              int
		bpfContextCount          int
		bpfContextValidation     map[string]bpfContextValidation
	}

	tests := []struct {
		name                      string
		policyEndpointeBPFContext *sync.Map
		currentGlobalMaps         map[string]goebpfmaps.BpfMap
		currentProgramAndMap      map[string]goelf.BpfData
		updateIngressProbe        bool
		updateEgressProbe         bool
		updateEventsProbe         bool
		want                      want
		wantErr                   error
	}{
		{
			name:                 "Conntrack and Events map are already present",
			updateIngressProbe:   false,
			updateEgressProbe:    false,
			updateEventsProbe:    false,
			currentGlobalMaps:    ConntrackandEventMaps,
			currentProgramAndMap: ProgramAndMap,
			want: want{
				isPolicyEventsMapPresent: true,
				isConntrackMapPresent:    true,
				eventsMapFD:              3,
				bpfContextCount:          1,
			},
			wantErr: nil,
		},
		{
			name:                 "Conntrack Map present while Events map is missing",
			updateIngressProbe:   false,
			updateEgressProbe:    false,
			updateEventsProbe:    false,
			currentGlobalMaps:    OnlyConntrackMap,
			currentProgramAndMap: ProgramAndMap,
			want: want{
				isPolicyEventsMapPresent: false,
				isConntrackMapPresent:    true,
				eventsMapFD:              0,
				bpfContextCount:          1,
			},
			wantErr: nil,
		},
		{
			name:                 "Conntrack Map missing while Events map is present",
			updateIngressProbe:   false,
			updateEgressProbe:    false,
			updateEventsProbe:    false,
			currentGlobalMaps:    OnlyEventsMap,
			currentProgramAndMap: ProgramAndMap,
			want: want{
				isPolicyEventsMapPresent: true,
				isConntrackMapPresent:    false,
				eventsMapFD:              3,
				bpfContextCount:          1,
			},
			wantErr: nil,
		},
		{
			name:               "Prevent BpfContext mangling",
			updateIngressProbe: false,
			updateEgressProbe:  false,
			updateEventsProbe:  false,
			currentGlobalMaps:  ConntrackandEventMaps,
			currentProgramAndMap: lo.Assign(
				ProgramAndMap,
				map[string]goelf.BpfData{
					"/sys/fs/bpf/globals/aws/programs/hello-udp-1234-default_handle_ingress": {
						Program: goebpfprogs.BpfProgram{
							ProgFD: 3,
						},
						Maps: make(map[string]goebpfmaps.BpfMap),
					},
				},
			),
			want: want{
				isPolicyEventsMapPresent: true,
				isConntrackMapPresent:    true,
				eventsMapFD:              3,
				bpfContextCount:          2,
				bpfContextValidation: map[string]bpfContextValidation{
					"hello-udp-748dc8d996-default": {
						ingressProbeFd: 1,
						egressProbeFd:  2,
					},
					"hello-udp-1234-default": {
						ingressProbeFd: 3,
						egressProbeFd:  0,
					},
				},
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
		mockBpfClient.EXPECT().RecoverAllBpfProgramsAndMaps().DoAndReturn(
			func() (map[string]goelf.BpfData, error) {
				return tt.currentProgramAndMap, nil
			},
		).AnyTimes()

		t.Run(tt.name, func(t *testing.T) {
			policyEndpointeBPFContext := new(sync.Map)
			globapMaps := new(sync.Map)
			gotIsConntrackMapPresent, gotIsPolicyEventsMapPresent, gotEventsMapFD, _, _, gotError := NewMockBpfClient().recoverBPFState(mockTCClient, mockBpfClient, policyEndpointeBPFContext, globapMaps,
				tt.updateIngressProbe, tt.updateEgressProbe, tt.updateEventsProbe)
			assert.Equal(t, tt.want.isConntrackMapPresent, gotIsConntrackMapPresent)
			assert.Equal(t, tt.want.isPolicyEventsMapPresent, gotIsPolicyEventsMapPresent)
			assert.Equal(t, tt.want.eventsMapFD, gotEventsMapFD)
			assert.Equal(t, tt.wantErr, gotError)
			assert.Equal(t, tt.want.bpfContextCount, sizeOfSyncMap(policyEndpointeBPFContext))

			if tt.want.bpfContextValidation != nil {
				for k, v := range tt.want.bpfContextValidation {
					context, ok := policyEndpointeBPFContext.Load(k)
					assert.True(t, ok)
					assert.Equal(t, v.ingressProbeFd, context.(BPFContext).ingressPgmInfo.Program.ProgFD)
					assert.Equal(t, v.egressProbeFd, context.(BPFContext).egressPgmInfo.Program.ProgFD)
				}
			}
		})
	}

}

func sizeOfSyncMap(m *sync.Map) int {
	count := 0
	m.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}

func TestIsFirstPodInPodIdentifierLocked(t *testing.T) {
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
			gotIsMapUpdateRequired := testBpfClient.isFirstPodInPodIdentifierLocked(tt.podIdentifier)
			assert.Equal(t, tt.want, gotIsMapUpdateRequired)
		})
	}

}

func TestBpfClient_getInterfaceCountForPod(t *testing.T) {
	testPod := types.NamespacedName{
		Name:      "testPod",
		Namespace: "testNS",
	}

	tests := []struct {
		name                        string
		providedCount               int
		isMultiNICEnabled           bool
		podNameToInterfaceCountData map[string]int
		wantCount                   int
		wantErr                     error
	}{
		{
			name:          "Provided count takes precedence",
			providedCount: 3,
			wantCount:     3,
			wantErr:       nil,
		},
		{
			name:              "Multi-NIC disabled defaults to 1",
			providedCount:     0,
			isMultiNICEnabled: false,
			wantCount:         1,
			wantErr:           nil,
		},
		{
			name:                        "Multi-NIC enabled with IPAM cache data",
			providedCount:               0,
			isMultiNICEnabled:           true,
			podNameToInterfaceCountData: map[string]int{"testPod_testNS": 2},
			wantCount:                   2,
			wantErr:                     nil,
		},
		{
			name:              "Multi-NIC enabled without data returns skip error",
			providedCount:     0,
			isMultiNICEnabled: true,
			wantCount:         0,
			wantErr:           ErrProbeAttachSkipped,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testBpfClient := &bpfClient{
				isMultiNICEnabled:       tt.isMultiNICEnabled,
				podNameToInterfaceCount: new(sync.Map),
			}

			for key, count := range tt.podNameToInterfaceCountData {
				testBpfClient.podNameToInterfaceCount.Store(key, count)
			}

			gotCount, gotErr := testBpfClient.getInterfaceCountForPod(testPod, "test-pod-id", tt.providedCount)
			assert.Equal(t, tt.wantCount, gotCount)
			assert.ErrorIs(t, gotErr, tt.wantErr)
		})
	}
}

func TestBpfClient_AttacheBPFProbes_MultipleInterfacesFlow(t *testing.T) {
	testPod := types.NamespacedName{
		Name:      "multi-nic-pod",
		Namespace: "default",
	}
	podIdentifier := "multi-nic-pod-default"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockTCClient := mock_tc.NewMockBpfTc(ctrl)
	mockTCClient.EXPECT().TCIngressAttach("mockedveth0", gomock.Any(), gomock.Any()).Times(1)
	mockTCClient.EXPECT().TCEgressAttach("mockedveth0", gomock.Any(), gomock.Any()).Times(1)
	mockTCClient.EXPECT().TCIngressAttach("mockedveth1", gomock.Any(), gomock.Any()).Times(1)
	mockTCClient.EXPECT().TCEgressAttach("mockedveth1", gomock.Any(), gomock.Any()).Times(1)

	mockBpfClient := mock_bpfclient.NewMockBpfSDKClient(ctrl)
	mockBpfClient.EXPECT().LoadBpfFile(gomock.Any(), gomock.Any()).Return(
		map[string]goelf.BpfData{
			"/sys/fs/bpf/globals/aws/programs/multi-nic-pod-default_handle_ingress": {
				Program: goebpfprogs.BpfProgram{ProgFD: 10},
				Maps: map[string]goebpfmaps.BpfMap{
					utils.TC_INGRESS_MAP:           {MapFD: 100},
					utils.TC_INGRESS_POD_STATE_MAP: {MapFD: 101},
				},
			},
		},
		map[string]goebpfmaps.BpfMap{},
		nil,
	).Times(1)
	mockBpfClient.EXPECT().LoadBpfFile(gomock.Any(), gomock.Any()).Return(
		map[string]goelf.BpfData{
			"/sys/fs/bpf/globals/aws/programs/multi-nic-pod-default_handle_egress": {
				Program: goebpfprogs.BpfProgram{ProgFD: 11},
				Maps: map[string]goebpfmaps.BpfMap{
					utils.TC_EGRESS_MAP:           {MapFD: 110},
					utils.TC_EGRESS_POD_STATE_MAP: {MapFD: 111},
				},
			},
		},
		map[string]goebpfmaps.BpfMap{},
		nil,
	).Times(1)

	testBpfClient := &bpfClient{
		hostMask:                  "/32",
		policyEndpointeBPFContext: new(sync.Map),
		bpfSDKClient:              mockBpfClient,
		bpfTCClient:               mockTCClient,
		ingressPodToProgMap:       new(sync.Map),
		egressPodToProgMap:        new(sync.Map),
		ingressProgToPodsMap:      new(sync.Map),
		egressProgToPodsMap:       new(sync.Map),
		isMultiNICEnabled:         true,
		ingressBinary:             "tc.v4ingress.bpf.o",
		egressBinary:              "tc.v4egress.bpf.o",
		deletedPods:               new(sync.Map),
	}

	utils.GetHostVethName = func(podName, podNamespace string, interfaceIndex int, interfacePrefixes []string) (string, error) {
		return fmt.Sprintf("mockedveth%d", interfaceIndex), nil
	}

	_, err := testBpfClient.AttacheBPFProbes(testPod, podIdentifier, 2, false)
	assert.NoError(t, err)

	podNamespacedName := utils.GetPodNamespacedName(testPod.Name, testPod.Namespace)
	_, ingressExists := testBpfClient.ingressPodToProgMap.Load(podNamespacedName)
	_, egressExists := testBpfClient.egressPodToProgMap.Load(podNamespacedName)
	assert.True(t, ingressExists)
	assert.True(t, egressExists)
}

func TestBpfClient_loadIPAMData(t *testing.T) {
	tests := []struct {
		name       string
		ipamData   string
		wantErr    bool
		wantCached map[string]int
	}{
		{
			name: "Valid IPAM data",
			ipamData: `{
				"allocations": [
					{
						"metadata": {
							"k8sPodName": "test-pod",
							"k8sPodNamespace": "default",
							"interfacesCount": 2
						}
					},
					{
						"metadata": {
							"k8sPodName": "multi-pod",
							"k8sPodNamespace": "kube-system",
							"interfacesCount": 3
						}
					}
				]
			}`,
			wantErr: false,
			wantCached: map[string]int{
				"test-pod_default":      2,
				"multi-pod_kube-system": 3,
			},
		},
		{
			name:     "Invalid JSON",
			ipamData: `{invalid json}`,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "ipam-test-*.json")
			assert.NoError(t, err)
			defer os.Remove(tmpFile.Name())

			_, err = tmpFile.WriteString(tt.ipamData)
			assert.NoError(t, err)
			tmpFile.Close()

			testBpfClient := &bpfClient{
				podNameToInterfaceCount: new(sync.Map),
			}

			err = testBpfClient.loadIPAMDataFromFile(tmpFile.Name())
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				for key, expectedCount := range tt.wantCached {
					count, ok := testBpfClient.podNameToInterfaceCount.Load(key)
					assert.True(t, ok)
					assert.Equal(t, expectedCount, count)
				}
			}
		})
	}
}

func TestBpfClient_getInterfaceCountFromBackupFile(t *testing.T) {
	testPod := types.NamespacedName{
		Name:      "test-pod",
		Namespace: "default",
	}

	tests := []struct {
		name      string
		cacheData map[string]int
		wantCount int
		wantErr   bool
	}{
		{
			name:      "Interface count found in cache",
			cacheData: map[string]int{"test-pod_default": 2},
			wantCount: 2,
			wantErr:   false,
		},
		{
			name:      "Interface count not found in cache",
			cacheData: map[string]int{},
			wantCount: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testBpfClient := &bpfClient{
				podNameToInterfaceCount: new(sync.Map),
			}

			for key, count := range tt.cacheData {
				testBpfClient.podNameToInterfaceCount.Store(key, count)
			}

			gotCount, gotErr := testBpfClient.getInterfaceCountFromBackupFile(testPod, "test-pod-id")
			assert.Equal(t, tt.wantCount, gotCount)
			if tt.wantErr {
				assert.Error(t, gotErr)
			} else {
				assert.NoError(t, gotErr)
			}
		})
	}
}

func Int32Ptr(i int32) *int32 {
	return &i
}

func TestIsProgFdShared(t *testing.T) {
	type want struct {
		isProgFdShared bool
	}
	podToProgFd := map[string]int{
		"pod1_A": 2,
		"pod2_A": 2,
		"pod1_B": 15,
	}
	tests := []struct {
		name         string
		podName      string
		podNamespace string
		want         want
		wantErr      error
	}{
		{
			name:         "ProgFD Shared",
			podName:      "pod1",
			podNamespace: "A",
			want: want{
				isProgFdShared: true,
			},
			wantErr: nil,
		},
		{
			name:         "ProgFD Not Shared",
			podName:      "pod1",
			podNamespace: "B",
			want: want{
				isProgFdShared: false,
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testBpfClient := &bpfClient{
				ingressPodToProgMap:  new(sync.Map),
				egressPodToProgMap:   new(sync.Map),
				ingressProgToPodsMap: new(sync.Map),
				egressProgToPodsMap:  new(sync.Map),
			}

			// Set up test data
			for pod, progFd := range podToProgFd {
				testBpfClient.ingressPodToProgMap.Store(pod, progFd)
				currentPodSet, _ := testBpfClient.ingressProgToPodsMap.LoadOrStore(progFd, make(map[string]struct{}))
				currentPodSet.(map[string]struct{})[pod] = struct{}{}
			}

			isProgFdShared, _ := testBpfClient.isProgFdShared(tt.podName, tt.podNamespace)
			assert.Equal(t, tt.want.isProgFdShared, isProgFdShared)
		})
	}
}

func TestAttacheBPFProbes_SkipsDeletedPod(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockTCClient := mock_tc.NewMockBpfTc(ctrl)
	mockTCClient.EXPECT().TCIngressAttach(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
	mockTCClient.EXPECT().TCEgressAttach(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

	testBpfClient := &bpfClient{
		deletedPods: new(sync.Map),
		bpfTCClient: mockTCClient,
	}

	pod := types.NamespacedName{Name: "nginx-abc123", Namespace: "default"}
	testBpfClient.deletedPods.Store(utils.GetPodNamespacedName(pod.Name, pod.Namespace), time.Now())

	_, err := testBpfClient.AttacheBPFProbes(pod, utils.GetPodIdentifier(pod.Name, pod.Namespace), 1, false)
	assert.NoError(t, err)
}

func TestAttacheBPFProbes_ConfirmedLiveClearsDeletedMarker(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockTCClient := mock_tc.NewMockBpfTc(ctrl)
	mockTCClient.EXPECT().TCIngressAttach(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mockTCClient.EXPECT().TCEgressAttach(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)

	mockBpfSDK := mock_bpfclient.NewMockBpfSDKClient(ctrl)
	mockBpfSDK.EXPECT().LoadBpfFile(gomock.Any(), gomock.Any()).AnyTimes()

	pod := types.NamespacedName{Name: "nginx-abc123", Namespace: "default"}
	podIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
	podNamespacedName := utils.GetPodNamespacedName(pod.Name, pod.Namespace)

	testBpfClient := &bpfClient{
		hostMask:                  "/32",
		policyEndpointeBPFContext: new(sync.Map),
		bpfSDKClient:              mockBpfSDK,
		bpfTCClient:               mockTCClient,
		ingressPodToProgMap:       new(sync.Map),
		egressPodToProgMap:        new(sync.Map),
		ingressProgToPodsMap:      new(sync.Map),
		egressProgToPodsMap:       new(sync.Map),
		deletedPods:               new(sync.Map),
	}
	testBpfClient.policyEndpointeBPFContext.Store(podIdentifier, BPFContext{
		ingressPgmInfo: goelf.BpfData{Program: goebpfprogs.BpfProgram{ProgID: 2, ProgFD: 3}},
		egressPgmInfo:  goelf.BpfData{Program: goebpfprogs.BpfProgram{ProgID: 4, ProgFD: 5}},
	})
	utils.GetHostVethName = func(_, _ string, _ int, _ []string) (string, error) {
		return "mockedveth0", nil
	}

	// CNI DEL of the previous pod with this name, then CNI ADD of the new one
	testBpfClient.deletedPods.Store(podNamespacedName, time.Now())

	_, err := testBpfClient.AttacheBPFProbes(pod, podIdentifier, 1, true)
	assert.NoError(t, err)

	_, attached := testBpfClient.ingressPodToProgMap.Load(podNamespacedName)
	assert.True(t, attached)
	_, stillMarked := testBpfClient.deletedPods.Load(podNamespacedName)
	assert.False(t, stillMarked)
}

func TestDeleteBPFProbes_AddsPodToDeletedMap(t *testing.T) {
	testBpfClient := &bpfClient{
		ingressPodToProgMap:  new(sync.Map),
		egressPodToProgMap:   new(sync.Map),
		ingressProgToPodsMap: new(sync.Map),
		egressProgToPodsMap:  new(sync.Map),
		deletedPods:          new(sync.Map),
	}

	pod := types.NamespacedName{Name: "nginx-xyz789", Namespace: "production"}
	_ = testBpfClient.DeleteBPFProbes(pod, utils.GetPodIdentifier(pod.Name, pod.Namespace))

	val, exists := testBpfClient.deletedPods.Load(utils.GetPodNamespacedName(pod.Name, pod.Namespace))
	assert.True(t, exists)
	_, isTime := val.(time.Time)
	assert.True(t, isTime)
}

func TestCleanupDeletedPodsIfNeeded(t *testing.T) {
	testBpfClient := &bpfClient{
		deletedPods: new(sync.Map),
	}

	now := time.Now()
	for i := 0; i <= 500; i++ {
		age := -10 * time.Minute // old
		if i > 100 {
			age = -1 * time.Minute // recent
		}
		testBpfClient.deletedPods.Store(fmt.Sprintf("pod-%d-ns", i), now.Add(age))
	}

	testBpfClient.cleanupDeletedPodsIfNeeded()

	remaining := 0
	testBpfClient.deletedPods.Range(func(_, _ any) bool {
		remaining++
		return true
	})
	assert.Equal(t, 400, remaining)
}

// newRaceTestBpfClient returns a bpfClient wired for exercising per-podIdentifier
// state without a kernel. Shadow maps are pre-seeded with the entries an empty
// rule set computes to, so BulkRefresh never issues a map syscall.
func newRaceTestBpfClient(t *testing.T) (*bpfClient, map[string][]byte) {
	t.Helper()
	fwRuleProcessor := fwrp.NewFirewallRuleProcessor("10.1.1.1", "/32", false)
	seed, err := fwRuleProcessor.ComputeMapEntriesFromEndpointRules(nil)
	assert.NoError(t, err)
	client := &bpfClient{
		hostMask:                        "/32",
		fwRuleProcessor:                 fwRuleProcessor,
		policyEndpointeBPFContext:       new(sync.Map),
		ingressPodToProgMap:             new(sync.Map),
		egressPodToProgMap:              new(sync.Map),
		ingressProgToPodsMap:            new(sync.Map),
		egressProgToPodsMap:             new(sync.Map),
		ingressInMemoryMap:              new(sync.Map),
		egressInMemoryMap:               new(sync.Map),
		clusterPolicyIngressInMemoryMap: new(sync.Map),
		clusterPolicyEgressInMemoryMap:  new(sync.Map),
		deletedPods:                     new(sync.Map),
	}
	return client, seed
}

// seededShadowMap builds shadow maps preloaded with a copy of seed, standing in
// for a kernel read.
func seededShadowMap(seed map[string][]byte) func(*goebpfmaps.BpfMap) (*InMemoryBpfMap, error) {
	return func(bpfMap *goebpfmaps.BpfMap) (*InMemoryBpfMap, error) {
		contents := make(map[string][]byte, len(seed))
		for k, v := range seed {
			contents[k] = v
		}
		return &InMemoryBpfMap{bpfMap: bpfMap, contents: contents}, nil
	}
}

// lockWaiters reports how many goroutines hold or wait on podIdentifier's lock.
func lockWaiters(client *bpfClient, podIdentifier string) int {
	client.podIdentifierLocks.mu.Lock()
	defer client.podIdentifierLocks.mu.Unlock()
	if m := client.podIdentifierLocks.locks[podIdentifier]; m != nil {
		return m.refs
	}
	return 0
}

// receiveWithin returns the next value from ch, failing the test if none
// arrives within a second, e.g. because the sending goroutine was stopped by a
// mock expectation failure.
func receiveWithin[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(time.Second):
		t.Fatal("no result within a second")
		var zero T
		return zero
	}
}

// disposableFD returns a descriptor the test owns, for program handles that
// real teardown code will close: DeleteBPFProbes unpins and closes the
// program FDs it finds in the context, so a made-up number could close an
// unrelated descriptor of the test process.
func disposableFD(t *testing.T) int {
	t.Helper()
	fd, err := syscall.Open(os.DevNull, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	return fd
}

// seedLastPodOfIdentifier records podKey as the only pod using
// podIdentifier's programs, as after that pod's CNI ADD. The program FDs are
// test-owned so the DeleteBPFProbes teardown can close them.
func seedLastPodOfIdentifier(t *testing.T, client *bpfClient, podIdentifier, podKey string, ingressMapID, egressMapID int) {
	t.Helper()
	ingressProgFD, egressProgFD := disposableFD(t), disposableFD(t)
	client.policyEndpointeBPFContext.Store(podIdentifier, raceTestBPFContext(ingressProgFD, ingressMapID, egressProgFD, egressMapID))
	client.ingressPodToProgMap.Store(podKey, ingressProgFD)
	client.ingressProgToPodsMap.Store(ingressProgFD, map[string]struct{}{podKey: {}})
	client.egressPodToProgMap.Store(podKey, egressProgFD)
	client.egressProgToPodsMap.Store(egressProgFD, map[string]struct{}{podKey: {}})
}

func raceTestBPFContext(ingressProgFD, ingressMapID, egressProgFD, egressMapID int) BPFContext {
	return BPFContext{
		ingressPgmInfo: goelf.BpfData{
			Program: goebpfprogs.BpfProgram{ProgFD: ingressProgFD},
			Maps:    map[string]goebpfmaps.BpfMap{utils.TC_INGRESS_MAP: {MapID: uint32(ingressMapID)}},
		},
		egressPgmInfo: goelf.BpfData{
			Program: goebpfprogs.BpfProgram{ProgFD: egressProgFD},
			Maps:    map[string]goebpfmaps.BpfMap{utils.TC_EGRESS_MAP: {MapID: uint32(egressMapID)}},
		},
	}
}

func cachedMapID(t *testing.T, cache *sync.Map, podIdentifier string) uint32 {
	t.Helper()
	value, ok := cache.Load(podIdentifier)
	if !assert.True(t, ok, "no shadow map cached for %s", podIdentifier) {
		return 0
	}
	return value.(*InMemoryBpfMap).GetUnderlyingMap().MapID
}

// Issue #676: a PolicyEndpoint reconcile updating the maps of the last pod of a
// podIdentifier races that pod's CNI DEL. The update must not leave a shadow map
// for the deleted (unpinned) map behind, or every later rule write for the
// identifier lands in a map no attached program reads.
func TestBpfClient_UpdateEbpfMaps_RacingDeleteDoesNotCacheOrphanMap(t *testing.T) {
	client, seed := newRaceTestBpfClient(t)
	podIdentifier := utils.GetPodIdentifier("ds-old", "ns")
	oldPod := types.NamespacedName{Name: "ds-old", Namespace: "ns"}
	oldPodKey := utils.GetPodNamespacedName(oldPod.Name, oldPod.Namespace)

	// State after the old pod's CNI ADD: one program pair, used by one pod.
	seedLastPodOfIdentifier(t, client, podIdentifier, oldPodKey, 100, 101)

	deleteDone := make(chan struct{})
	var once sync.Once
	origNewInMemoryBpfMap := newInMemoryBpfMap
	defer func() { newInMemoryBpfMap = origNewInMemoryBpfMap }()
	newInMemoryBpfMap = func(bpfMap *goebpfmaps.BpfMap) (*InMemoryBpfMap, error) {
		// The first shadow-map build happens mid-update, after the context was
		// read. Deliver the CNI DEL here: it must wait for the update to finish
		// rather than tear the identifier down underneath it.
		once.Do(func() {
			go func() {
				_ = client.DeleteBPFProbes(oldPod, podIdentifier)
				close(deleteDone)
			}()
			select {
			case <-deleteDone:
				t.Error("CNI DEL completed while UpdateEbpfMaps was mid-update")
			case <-time.After(50 * time.Millisecond):
			}
		})
		return seededShadowMap(seed)(bpfMap)
	}

	assert.NoError(t, client.UpdateEbpfMaps(podIdentifier, nil, nil))
	<-deleteDone
	assert.False(t, client.HasBPFContext(podIdentifier))

	// The replacement pod's CNI ADD loads a fresh program pair for the identifier.
	client.policyEndpointeBPFContext.Store(podIdentifier, raceTestBPFContext(7, 200, 9, 201))

	assert.NoError(t, client.UpdateEbpfMaps(podIdentifier, nil, nil))
	assert.Equal(t, uint32(200), cachedMapID(t, client.ingressInMemoryMap, podIdentifier))
	assert.Equal(t, uint32(201), cachedMapID(t, client.egressInMemoryMap, podIdentifier))
}

// Issue #676: an attach for a pod whose CNI DEL is in progress must observe the
// DEL once it gets the lock, instead of loading a new program set for the
// identifier on behalf of a pod that no longer exists.
func TestBpfClient_AttacheBPFProbes_WaitsForInProgressDelete(t *testing.T) {
	client, _ := newRaceTestBpfClient(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockSDKClient := mock_bpfclient.NewMockBpfSDKClient(ctrl)
	mockSDKClient.EXPECT().LoadBpfFile(gomock.Any(), gomock.Any()).Times(0)
	mockTCClient := mock_tc.NewMockBpfTc(ctrl)
	mockTCClient.EXPECT().TCIngressAttach(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
	mockTCClient.EXPECT().TCEgressAttach(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
	client.bpfSDKClient = mockSDKClient
	client.bpfTCClient = mockTCClient

	origGetHostVethName := utils.GetHostVethName
	defer func() { utils.GetHostVethName = origGetHostVethName }()
	utils.GetHostVethName = func(string, string, int, []string) (string, error) { return "mockedveth0", nil }

	pod := types.NamespacedName{Name: "ds-old", Namespace: "ns"}
	podIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)

	client.podIdentifierLocks.Lock(podIdentifier) // the CNI DEL holds the lock
	attachDone := make(chan error)
	go func() {
		_, err := client.AttacheBPFProbes(pod, podIdentifier, INTERFACE_COUNT_DEFAULT, false)
		attachDone <- err
	}()
	assert.Eventually(t, func() bool { return lockWaiters(client, podIdentifier) == 2 }, time.Second, time.Millisecond)
	client.deletedPods.Store(utils.GetPodNamespacedName(pod.Name, pod.Namespace), time.Now())
	client.podIdentifierLocks.Unlock(podIdentifier)

	assert.NoError(t, receiveWithin(t, attachDone))
	assert.False(t, client.HasBPFContext(podIdentifier))
}

func TestBpfClient_DeleteBPFProbes_ReleasesPodIdentifierLock(t *testing.T) {
	client, _ := newRaceTestBpfClient(t)
	pod := types.NamespacedName{Name: "ds-old", Namespace: "ns"}
	podKey := utils.GetPodNamespacedName(pod.Name, pod.Namespace)
	podIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
	seedLastPodOfIdentifier(t, client, podIdentifier, podKey, 100, 101)

	assert.NoError(t, client.DeleteBPFProbes(pod, podIdentifier))
	assert.False(t, client.HasBPFContext(podIdentifier))
	assert.Zero(t, client.podIdentifierLocks.len())
}

// The first-pod decision is made under the lock, after a CNI DEL of the
// identifier's last pod has finished, so an attach that loads a fresh program
// set reports it and the CNI ADD programs the new maps.
func TestBpfClient_AttacheBPFProbes_ReportsFreshLoadAfterLastPodDeleted(t *testing.T) {
	client, _ := newRaceTestBpfClient(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	podIdentifier := utils.GetPodIdentifier("ds-new", "ns")
	newPod := types.NamespacedName{Name: "ds-new", Namespace: "ns"}
	oldPod := types.NamespacedName{Name: "ds-old", Namespace: "ns"}
	oldPodKey := utils.GetPodNamespacedName(oldPod.Name, oldPod.Namespace)
	seedLastPodOfIdentifier(t, client, podIdentifier, oldPodKey, 100, 101)
	assert.True(t, client.HasBPFContext(podIdentifier), "precondition: old pod's programs exist")
	assert.NoError(t, client.DeleteBPFProbes(oldPod, podIdentifier))

	ingressPinPath := utils.GetBPFPinPathFromPodIdentifier(podIdentifier, "ingress")
	egressPinPath := utils.GetBPFPinPathFromPodIdentifier(podIdentifier, "egress")
	loaded := func(pinPath string, progFD int) map[string]goelf.BpfData {
		return map[string]goelf.BpfData{pinPath: {
			Program: goebpfprogs.BpfProgram{ProgFD: progFD},
			Maps:    map[string]goebpfmaps.BpfMap{"m": {MapID: uint32(progFD)}},
		}}
	}
	mockSDKClient := mock_bpfclient.NewMockBpfSDKClient(ctrl)
	gomock.InOrder(
		mockSDKClient.EXPECT().LoadBpfFile(gomock.Any(), podIdentifier).Return(loaded(ingressPinPath, 7), nil, nil),
		mockSDKClient.EXPECT().LoadBpfFile(gomock.Any(), podIdentifier).Return(loaded(egressPinPath, 9), nil, nil),
	)
	mockTCClient := mock_tc.NewMockBpfTc(ctrl)
	mockTCClient.EXPECT().TCEgressAttach(gomock.Any(), 7, gomock.Any()).Return(nil)
	mockTCClient.EXPECT().TCIngressAttach(gomock.Any(), 9, gomock.Any()).Return(nil)
	client.bpfSDKClient = mockSDKClient
	client.bpfTCClient = mockTCClient
	origGetHostVethName := utils.GetHostVethName
	defer func() { utils.GetHostVethName = origGetHostVethName }()
	utils.GetHostVethName = func(string, string, int, []string) (string, error) { return "mockedveth0", nil }

	first, err := client.AttacheBPFProbes(newPod, podIdentifier, INTERFACE_COUNT_DEFAULT, true)
	assert.NoError(t, err)
	assert.True(t, first, "a fresh program load must be reported so the caller programs the new maps")

	// A second pod of the identifier reuses the programs.
	otherPod := types.NamespacedName{Name: "ds-other", Namespace: "ns"}
	mockTCClient.EXPECT().TCEgressAttach(gomock.Any(), 7, gomock.Any()).Return(nil)
	mockTCClient.EXPECT().TCIngressAttach(gomock.Any(), 9, gomock.Any()).Return(nil)
	first, err = client.AttacheBPFProbes(otherPod, podIdentifier, INTERFACE_COUNT_DEFAULT, true)
	assert.NoError(t, err)
	assert.False(t, first)
}

// The pod-state writers go through the context's map FDs, which a concurrent
// CNI DEL closes; they must wait for the identifier lock too.
func TestBpfClient_PodStateWritersWaitForPodIdentifierLock(t *testing.T) {
	client, _ := newRaceTestBpfClient(t)
	podIdentifier := utils.GetPodIdentifier("ds-old", "ns")
	writers := map[string]func() error{
		"UpdatePodStateEbpfMaps": func() error {
			return client.UpdatePodStateEbpfMaps(podIdentifier, POD_STATE_MAP_KEY, DEFAULT_ALLOW, true, true)
		},
		"CreatePodStateEbpfEntryIfNotExists": func() error {
			return client.CreatePodStateEbpfEntryIfNotExists(podIdentifier, CLUSTER_POLICY_POD_STATE_MAP_KEY, DEFAULT_ALLOW)
		},
		"UpdateClusterPolicyEbpfMaps": func() error {
			return client.UpdateClusterPolicyEbpfMaps(podIdentifier, nil, nil)
		},
		"UpdateEbpfMaps": func() error {
			return client.UpdateEbpfMaps(podIdentifier, nil, nil)
		},
	}
	for name, write := range writers {
		t.Run(name, func(t *testing.T) {
			client.podIdentifierLocks.Lock(podIdentifier) // a CNI DEL in progress
			done := make(chan error)
			go func() { done <- write() }()
			ranUnderLock := false
			select {
			case <-done:
				ranUnderLock = true
			case <-time.After(50 * time.Millisecond):
			}
			client.podIdentifierLocks.Unlock(podIdentifier) // DEL finished: no context left
			if ranUnderLock {
				t.Fatal("writer ran while the identifier lock was held")
			}
			assert.ErrorContains(t, <-done, "no bpf context registered")
		})
	}
}

// ReAttachEbpfProbes runs at startup and calls the locked pod-state writer for
// each identifier it reattaches, so it must not hold an identifier lock itself.
func TestBpfClient_ReAttachEbpfProbes_ReleasesPodIdentifierLocks(t *testing.T) {
	client, _ := newRaceTestBpfClient(t)
	client.ingressBinary, client.egressBinary = "ingress.bpf.o", "egress.bpf.o"
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	podIdentifier := utils.GetPodIdentifier("ds-a", "ns")
	ingressPinPath := utils.GetBPFPinPathFromPodIdentifier(podIdentifier, "ingress")
	egressPinPath := utils.GetBPFPinPathFromPodIdentifier(podIdentifier, "egress")
	client.interfaceNametoIngressPinPath = map[string]string{"eni1": ingressPinPath}
	client.interfaceNametoEgressPinPath = map[string]string{"eni1": egressPinPath}

	notAMap := disposableFD(t)
	defer syscall.Close(notAMap)
	loaded := func(pinPath string, progFD int, podStateMap string) map[string]goelf.BpfData {
		return map[string]goelf.BpfData{pinPath: {
			Program: goebpfprogs.BpfProgram{ProgFD: progFD},
			Maps:    map[string]goebpfmaps.BpfMap{podStateMap: {MapFD: uint32(notAMap)}},
		}}
	}
	mockSDKClient := mock_bpfclient.NewMockBpfSDKClient(ctrl)
	mockSDKClient.EXPECT().LoadBpfFile(client.ingressBinary, podIdentifier).Return(loaded(ingressPinPath, 7, utils.TC_INGRESS_POD_STATE_MAP), nil, nil)
	mockSDKClient.EXPECT().LoadBpfFile(client.egressBinary, podIdentifier).Return(loaded(egressPinPath, 9, utils.TC_EGRESS_POD_STATE_MAP), nil, nil)
	mockTCClient := mock_tc.NewMockBpfTc(ctrl)
	mockTCClient.EXPECT().TCEgressAttach("eni1", 7, gomock.Any()).Return(nil)
	mockTCClient.EXPECT().TCIngressAttach("eni1", 9, gomock.Any()).Return(nil)
	client.bpfSDKClient = mockSDKClient
	client.bpfTCClient = mockTCClient

	done := make(chan error)
	go func() { done <- client.ReAttachEbpfProbes() }()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("ReAttachEbpfProbes did not return")
	}
	value, ok := client.policyEndpointeBPFContext.Load(podIdentifier)
	require.True(t, ok)
	assert.Equal(t, 7, value.(BPFContext).ingressPgmInfo.Program.ProgFD)
	assert.Equal(t, 9, value.(BPFContext).egressPgmInfo.Program.ProgFD)
	assert.Zero(t, client.podIdentifierLocks.len())
}

func TestShadowMapForLocked_RejectsUnexpectedCacheValue(t *testing.T) {
	cache := new(sync.Map)
	cache.Store("ds@ns", "not a shadow map")
	_, err := shadowMapForLocked(cache, "ds@ns", goebpfmaps.BpfMap{MapID: 200})
	assert.ErrorContains(t, err, "unexpected type string")
}

// A CNI ADD for a pod recreated under the same name (a StatefulSet pod, say)
// must not be skipped by the previous pod's deleted-pod marker, even when that
// marker is written by a CNI DEL that holds the identifier lock while the ADD
// waits for it.
func TestBpfClient_AttacheBPFProbes_ConfirmedLiveAttachSurvivesConcurrentDelete(t *testing.T) {
	client, _ := newRaceTestBpfClient(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	pod := types.NamespacedName{Name: "web-0", Namespace: "ns"}
	podKey := utils.GetPodNamespacedName(pod.Name, pod.Namespace)
	podIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
	loaded := func(direction string, progFD int) map[string]goelf.BpfData {
		return map[string]goelf.BpfData{utils.GetBPFPinPathFromPodIdentifier(podIdentifier, direction): {
			Program: goebpfprogs.BpfProgram{ProgFD: progFD},
			Maps:    map[string]goebpfmaps.BpfMap{"m": {MapID: uint32(progFD)}},
		}}
	}
	mockSDKClient := mock_bpfclient.NewMockBpfSDKClient(ctrl)
	gomock.InOrder(
		mockSDKClient.EXPECT().LoadBpfFile(gomock.Any(), podIdentifier).Return(loaded("ingress", 7), nil, nil),
		mockSDKClient.EXPECT().LoadBpfFile(gomock.Any(), podIdentifier).Return(loaded("egress", 9), nil, nil),
	)
	mockTCClient := mock_tc.NewMockBpfTc(ctrl)
	mockTCClient.EXPECT().TCEgressAttach(gomock.Any(), 7, gomock.Any()).Return(nil)
	mockTCClient.EXPECT().TCIngressAttach(gomock.Any(), 9, gomock.Any()).Return(nil)
	client.bpfSDKClient = mockSDKClient
	client.bpfTCClient = mockTCClient
	origGetHostVethName := utils.GetHostVethName
	defer func() { utils.GetHostVethName = origGetHostVethName }()
	utils.GetHostVethName = func(string, string, int, []string) (string, error) { return "mockedveth0", nil }

	client.podIdentifierLocks.Lock(podIdentifier) // the previous web-0's CNI DEL
	type result struct {
		first bool
		err   error
	}
	attachDone := make(chan result)
	go func() {
		first, err := client.AttacheBPFProbes(pod, podIdentifier, INTERFACE_COUNT_DEFAULT, true)
		attachDone <- result{first, err}
	}()
	assert.Eventually(t, func() bool { return lockWaiters(client, podIdentifier) == 2 }, time.Second, time.Millisecond)
	client.deletedPods.Store(podKey, time.Now()) // DEL publishes its marker last
	client.podIdentifierLocks.Unlock(podIdentifier)

	got := receiveWithin(t, attachDone)
	assert.NoError(t, got.err)
	assert.True(t, got.first, "the replacement pod's maps must be programmed")
	_, attached := client.ingressPodToProgMap.Load(podKey)
	assert.True(t, attached, "the replacement pod must be attached")
	_, stillMarked := client.deletedPods.Load(podKey)
	assert.False(t, stillMarked)
}

// Only the attach that loads an identifier's programs reports its first pod. A
// sibling pod and a repeated ADD reuse the programs and their shared maps.
func TestBpfClient_AttacheBPFProbes_OnlyTheLoadingAttachIsFirstPod(t *testing.T) {
	client, _ := newRaceTestBpfClient(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	podIdentifier := utils.GetPodIdentifier("app-b", "ns")
	loaded := func(direction string, progFD int) map[string]goelf.BpfData {
		return map[string]goelf.BpfData{utils.GetBPFPinPathFromPodIdentifier(podIdentifier, direction): {
			Program: goebpfprogs.BpfProgram{ProgFD: progFD},
			Maps:    map[string]goebpfmaps.BpfMap{"m": {MapID: uint32(progFD)}},
		}}
	}
	mockSDKClient := mock_bpfclient.NewMockBpfSDKClient(ctrl)
	gomock.InOrder(
		mockSDKClient.EXPECT().LoadBpfFile(gomock.Any(), podIdentifier).Return(loaded("ingress", 7), nil, nil),
		mockSDKClient.EXPECT().LoadBpfFile(gomock.Any(), podIdentifier).Return(loaded("egress", 9), nil, nil),
	)
	mockTCClient := mock_tc.NewMockBpfTc(ctrl)
	mockTCClient.EXPECT().TCEgressAttach(gomock.Any(), 7, gomock.Any()).Return(nil).Times(2)
	mockTCClient.EXPECT().TCIngressAttach(gomock.Any(), 9, gomock.Any()).Return(nil).Times(2)
	client.bpfSDKClient = mockSDKClient
	client.bpfTCClient = mockTCClient
	origGetHostVethName := utils.GetHostVethName
	defer func() { utils.GetHostVethName = origGetHostVethName }()
	utils.GetHostVethName = func(string, string, int, []string) (string, error) { return "mockedveth0", nil }

	attach := func(name string) bool {
		t.Helper()
		first, err := client.AttacheBPFProbes(types.NamespacedName{Name: name, Namespace: "ns"}, podIdentifier, INTERFACE_COUNT_DEFAULT, true)
		require.NoError(t, err)
		return first
	}
	assert.True(t, attach("app-b-1"), "the attach that loads the programs")
	assert.False(t, attach("app-b-2"), "a sibling reuses the loaded programs")
	assert.False(t, attach("app-b-2"), "a repeated ADD for an attached pod")
}

// The first-pod decision is made under the lock: a CNI ADD that is waiting on
// the lock while the CNI DEL of the identifier's last pod tears it down must
// find no programs, load fresh ones and report the first pod.
func TestBpfClient_AttacheBPFProbes_FirstPodDecidedAfterConcurrentDelete(t *testing.T) {
	client, _ := newRaceTestBpfClient(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	podIdentifier := utils.GetPodIdentifier("ds-new", "ns")
	newPod := types.NamespacedName{Name: "ds-new", Namespace: "ns"}
	oldPod := types.NamespacedName{Name: "ds-old", Namespace: "ns"}
	seedLastPodOfIdentifier(t, client, podIdentifier, utils.GetPodNamespacedName(oldPod.Name, oldPod.Namespace), 100, 101)

	loaded := func(direction string, progFD int) map[string]goelf.BpfData {
		return map[string]goelf.BpfData{utils.GetBPFPinPathFromPodIdentifier(podIdentifier, direction): {
			Program: goebpfprogs.BpfProgram{ProgFD: progFD},
			Maps:    map[string]goebpfmaps.BpfMap{"m": {MapID: uint32(progFD)}},
		}}
	}
	mockSDKClient := mock_bpfclient.NewMockBpfSDKClient(ctrl)
	gomock.InOrder(
		mockSDKClient.EXPECT().LoadBpfFile(gomock.Any(), podIdentifier).Return(loaded("ingress", 7), nil, nil),
		mockSDKClient.EXPECT().LoadBpfFile(gomock.Any(), podIdentifier).Return(loaded("egress", 9), nil, nil),
	)
	mockTCClient := mock_tc.NewMockBpfTc(ctrl)
	mockTCClient.EXPECT().TCEgressAttach(gomock.Any(), 7, gomock.Any()).Return(nil)
	mockTCClient.EXPECT().TCIngressAttach(gomock.Any(), 9, gomock.Any()).Return(nil)
	client.bpfSDKClient = mockSDKClient
	client.bpfTCClient = mockTCClient
	origGetHostVethName := utils.GetHostVethName
	defer func() { utils.GetHostVethName = origGetHostVethName }()
	utils.GetHostVethName = func(string, string, int, []string) (string, error) { return "mockedveth0", nil }

	client.podIdentifierLocks.Lock(podIdentifier) // the old pod's CNI DEL
	type result struct {
		first bool
		err   error
	}
	attachDone := make(chan result)
	go func() {
		first, err := client.AttacheBPFProbes(newPod, podIdentifier, INTERFACE_COUNT_DEFAULT, true)
		attachDone <- result{first, err}
	}()
	assert.Eventually(t, func() bool { return lockWaiters(client, podIdentifier) == 2 }, time.Second, time.Millisecond)
	client.deletePodFromIngressProgPodCaches(oldPod.Name, oldPod.Namespace)
	client.deletePodFromEgressProgPodCaches(oldPod.Name, oldPod.Namespace)
	assert.NoError(t, client.deleteBPFProbes(podIdentifier))
	client.podIdentifierLocks.Unlock(podIdentifier)

	got := receiveWithin(t, attachDone)
	assert.NoError(t, got.err)
	assert.True(t, got.first, "the new pod's freshly loaded maps must be programmed by its CNI ADD")
}

// Concurrent CNI ADDs for two pods of a new identifier: exactly one loads the
// programs and reports the first pod; the other reuses them.
func TestBpfClient_AttacheBPFProbes_ConcurrentSiblingsLoadProgramsOnce(t *testing.T) {
	client, _ := newRaceTestBpfClient(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	podIdentifier := utils.GetPodIdentifier("app-b", "ns")
	loaded := func(direction string, progFD int) map[string]goelf.BpfData {
		return map[string]goelf.BpfData{utils.GetBPFPinPathFromPodIdentifier(podIdentifier, direction): {
			Program: goebpfprogs.BpfProgram{ProgFD: progFD},
			Maps:    map[string]goebpfmaps.BpfMap{"m": {MapID: uint32(progFD)}},
		}}
	}
	mockSDKClient := mock_bpfclient.NewMockBpfSDKClient(ctrl)
	gomock.InOrder(
		mockSDKClient.EXPECT().LoadBpfFile(gomock.Any(), podIdentifier).Return(loaded("ingress", 7), nil, nil),
		mockSDKClient.EXPECT().LoadBpfFile(gomock.Any(), podIdentifier).Return(loaded("egress", 9), nil, nil),
	)
	mockTCClient := mock_tc.NewMockBpfTc(ctrl)
	mockTCClient.EXPECT().TCEgressAttach(gomock.Any(), 7, gomock.Any()).Return(nil).Times(2)
	mockTCClient.EXPECT().TCIngressAttach(gomock.Any(), 9, gomock.Any()).Return(nil).Times(2)
	client.bpfSDKClient = mockSDKClient
	client.bpfTCClient = mockTCClient
	origGetHostVethName := utils.GetHostVethName
	defer func() { utils.GetHostVethName = origGetHostVethName }()
	utils.GetHostVethName = func(string, string, int, []string) (string, error) { return "mockedveth0", nil }

	client.podIdentifierLocks.Lock(podIdentifier) // hold both ADDs until they are queued
	firsts := make(chan bool, 2)
	for _, name := range []string{"app-b-1", "app-b-2"} {
		go func() {
			first, err := client.AttacheBPFProbes(types.NamespacedName{Name: name, Namespace: "ns"}, podIdentifier, INTERFACE_COUNT_DEFAULT, true)
			assert.NoError(t, err)
			firsts <- first
		}()
	}
	assert.Eventually(t, func() bool { return lockWaiters(client, podIdentifier) == 3 }, time.Second, time.Millisecond)
	client.podIdentifierLocks.Unlock(podIdentifier)

	a, b := receiveWithin(t, firsts), receiveWithin(t, firsts)
	assert.True(t, a != b, "exactly one ADD must report the first pod, got %v and %v", a, b)
}

// A reconciler attach for a pod already marked deleted must return without
// waiting for the identifier lock: after an agent restart PolicyEndpoints still
// list just-deleted pods, and waiting behind the replacement pod's CNI ADD for
// each of them delays the reconcile of every other identifier.
func TestBpfClient_AttacheBPFProbes_DeletedPodSkipsWithoutWaitingForLock(t *testing.T) {
	client, _ := newRaceTestBpfClient(t)
	pod := types.NamespacedName{Name: "ds-old", Namespace: "ns"}
	podIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
	client.deletedPods.Store(utils.GetPodNamespacedName(pod.Name, pod.Namespace), time.Now())

	client.podIdentifierLocks.Lock(podIdentifier) // the replacement pod's CNI ADD
	defer client.podIdentifierLocks.Unlock(podIdentifier)
	done := make(chan bool)
	go func() {
		first, err := client.AttacheBPFProbes(pod, podIdentifier, INTERFACE_COUNT_DEFAULT, false)
		done <- err == nil && !first
	}()
	select {
	case ok := <-done:
		assert.True(t, ok)
	case <-time.After(time.Second):
		t.Fatal("reconciler attach of a deleted pod waited for the identifier lock")
	}
}

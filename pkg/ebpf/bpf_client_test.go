package ebpf

import (
	"errors"
	"fmt"
	"os"
	"sync"
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
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
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
			wantErr:           errors.New("Skipping probe attach: multiNIC enabled and interface count is unknown"),
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

		restoreGetHostVethName(t)
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

			restoreGetHostVethName(t)
			utils.GetHostVethName = func(podName, podNamespace string, interfaceIndex int, interfacePrefixes []string) (string, error) {
				return fmt.Sprintf("mockedveth%d", interfaceIndex), nil
			}

			gotError := testBpfClient.AttacheBPFProbes(tt.testPod, tt.podIdentifier, tt.numInterfaces, false)
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
			wantErr:           errors.New("Skipping probe attach: multiNIC enabled and interface count is unknown"),
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
			assert.Equal(t, tt.wantErr, gotErr)
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

	restoreGetHostVethName(t)
	utils.GetHostVethName = func(podName, podNamespace string, interfaceIndex int, interfacePrefixes []string) (string, error) {
		return fmt.Sprintf("mockedveth%d", interfaceIndex), nil
	}

	err := testBpfClient.AttacheBPFProbes(testPod, podIdentifier, 2, false)
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

// Locks are sharded over a fixed array, so the same identifier must always map to
// the same mutex, every index must be in range, and identifiers must spread out
// rather than piling onto one shard.
func TestLockFor_ShardingIsStableAndInRange(t *testing.T) {
	c := &bpfClient{}

	// Same identifier -> same mutex, every time.
	for _, id := range []string{"web-abc123@default", "api-xyz789@prod", ""} {
		assert.Same(t, c.lockFor(id), c.lockFor(id), "identifier %q mapped to two different mutexes", id)
	}

	// Distinct identifiers spread across shards instead of collapsing onto one.
	seen := map[uint32]int{}
	for i := 0; i < 4096; i++ {
		idx := shardIndex(fmt.Sprintf("rs-%d@ns%d", i, i%7))
		assert.Less(t, idx, uint32(podIdentifierLockShards), "shard index out of range")
		seen[idx]++
	}
	assert.Equal(t, podIdentifierLockShards, len(seen),
		"4096 identifiers should reach every shard; got %d", len(seen))

	// Two identifiers sharing a shard is expected and safe -- assert it can happen
	// so the test documents the trade-off rather than pretending it cannot.
	assert.Greater(t, seen[shardIndex("rs-0@ns0")], 1, "expected shard reuse across identifiers")
}

// suppressionCount reads one stage's counter value without pulling in testutil.
func suppressionCount(t *testing.T, stage string) float64 {
	t.Helper()
	c, err := attachSuppressedPodDeleted.GetMetricWithLabelValues(stage)
	assert.NoError(t, err)
	var m dto.Metric
	assert.NoError(t, c.Write(&m))
	return m.GetCounter().GetValue()
}

// A CounterVec exports nothing for a label until first used, so without
// pre-initialisation the metric is absent from /metrics until the first
// suppression -- observed on a live cluster, and useless for a dashboard.
func TestAttachSuppressionCounter_ExportsBothStagesFromStartup(t *testing.T) {
	// Reset first so the assertion does not depend on which tests ran before.
	attachSuppressedPodDeleted.Reset()
	initAttachSuppressionSeries()

	ch := make(chan prometheus.Metric, 8)
	attachSuppressedPodDeleted.Collect(ch)
	close(ch)
	assert.Equal(t, 2, len(ch),
		"both pre_lock and post_lock series must exist before any suppression happens")
}

// And it must actually count, per stage.
func TestAttachSuppressionCounter_IncrementsForTheStageThatFired(t *testing.T) {
	prometheusRegister()

	pod := types.NamespacedName{Name: "nginx-abc123", Namespace: "default"}
	podIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
	podNamespacedName := utils.GetPodNamespacedName(pod.Name, pod.Namespace)

	c := &bpfClient{deletedPods: new(sync.Map)}
	before := suppressionCount(t, suppressionStagePostLock)

	// No tombstone yet: nothing to suppress, nothing to count.
	assert.False(t, c.suppressAttachForDeletedPod(pod, podIdentifier, podNamespacedName, suppressionStagePostLock))
	assert.Equal(t, before, suppressionCount(t, suppressionStagePostLock))

	c.deletedPods.Store(podNamespacedName, time.Now())
	assert.True(t, c.suppressAttachForDeletedPod(pod, podIdentifier, podNamespacedName, suppressionStagePostLock))
	assert.Equal(t, before+1, suppressionCount(t, suppressionStagePostLock),
		"a post_lock suppression must increment the post_lock series")
}

// restoreGetHostVethName registers cleanup that puts the package-level
// utils.GetHostVethName back after a test replaces it. Without this a stub leaks
// into every later test in the package and results become order-dependent.
func restoreGetHostVethName(t *testing.T) {
	original := utils.GetHostVethName
	t.Cleanup(func() { utils.GetHostVethName = original })
}

// newAttachTestClient builds a bpfClient wired for the AttacheBPFProbes tests,
// with a BPFContext already registered for podIdentifier so the attach re-uses
// ingress progFD 3 / egress progFD 5 instead of loading an ELF.
func newAttachTestClient(t *testing.T, podIdentifier string, sdk *mock_bpfclient.MockBpfSDKClient, tc *mock_tc.MockBpfTc) *bpfClient {
	t.Helper()
	c := &bpfClient{
		hostMask:                  "/32",
		policyEndpointeBPFContext: new(sync.Map),
		bpfSDKClient:              sdk,
		bpfTCClient:               tc,
		ingressPodToProgMap:       new(sync.Map),
		egressPodToProgMap:        new(sync.Map),
		ingressProgToPodsMap:      new(sync.Map),
		egressProgToPodsMap:       new(sync.Map),
		podNameToInterfaceCount:   new(sync.Map),
		deletedPods:               new(sync.Map),
		// Needed by deleteBPFProbes, so an attach/delete round trip does not nil
		// dereference. Every sync.Map field AttacheBPFProbes or DeleteBPFProbes can
		// reach must be initialized here.
		ingressInMemoryMap:              new(sync.Map),
		egressInMemoryMap:               new(sync.Map),
		clusterPolicyIngressInMemoryMap: new(sync.Map),
		clusterPolicyEgressInMemoryMap:  new(sync.Map),
		globalMaps:                      new(sync.Map),
	}
	c.policyEndpointeBPFContext.Store(podIdentifier, BPFContext{
		ingressPgmInfo: goelf.BpfData{Program: goebpfprogs.BpfProgram{ProgID: 2, ProgFD: 3}},
		egressPgmInfo:  goelf.BpfData{Program: goebpfprogs.BpfProgram{ProgID: 4, ProgFD: 5}},
	})
	restoreGetHostVethName(t)
	utils.GetHostVethName = func(_, _ string, _ int, _ []string) (string, error) {
		return "mockedveth0", nil
	}
	return c
}

// assertNotInProgSets checks the pod is absent from the progFD -> pods sets.
// These, not the podToProg maps, are what isProgFdShared counts, so they are the
// structures whose corruption produces the pin leak.
func assertNotInProgSets(t *testing.T, c *bpfClient, podNamespacedName string) {
	t.Helper()
	for _, m := range []struct {
		name   string
		set    *sync.Map
		progFD int
	}{
		{"ingressProgToPodsMap", c.ingressProgToPodsMap, 3},
		{"egressProgToPodsMap", c.egressProgToPodsMap, 5},
	} {
		if raw, ok := m.set.Load(m.progFD); ok {
			_, present := raw.(map[string]struct{})[podNamespacedName]
			assert.False(t, present, "deleted pod was re-inserted into %s", m.name)
		}
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

	err := testBpfClient.AttacheBPFProbes(pod, utils.GetPodIdentifier(pod.Name, pod.Namespace), 1, false)
	assert.ErrorIs(t, err, ErrAttachSkippedPodDeleted, "a skip must be reported as ErrAttachSkippedPodDeleted")
}

// A caller with authoritative evidence the pod exists (a CNI ADD) must never be
// vetoed by a stale tombstone: skipping would leave a live pod with no probes,
// unenforced, while the RPC still reported success.
func TestAttacheBPFProbes_ProceedsWhenPodConfirmedLive(t *testing.T) {
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

	testBpfClient := newAttachTestClient(t, podIdentifier, mockBpfSDK, mockTCClient)

	// A tombstone is present and is NOT cleared beforehand: the attach itself must
	// drop it, under the lock, because the caller knows the pod is live.
	testBpfClient.deletedPods.Store(podNamespacedName, time.Now())

	err := testBpfClient.AttacheBPFProbes(pod, podIdentifier, 1, true)
	assert.NoError(t, err, "a confirmed-live attach must never be skipped")

	_, ingressAttached := testBpfClient.ingressPodToProgMap.Load(podNamespacedName)
	assert.True(t, ingressAttached)
	_, tombstoneStillSet := testBpfClient.deletedPods.Load(podNamespacedName)
	assert.False(t, tombstoneStillSet, "a confirmed-live attach must clear the stale tombstone")
}

// A pod deleted while an attach is blocked on podIdentifierLock must not be
// re-attached once the lock is released. The tombstone check before the lock can
// be stale, so re-inserting here would leave the pod in ingressProgToPodsMap
// forever — nothing removes it again — keeping isProgFdShared true for the last
// pod of the podIdentifier and leaking its pinned programs and maps.
func TestAttacheBPFProbes_SkipsPodDeletedWhileWaitingForLock(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockTCClient := mock_tc.NewMockBpfTc(ctrl)
	mockTCClient.EXPECT().TCIngressAttach(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)
	mockTCClient.EXPECT().TCEgressAttach(gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

	mockBpfSDK := mock_bpfclient.NewMockBpfSDKClient(ctrl)
	mockBpfSDK.EXPECT().LoadBpfFile(gomock.Any(), gomock.Any()).AnyTimes()

	pod := types.NamespacedName{Name: "churn-abc123", Namespace: "leak-test"}
	podIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
	podNamespacedName := utils.GetPodNamespacedName(pod.Name, pod.Namespace)

	testBpfClient := newAttachTestClient(t, podIdentifier, mockBpfSDK, mockTCClient)

	// Hold podIdentifierLock so the attach below parks on it, standing in for an
	// in-flight DeleteBPFProbes which holds this same lock.
	heldLock := testBpfClient.lockFor(podIdentifier)
	heldLock.Lock()

	done := make(chan error, 1)
	go func() {
		done <- testBpfClient.AttacheBPFProbes(pod, podIdentifier, 1, false)
	}()

	// Give the goroutine time to pass the pre-lock check and park on Lock(). With
	// a bare sync.Mutex there is nothing to observe waiters on, so this is a sleep
	// -- but it cannot produce a false pass: no tombstone exists yet, so the only
	// way the attach could return is by completing, which the held lock prevents.
	// The assertion below is what rules out a bail-out at the pre-lock check.
	select {
	case <-done:
		heldLock.Unlock()
		t.Fatal("AttacheBPFProbes returned while the lock was held; test cannot validate the post-lock check")
	case <-time.After(200 * time.Millisecond):
	}

	// DeleteBPFProbes would have recorded this while holding the lock.
	testBpfClient.deletedPods.Store(podNamespacedName, time.Now())
	heldLock.Unlock()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, ErrAttachSkippedPodDeleted)
	case <-time.After(5 * time.Second):
		t.Fatal("AttacheBPFProbes did not return after podIdentifierLock was released")
	}

	// The pod must not have been re-registered against the shared program.
	_, attached := testBpfClient.ingressPodToProgMap.Load(podNamespacedName)
	assert.False(t, attached, "deleted pod was re-inserted into ingressPodToProgMap")
	_, egressAttached := testBpfClient.egressPodToProgMap.Load(podNamespacedName)
	assert.False(t, egressAttached, "deleted pod was re-inserted into egressPodToProgMap")
	// The refcount, not the podToProg maps, is what leaks the pins.
	assertNotInProgSets(t, testBpfClient, podNamespacedName)
}

// Drives concurrent attaches and deletes across one podIdentifier so the race
// detector can see the progFD -> pods sets. Those inner values are plain Go
// maps, and concurrent access to a plain map is a fatal runtime throw that takes
// the whole agent down, so this must be exercised under -race rather than
// reasoned about. Run with: go test -race -run TestAttachDeleteConcurrent ./pkg/ebpf/
func TestAttachDeleteConcurrentOnOneIdentifier(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockTCClient := mock_tc.NewMockBpfTc(ctrl)
	mockTCClient.EXPECT().TCIngressAttach(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	mockTCClient.EXPECT().TCEgressAttach(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	mockTCClient.EXPECT().TCIngressDetach(gomock.Any()).AnyTimes()
	mockTCClient.EXPECT().TCEgressDetach(gomock.Any()).AnyTimes()

	// Every pod of a ReplicaSet shares one identifier, so pods churning under a
	// single identifier is the steady state for any rolling Deployment.
	const podIdentifier = "web-abc123@default"

	// The first delete of each cycle drops policyEndpointeBPFContext, so later
	// attaches take the load-from-ELF path. Return program data keyed by the pin
	// paths the loader looks up, otherwise every attach after the first fails.
	mockBpfSDK := mock_bpfclient.NewMockBpfSDKClient(ctrl)
	mockBpfSDK.EXPECT().LoadBpfFile(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_, _ string) (map[string]goelf.BpfData, map[string]goebpfmaps.BpfMap, error) {
			return map[string]goelf.BpfData{
				utils.GetBPFPinPathFromPodIdentifier(podIdentifier, "ingress"): {
					Program: goebpfprogs.BpfProgram{ProgID: 2, ProgFD: 3},
					Maps: map[string]goebpfmaps.BpfMap{
						utils.TC_INGRESS_MAP:           {MapFD: 100},
						utils.TC_INGRESS_POD_STATE_MAP: {MapFD: 101},
					},
				},
				utils.GetBPFPinPathFromPodIdentifier(podIdentifier, "egress"): {
					Program: goebpfprogs.BpfProgram{ProgID: 4, ProgFD: 5},
					Maps: map[string]goebpfmaps.BpfMap{
						utils.TC_EGRESS_MAP:           {MapFD: 110},
						utils.TC_EGRESS_POD_STATE_MAP: {MapFD: 111},
					},
				},
			}, map[string]goebpfmaps.BpfMap{}, nil
		}).AnyTimes()

	testBpfClient := newAttachTestClient(t, podIdentifier, mockBpfSDK, mockTCClient)

	const workers = 8
	const iterations = 40
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				pod := types.NamespacedName{
					Name:      fmt.Sprintf("web-abc123-w%dn%d", w, i),
					Namespace: "default",
				}
				// podConfirmedLive=true mirrors the CNI ADD path, which must not be
				// vetoed by another pod's tombstone.
				if err := testBpfClient.AttacheBPFProbes(pod, podIdentifier, 1, true); err != nil {
					t.Errorf("attach failed for %s: %v", pod.Name, err)
					return
				}
				if err := testBpfClient.DeleteBPFProbes(pod, podIdentifier); err != nil {
					t.Errorf("delete failed for %s: %v", pod.Name, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	// Once every pod has been deleted nothing may still be counted against the
	// shared programs; a survivor here is the stale entry that keeps
	// isProgFdShared true for the last pod and leaks its pins.
	for _, m := range []struct {
		name string
		set  *sync.Map
	}{
		{"ingressProgToPodsMap", testBpfClient.ingressProgToPodsMap},
		{"egressProgToPodsMap", testBpfClient.egressProgToPodsMap},
	} {
		m.set.Range(func(progFD, raw any) bool {
			assert.Empty(t, raw.(map[string]struct{}),
				"%s still counts pods against progFD %v after all pods were deleted", m.name, progFD)
			return true
		})
	}
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

package ebpf

import (
	"sync"
	"testing"

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

func TestLoadBPFProgram(t *testing.T) {
	var wantErr error
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBpfClient := mock_bpfclient.NewMockBpfSDKClient(ctrl)
	testBpfClient := &bpfClient{
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
			podIdentifier: utils.GetPodIdentifier(testPod.Name, testPod.Namespace),
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

		utils.GetHostVethName = func(podName, podNamespace string, prefixes []string) (string, error) {
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
			gotIsConntrackMapPresent, gotIsPolicyEventsMapPresent, gotEventsMapFD, _, _, gotError := recoverBPFState(mockTCClient, mockBpfClient, policyEndpointeBPFContext, globapMaps,
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

func Int32Ptr(i int32) *int32 {
	return &i
}

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
						utils.TC_INGRESS_MAP:                {MapFD: 100},
						utils.TC_CLUSTER_POLICY_INGRESS_MAP: {MapFD: 101},
						utils.TC_INGRESS_POD_STATE_MAP:      {MapFD: 102},
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
			// A partial map set: non-empty, valid progFD, but the pod state map is
			// absent. Indexing it later would yield a zero-valued BpfMap with FD 0
			// and every write would fail with EINVAL, so the load must be rejected.
			name: "program loaded without the pod state map",
			loadReturn: map[string]goelf.BpfData{
				pinPath: {
					Program: goebpfprogs.BpfProgram{ProgFD: 7},
					Maps: map[string]goebpfmaps.BpfMap{
						utils.TC_INGRESS_MAP:                {MapFD: 100},
						utils.TC_CLUSTER_POLICY_INGRESS_MAP: {MapFD: 102},
					},
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

func TestLoadBPFProgramRejectsIncompleteMapSet(t *testing.T) {
	for _, direction := range []string{"ingress", "egress"} {
		mapNames, ok := utils.GetBPFMapNames(direction)
		if !assert.True(t, ok, "map names must exist for %s", direction) {
			continue
		}

		for _, failureMode := range []string{"missing", "zero FD", "renamed"} {
			for _, missingMapName := range mapNames.Required() {
				t.Run(fmt.Sprintf("%s/%s/%s", direction, failureMode, missingMapName), func(t *testing.T) {
					maps := make(map[string]goebpfmaps.BpfMap, len(mapNames.Required()))
					for index, mapName := range mapNames.Required() {
						maps[mapName] = goebpfmaps.BpfMap{MapFD: uint32(100 + index)}
					}
					if failureMode == "missing" {
						delete(maps, missingMapName)
					} else if failureMode == "zero FD" {
						mapInfo := maps[missingMapName]
						mapInfo.MapFD = 0
						maps[missingMapName] = mapInfo
					} else {
						delete(maps, missingMapName)
						maps["unexpected_map"] = goebpfmaps.BpfMap{MapFD: 999}
					}

					pinPath := utils.GetBPFPinPathFromPodIdentifier("test-abcd", direction)
					ctrl := gomock.NewController(t)
					defer ctrl.Finish()
					mockBpfClient := mock_bpfclient.NewMockBpfSDKClient(ctrl)
					mockBpfClient.EXPECT().LoadBpfFile(gomock.Any(), gomock.Any()).Return(
						map[string]goelf.BpfData{
							pinPath: {
								Program: goebpfprogs.BpfProgram{ProgFD: 7},
								Maps:    maps,
							},
						}, map[string]goebpfmaps.BpfMap{}, nil)

					testBpfClient := &bpfClient{bpfSDKClient: mockBpfClient}
					_, _, err := testBpfClient.loadBPFProgram("handle_"+direction, direction, "test-abcd")
					if !assert.Error(t, err) {
						return
					}
					assert.Contains(t, err.Error(), missingMapName)
				})
			}
		}
	}
}

func TestLoadBPFProgramCleansUpRejectedLoadResources(t *testing.T) {
	const podIdentifier = "test-abcd"
	direction := "ingress"
	pinPath := utils.GetBPFPinPathFromPodIdentifier(podIdentifier, direction)
	incomplete := testBPFData(direction, 0)

	programFile, err := os.CreateTemp(t.TempDir(), "program")
	if !assert.NoError(t, err) {
		return
	}
	defer programFile.Close()
	incomplete.Program.ProgFD = int(programFile.Fd())
	delete(incomplete.Maps, utils.TC_INGRESS_POD_STATE_MAP)

	mapNames, ok := utils.GetBPFMapNames(direction)
	if !assert.True(t, ok) {
		return
	}
	loadedMapData := make(map[string]goebpfmaps.BpfMap, len(mapNames.Required()))
	mapFiles := make([]*os.File, 0, len(mapNames.Required()))
	for _, mapName := range mapNames.Required() {
		mapFile, createErr := os.CreateTemp(t.TempDir(), mapName)
		if !assert.NoError(t, createErr) {
			return
		}
		mapFiles = append(mapFiles, mapFile)
		loadedMapData[mapName] = goebpfmaps.BpfMap{MapFD: uint32(mapFile.Fd())}
	}
	defer func() {
		for _, mapFile := range mapFiles {
			_ = mapFile.Close()
		}
	}()

	globalFile, err := os.CreateTemp(t.TempDir(), "global")
	if !assert.NoError(t, err) {
		return
	}
	defer globalFile.Close()
	loadedMapData["global_map"] = goebpfmaps.BpfMap{MapFD: uint32(globalFile.Fd())}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockBpfClient := mock_bpfclient.NewMockBpfSDKClient(ctrl)
	mockBpfClient.EXPECT().LoadBpfFile(gomock.Any(), podIdentifier).Return(
		map[string]goelf.BpfData{pinPath: incomplete}, loadedMapData, nil)

	_, _, err = (&bpfClient{bpfSDKClient: mockBpfClient}).loadBPFProgram("handle_ingress", direction, podIdentifier)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), utils.TC_INGRESS_POD_STATE_MAP)
	assert.Error(t, programFile.Close(), "rejected program must be closed by cleanup")
	for _, mapFile := range mapFiles {
		assert.Error(t, mapFile.Close(), "rejected local map must be closed by cleanup")
	}
	assert.NoError(t, globalFile.Close(), "shared maps must not be closed by local cleanup")
}

func TestDeleteBPFProgramAndMapsClearsCleanedHandles(t *testing.T) {
	const podIdentifier = "test-abcd"

	programFile, err := os.CreateTemp(t.TempDir(), "program")
	if !assert.NoError(t, err) {
		return
	}
	defer programFile.Close()

	mapNames, ok := utils.GetBPFMapNames("ingress")
	if !assert.True(t, ok) {
		return
	}
	mapFiles := make(map[string]*os.File, len(mapNames.Required()))
	defer func() {
		for _, mapFile := range mapFiles {
			_ = mapFile.Close()
		}
	}()
	maps := make(map[string]goebpfmaps.BpfMap, len(mapNames.Required()))
	for _, mapName := range mapNames.Required() {
		mapFile, createErr := os.CreateTemp(t.TempDir(), mapName)
		if !assert.NoError(t, createErr) {
			return
		}
		mapFiles[mapName] = mapFile
		maps[mapName] = goebpfmaps.BpfMap{MapFD: uint32(mapFile.Fd())}
	}

	testBpfClient := &bpfClient{policyEndpointeBPFContext: new(sync.Map)}
	testBpfClient.policyEndpointeBPFContext.Store(podIdentifier, BPFContext{
		ingressPgmInfo: goelf.BpfData{
			Program: goebpfprogs.BpfProgram{ProgFD: int(programFile.Fd())},
			Maps:    maps,
		},
	})

	assert.NoError(t, testBpfClient.deleteBPFProgramAndMaps(podIdentifier, "ingress"))

	value, ok := testBpfClient.policyEndpointeBPFContext.Load(podIdentifier)
	if !assert.True(t, ok) {
		return
	}
	context := value.(BPFContext)
	assert.Zero(t, context.ingressPgmInfo.Program.ProgFD)
	for _, mapName := range mapNames.Required() {
		assert.Zero(t, context.ingressPgmInfo.Maps[mapName].MapFD)
	}
	assert.Error(t, programFile.Close(), "cleaned program handle must not remain open")
	for mapName, mapFile := range mapFiles {
		assert.Error(t, mapFile.Close(), "%s handle must not remain open", mapName)
	}
}

type recordingInMemoryBPFMap struct {
	refreshCalls int
	lastContents map[string][]byte
}

func (m *recordingInMemoryBPFMap) BulkRefresh(contents map[string][]byte) error {
	m.refreshCalls++
	m.lastContents = contents
	return nil
}

func testBPFData(direction string, progFD int) goelf.BpfData {
	mapNames, ok := utils.GetBPFMapNames(direction)
	if !ok {
		panic(fmt.Sprintf("unsupported test direction %q", direction))
	}

	maps := make(map[string]goebpfmaps.BpfMap, len(mapNames.Required()))
	for index, mapName := range mapNames.Required() {
		maps[mapName] = goebpfmaps.BpfMap{
			MapFD: uint32(100 + index),
			MapID: uint32(200 + index),
		}
	}
	return goelf.BpfData{
		Program: goebpfprogs.BpfProgram{ProgFD: progFD},
		Maps:    maps,
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

	sampleIngressPgmInfo := testBPFData("ingress", 21)
	sampleIngressPgmInfo.Maps[utils.TC_INGRESS_MAP] = goebpfmaps.BpfMap{
		MapFD: uint32(ingressMapFD),
		MapID: uint32(ingressMapID),
	}
	sampleEgressPgmInfo := testBPFData("egress", 22)
	sampleEgressPgmInfo.Maps[utils.TC_EGRESS_MAP] = goebpfmaps.BpfMap{
		MapFD: uint32(egressMapFD),
		MapID: uint32(egressMapID),
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
			ingressMap := &recordingInMemoryBPFMap{}
			egressMap := &recordingInMemoryBPFMap{}
			testBpfClient := &bpfClient{
				hostMask:                  "/32",
				policyEndpointeBPFContext: new(sync.Map),
				ingressInMemoryMap:        new(sync.Map),
				egressInMemoryMap:         new(sync.Map),
				fwRuleProcessor:           fwrp.NewFirewallRuleProcessor("10.1.1.1", "/32", false),
			}

			sampleBPFContext := BPFContext{
				ingressPgmInfo: sampleIngressPgmInfo,
				egressPgmInfo:  sampleEgressPgmInfo,
			}
			testBpfClient.policyEndpointeBPFContext.Store(tt.podIdentifier, sampleBPFContext)
			testBpfClient.ingressInMemoryMap.Store(tt.podIdentifier, ingressMap)
			testBpfClient.egressInMemoryMap.Store(tt.podIdentifier, egressMap)
			gotErr := testBpfClient.UpdateEbpfMaps(tt.podIdentifier, tt.ingressFirewallRules,
				tt.egressFirewallRules)
			assert.Equal(t, tt.wantErr, gotErr)
			assert.Equal(t, 1, ingressMap.refreshCalls)
			assert.Equal(t, 1, egressMap.refreshCalls)
			assert.NotEmpty(t, ingressMap.lastContents)
			assert.NotEmpty(t, egressMap.lastContents)
		})
	}
}

func TestBpfClient_UpdatePodStateEbpfMaps(t *testing.T) {
	ingressPodStateMapFD, ingressPodStateMapID, egressPodStateMapFD, egressPodStateMapID := 11, 12, 13, 14

	sampleIngressPgmInfo := testBPFData("ingress", 31)
	sampleIngressPgmInfo.Maps[utils.TC_INGRESS_POD_STATE_MAP] = goebpfmaps.BpfMap{
		MapFD: uint32(ingressPodStateMapFD),
		MapID: uint32(ingressPodStateMapID),
	}
	sampleEgressPgmInfo := testBPFData("egress", 32)
	sampleEgressPgmInfo.Maps[utils.TC_EGRESS_POD_STATE_MAP] = goebpfmaps.BpfMap{
		MapFD: uint32(egressPodStateMapFD),
		MapID: uint32(egressPodStateMapID),
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
			originalUpdateBPFMapEntry := updateBPFMapEntry
			t.Cleanup(func() { updateBPFMapEntry = originalUpdateBPFMapEntry })
			var updatedMapFDs []uint32
			updateBPFMapEntry = func(mapInfo goebpfmaps.BpfMap, key, value uintptr, flags uint64) error {
				updatedMapFDs = append(updatedMapFDs, mapInfo.MapFD)
				return nil
			}

			testBpfClient := &bpfClient{
				hostMask:                  "/32",
				policyEndpointeBPFContext: new(sync.Map),
			}

			sampleBPFContext := BPFContext{
				ingressPgmInfo: sampleIngressPgmInfo,
				egressPgmInfo:  sampleEgressPgmInfo,
			}
			testBpfClient.policyEndpointeBPFContext.Store(tt.podIdentifier, sampleBPFContext)
			gotErr := testBpfClient.UpdatePodStateEbpfMaps(tt.podIdentifier, POD_STATE_MAP_KEY, tt.state, true, true)
			assert.Equal(t, tt.wantErr, gotErr)
			assert.ElementsMatch(t, []uint32{uint32(ingressPodStateMapFD), uint32(egressPodStateMapFD)}, updatedMapFDs)
		})
	}
}

func TestBpfClient_UpdatePodStateEbpfMapsMissingMapPreservesContext(t *testing.T) {
	// A recovered or reloaded BPFContext can carry a program whose ProgFD is set while the
	// pod state map is absent from its Maps set. Indexing without checking presence yields a
	// zero-valued BpfMap, so the write targets FD 0 and the kernel returns EINVAL. Returning
	// that error keeps a missing pod-state map from being treated as a successful update.
	tests := []struct {
		name           string
		podIdentifier  string
		ingressPgmInfo goelf.BpfData
		egressPgmInfo  goelf.BpfData
		updateIngress  bool
		updateEgress   bool
		wantErrSubstr  string
	}{
		{
			name:          "ingress pod state map absent from context",
			podIdentifier: "sample_pod_identifier",
			ingressPgmInfo: goelf.BpfData{
				Program: goebpfprogs.BpfProgram{ProgFD: 45},
				Maps:    map[string]goebpfmaps.BpfMap{},
			},
			updateIngress: true,
			wantErrSubstr: utils.TC_INGRESS_POD_STATE_MAP,
		},
		{
			name:          "egress pod state map absent from context",
			podIdentifier: "sample_pod_identifier",
			egressPgmInfo: goelf.BpfData{
				Program: goebpfprogs.BpfProgram{ProgFD: 49},
				Maps:    map[string]goebpfmaps.BpfMap{},
			},
			updateEgress:  true,
			wantErrSubstr: utils.TC_EGRESS_POD_STATE_MAP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testBpfClient := &bpfClient{
				hostMask:                  "/32",
				policyEndpointeBPFContext: new(sync.Map),
			}
			testBpfClient.policyEndpointeBPFContext.Store(tt.podIdentifier, BPFContext{
				ingressPgmInfo: tt.ingressPgmInfo,
				egressPgmInfo:  tt.egressPgmInfo,
			})

			gotErr := testBpfClient.UpdatePodStateEbpfMaps(tt.podIdentifier, POD_STATE_MAP_KEY,
				DEFAULT_ALLOW, tt.updateIngress, tt.updateEgress)

			// The failure must surface to the caller so reconciliation can retry.
			assert.Error(t, gotErr)
			assert.Contains(t, gotErr.Error(), tt.wantErrSubstr)

			// The context and its handles remain owned by the client so attached filters and
			// shadow-map ownership remain available for a retry.
			_, stillCached := testBpfClient.policyEndpointeBPFContext.Load(tt.podIdentifier)
			assert.True(t, stillCached, "bpf context ownership must be preserved after a pod state map failure")
		})
	}
}

func TestBpfClient_CreatePodStateEbpfEntryIfNotExistsMissingMapPreservesContext(t *testing.T) {
	// Same hazard as the update path, on the function that seeds the entry in the first place.
	// A missing pod_state entry is exactly what makes the datapath drop every packet, so an
	// unnoticed failure here is at least as damaging as a failed update.
	tests := []struct {
		name           string
		podIdentifier  string
		ingressPgmInfo goelf.BpfData
		egressPgmInfo  goelf.BpfData
		wantErrSubstr  string
	}{
		{
			name:          "ingress pod state map absent from context",
			podIdentifier: "sample_pod_identifier",
			ingressPgmInfo: goelf.BpfData{
				Program: goebpfprogs.BpfProgram{ProgFD: 45},
				Maps:    map[string]goebpfmaps.BpfMap{},
			},
			wantErrSubstr: utils.TC_INGRESS_POD_STATE_MAP,
		},
		{
			name:          "egress pod state map absent from context",
			podIdentifier: "sample_pod_identifier",
			egressPgmInfo: goelf.BpfData{
				Program: goebpfprogs.BpfProgram{ProgFD: 49},
				Maps:    map[string]goebpfmaps.BpfMap{},
			},
			wantErrSubstr: utils.TC_EGRESS_POD_STATE_MAP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testBpfClient := &bpfClient{
				hostMask:                  "/32",
				policyEndpointeBPFContext: new(sync.Map),
			}
			testBpfClient.policyEndpointeBPFContext.Store(tt.podIdentifier, BPFContext{
				ingressPgmInfo: tt.ingressPgmInfo,
				egressPgmInfo:  tt.egressPgmInfo,
			})

			gotErr := testBpfClient.CreatePodStateEbpfEntryIfNotExists(tt.podIdentifier,
				POD_STATE_MAP_KEY, DEFAULT_ALLOW)

			assert.Error(t, gotErr)
			assert.Contains(t, gotErr.Error(), tt.wantErrSubstr)

			_, stillCached := testBpfClient.policyEndpointeBPFContext.Load(tt.podIdentifier)
			assert.True(t, stillCached, "bpf context ownership must be preserved after a pod state entry failure")
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
			podIdentifierLock:         new(sync.Map),
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
				podIdentifierLock:         new(sync.Map),
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

			gotError := testBpfClient.AttacheBPFProbes(tt.testPod, tt.podIdentifier, tt.numInterfaces)
			assert.Equal(t, tt.wantErr, gotError)
		})
	}
}

func TestAttachBPFProbeDoesNotDetachUnverifiedFilter(t *testing.T) {
	tests := []struct {
		name       string
		attach     func(*bpfClient) error
		attachCall func(*mock_tc.MockBpfTc)
	}{
		{
			name: "ingress",
			attach: func(client *bpfClient) error {
				_, err := client.attachIngressBPFProbe("mockedveth0", "sample-pod-default")
				return err
			},
			attachCall: func(mockTCClient *mock_tc.MockBpfTc) {
				mockTCClient.EXPECT().TCEgressAttach("mockedveth0", 3, utils.TC_INGRESS_PROG).Return(errors.New(utils.ErrFileExists))
				mockTCClient.EXPECT().TCEgressDetach(gomock.Any()).Times(0)
			},
		},
		{
			name: "egress",
			attach: func(client *bpfClient) error {
				_, err := client.attachEgressBPFProbe("mockedveth0", "sample-pod-default")
				return err
			},
			attachCall: func(mockTCClient *mock_tc.MockBpfTc) {
				mockTCClient.EXPECT().TCIngressAttach("mockedveth0", 3, utils.TC_EGRESS_PROG).Return(errors.New(utils.ErrFileExists))
				mockTCClient.EXPECT().TCIngressDetach(gomock.Any()).Times(0)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockTCClient := mock_tc.NewMockBpfTc(ctrl)
			tt.attachCall(mockTCClient)

			testBpfClient := &bpfClient{
				bpfTCClient:               mockTCClient,
				policyEndpointeBPFContext: new(sync.Map),
			}
			testBpfClient.policyEndpointeBPFContext.Store("sample-pod-default", BPFContext{
				ingressPgmInfo: goelf.BpfData{Program: goebpfprogs.BpfProgram{ProgFD: 3}},
				egressPgmInfo:  goelf.BpfData{Program: goebpfprogs.BpfProgram{ProgFD: 3}},
			})

			assert.EqualError(t, tt.attach(testBpfClient), utils.ErrFileExists)
		})
	}
}

func TestRecoverBPFState(t *testing.T) {
	originalNewInMemoryBpfMap := newInMemoryBpfMap
	t.Cleanup(func() { newInMemoryBpfMap = originalNewInMemoryBpfMap })
	newInMemoryBpfMap = func(bpfMap *goebpfmaps.BpfMap) (*InMemoryBpfMap, error) {
		return &InMemoryBpfMap{
			bpfMap:   bpfMap,
			contents: make(map[string][]byte),
		}, nil
	}

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
		"/sys/fs/bpf/globals/aws/programs/hello-udp-748dc8d996-default_handle_ingress": testBPFData("ingress", 1),
		"/sys/fs/bpf/globals/aws/programs/hello-udp-748dc8d996-default_handle_egress":  testBPFData("egress", 2),
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
					"/sys/fs/bpf/globals/aws/programs/hello-udp-1234-default_handle_ingress": testBPFData("ingress", 3),
					"/sys/fs/bpf/globals/aws/programs/hello-udp-1234-default_handle_egress":  testBPFData("egress", 4),
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
						egressProbeFd:  4,
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

func TestRecoverBPFStateRejectsIncompleteMapSet(t *testing.T) {
	const podIdentifier = "hello-udp-748dc8d996-default"
	pinPath := utils.GetBPFPinPathFromPodIdentifier(podIdentifier, "ingress")
	incomplete := testBPFData("ingress", 1)
	delete(incomplete.Maps, utils.TC_INGRESS_POD_STATE_MAP)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockBpfClient := mock_bpfclient.NewMockBpfSDKClient(ctrl)
	mockBpfClient.EXPECT().RecoverGlobalMaps().Return(nil, nil)
	mockBpfClient.EXPECT().RecoverAllBpfProgramsAndMaps().Return(map[string]goelf.BpfData{
		pinPath: incomplete,
	}, nil)

	context := new(sync.Map)
	_, _, _, _, _, err := NewMockBpfClient().recoverBPFState(
		mock_tc.NewMockBpfTc(ctrl),
		mockBpfClient,
		context,
		new(sync.Map),
		false,
		false,
		false,
	)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), utils.TC_INGRESS_POD_STATE_MAP)
	assert.Equal(t, 0, sizeOfSyncMap(context), "invalid recovered state must not be published")
}

func TestRecoverBPFStateRejectsMissingDirection(t *testing.T) {
	const podIdentifier = "hello-udp-748dc8d996-default"
	ingressPinPath := utils.GetBPFPinPathFromPodIdentifier(podIdentifier, "ingress")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockBpfClient := mock_bpfclient.NewMockBpfSDKClient(ctrl)
	mockBpfClient.EXPECT().RecoverGlobalMaps().Return(nil, nil)
	mockBpfClient.EXPECT().RecoverAllBpfProgramsAndMaps().Return(map[string]goelf.BpfData{
		ingressPinPath: testBPFData("ingress", 1),
	}, nil)

	client := NewMockBpfClient()
	context := new(sync.Map)
	_, _, _, _, _, err := client.recoverBPFState(
		mock_tc.NewMockBpfTc(ctrl),
		mockBpfClient,
		context,
		new(sync.Map),
		false,
		false,
		false,
	)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing egress direction")
	assert.Equal(t, 0, sizeOfSyncMap(context), "incomplete recovered directions must not be published")
	assert.Equal(t, 0, sizeOfSyncMap(client.ingressInMemoryMap))
	assert.Equal(t, 0, sizeOfSyncMap(client.egressInMemoryMap))
}

func TestRecoverBPFStateRejectsShadowHydrationFailure(t *testing.T) {
	const podIdentifier = "hello-udp-748dc8d996-default"
	programAndMaps := map[string]goelf.BpfData{
		utils.GetBPFPinPathFromPodIdentifier(podIdentifier, "ingress"): testBPFData("ingress", 1),
		utils.GetBPFPinPathFromPodIdentifier(podIdentifier, "egress"):  testBPFData("egress", 2),
	}

	originalNewInMemoryBpfMap := newInMemoryBpfMap
	t.Cleanup(func() { newInMemoryBpfMap = originalNewInMemoryBpfMap })
	newInMemoryBpfMap = func(*goebpfmaps.BpfMap) (*InMemoryBpfMap, error) {
		return nil, errors.New("shadow hydration failed")
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockBpfClient := mock_bpfclient.NewMockBpfSDKClient(ctrl)
	mockBpfClient.EXPECT().RecoverGlobalMaps().Return(nil, nil)
	mockBpfClient.EXPECT().RecoverAllBpfProgramsAndMaps().Return(programAndMaps, nil)

	client := NewMockBpfClient()
	context := new(sync.Map)
	_, _, _, _, _, err := client.recoverBPFState(
		mock_tc.NewMockBpfTc(ctrl),
		mockBpfClient,
		context,
		new(sync.Map),
		false,
		false,
		false,
	)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "shadow hydration failed")
	assert.Equal(t, 0, sizeOfSyncMap(context), "failed shadow hydration must not publish context")
	assert.Equal(t, 0, sizeOfSyncMap(client.ingressInMemoryMap))
	assert.Equal(t, 0, sizeOfSyncMap(client.egressInMemoryMap))
	assert.Equal(t, 0, sizeOfSyncMap(client.clusterPolicyIngressInMemoryMap))
	assert.Equal(t, 0, sizeOfSyncMap(client.clusterPolicyEgressInMemoryMap))
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
					utils.TC_INGRESS_MAP:                {MapFD: 100},
					utils.TC_CLUSTER_POLICY_INGRESS_MAP: {MapFD: 101},
					utils.TC_INGRESS_POD_STATE_MAP:      {MapFD: 102},
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
					utils.TC_EGRESS_MAP:                {MapFD: 110},
					utils.TC_CLUSTER_POLICY_EGRESS_MAP: {MapFD: 111},
					utils.TC_EGRESS_POD_STATE_MAP:      {MapFD: 112},
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
		podIdentifierLock:         new(sync.Map),
		isMultiNICEnabled:         true,
		ingressBinary:             "tc.v4ingress.bpf.o",
		egressBinary:              "tc.v4egress.bpf.o",
		deletedPods:               new(sync.Map),
	}

	utils.GetHostVethName = func(podName, podNamespace string, interfaceIndex int, interfacePrefixes []string) (string, error) {
		return fmt.Sprintf("mockedveth%d", interfaceIndex), nil
	}

	err := testBpfClient.AttacheBPFProbes(testPod, podIdentifier, 2)
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
		podIdentifierLock: new(sync.Map),
		deletedPods:       new(sync.Map),
		bpfTCClient:       mockTCClient,
	}

	pod := types.NamespacedName{Name: "nginx-abc123", Namespace: "default"}
	testBpfClient.deletedPods.Store(utils.GetPodNamespacedName(pod.Name, pod.Namespace), time.Now())

	err := testBpfClient.AttacheBPFProbes(pod, utils.GetPodIdentifier(pod.Name, pod.Namespace), 1)
	assert.NoError(t, err)
}

func TestAttacheBPFProbes_ProceedsAfterClearDeletedPod(t *testing.T) {
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
		podIdentifierLock:         new(sync.Map),
		deletedPods:               new(sync.Map),
	}
	testBpfClient.policyEndpointeBPFContext.Store(podIdentifier, BPFContext{
		ingressPgmInfo: goelf.BpfData{Program: goebpfprogs.BpfProgram{ProgID: 2, ProgFD: 3}},
		egressPgmInfo:  goelf.BpfData{Program: goebpfprogs.BpfProgram{ProgID: 4, ProgFD: 5}},
	})
	utils.GetHostVethName = func(_, _ string, _ int, _ []string) (string, error) {
		return "mockedveth0", nil
	}

	// Delete then clear — simulates CNI DEL followed by CNI ADD
	testBpfClient.deletedPods.Store(podNamespacedName, time.Now())
	testBpfClient.ClearDeletedPod(podNamespacedName)

	err := testBpfClient.AttacheBPFProbes(pod, podIdentifier, 1)
	assert.NoError(t, err)

	_, attached := testBpfClient.ingressPodToProgMap.Load(podNamespacedName)
	assert.True(t, attached)
}

func TestDeleteBPFProbes_AddsPodToDeletedMap(t *testing.T) {
	testBpfClient := &bpfClient{
		ingressPodToProgMap:  new(sync.Map),
		egressPodToProgMap:   new(sync.Map),
		ingressProgToPodsMap: new(sync.Map),
		egressProgToPodsMap:  new(sync.Map),
		podIdentifierLock:    new(sync.Map),
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

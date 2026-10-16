package ebpf

import (
	"fmt"
	"math/rand"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	goelf "github.com/aws/aws-ebpf-sdk-go/pkg/elfparser"
	mock_bpfclient "github.com/aws/aws-ebpf-sdk-go/pkg/elfparser/mocks"
	goebpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	goebpfprogs "github.com/aws/aws-ebpf-sdk-go/pkg/progs"
	mock_tc "github.com/aws/aws-ebpf-sdk-go/pkg/tc/mocks"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/types"
)

// shadowMapsMatchContext reports whether podIdentifier's cached shadow maps all
// wrap the kernel maps its current context points at, and that no shadow map
// is cached once the context is gone. Callers must hold the identifier lock.
func shadowMapsMatchContext(client *bpfClient, podIdentifier string) error {
	value, hasContext := client.policyEndpointeBPFContext.Load(podIdentifier)
	caches := []struct {
		cache   *sync.Map
		mapName string
		egress  bool
	}{
		{client.ingressInMemoryMap, utils.TC_INGRESS_MAP, false},
		{client.egressInMemoryMap, utils.TC_EGRESS_MAP, true},
		{client.clusterPolicyIngressInMemoryMap, utils.TC_CLUSTER_POLICY_INGRESS_MAP, false},
		{client.clusterPolicyEgressInMemoryMap, utils.TC_CLUSTER_POLICY_EGRESS_MAP, true},
	}
	for _, c := range caches {
		cached, ok := c.cache.Load(podIdentifier)
		if !ok {
			continue
		}
		if !hasContext {
			return fmt.Errorf("%s: shadow map for %s cached without a context", podIdentifier, c.mapName)
		}
		pgm := value.(BPFContext).ingressPgmInfo
		if c.egress {
			pgm = value.(BPFContext).egressPgmInfo
		}
		got, want := cached.(*InMemoryBpfMap).GetUnderlyingMap().MapID, pgm.Maps[c.mapName].MapID
		if got != want {
			return fmt.Errorf("%s: shadow map for %s wraps map ID %d, context has %d", podIdentifier, c.mapName, got, want)
		}
	}
	return nil
}

// Randomized concurrency check for issue #676: CNI ADD/DEL, reconciler
// attaches and every map writer run concurrently over a few identifiers,
// while a checker repeatedly takes each identifier's lock and asserts its
// shadow maps match its context. Program loads hand out fresh map IDs and
// real (disposable) FDs, so teardown closes descriptors the test owns.
func TestBpfClient_ConcurrentLifecycleKeepsShadowMapsConsistent(t *testing.T) {
	client, seed := newRaceTestBpfClient(t)
	client.ingressBinary, client.egressBinary = "ingress.bpf.o", "egress.bpf.o"
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	var mapIDs uint32
	nextMap := func() goebpfmaps.BpfMap { return goebpfmaps.BpfMap{MapID: atomic.AddUint32(&mapIDs, 1)} }
	mockSDKClient := mock_bpfclient.NewMockBpfSDKClient(ctrl)
	mockSDKClient.EXPECT().LoadBpfFile(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(file, podIdentifier string) (map[string]goelf.BpfData, map[string]goebpfmaps.BpfMap, error) {
			fd, err := syscall.Open(os.DevNull, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
			if err != nil {
				return nil, nil, err
			}
			direction, maps := "ingress", map[string]goebpfmaps.BpfMap{
				utils.TC_INGRESS_MAP: nextMap(), utils.TC_CLUSTER_POLICY_INGRESS_MAP: nextMap(), utils.TC_INGRESS_POD_STATE_MAP: nextMap(),
			}
			if file == client.egressBinary {
				direction, maps = "egress", map[string]goebpfmaps.BpfMap{
					utils.TC_EGRESS_MAP: nextMap(), utils.TC_CLUSTER_POLICY_EGRESS_MAP: nextMap(), utils.TC_EGRESS_POD_STATE_MAP: nextMap(),
				}
			}
			pinPath := utils.GetBPFPinPathFromPodIdentifier(podIdentifier, direction)
			return map[string]goelf.BpfData{pinPath: {Program: goebpfprogs.BpfProgram{ProgFD: fd}, Maps: maps}}, nil, nil
		})
	mockTCClient := mock_tc.NewMockBpfTc(ctrl)
	mockTCClient.EXPECT().TCIngressAttach(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(nil)
	mockTCClient.EXPECT().TCEgressAttach(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(nil)
	client.bpfSDKClient = mockSDKClient
	client.bpfTCClient = mockTCClient

	origGetHostVethName := utils.GetHostVethName
	defer func() { utils.GetHostVethName = origGetHostVethName }()
	utils.GetHostVethName = func(string, string, int, []string) (string, error) { return "mockedveth0", nil }
	origNewInMemoryBpfMap := newInMemoryBpfMap
	defer func() { newInMemoryBpfMap = origNewInMemoryBpfMap }()
	newInMemoryBpfMap = func(bpfMap *goebpfmaps.BpfMap) (*InMemoryBpfMap, error) {
		time.Sleep(time.Duration(rand.Intn(200)) * time.Microsecond) // widen the hydrate window
		return seededShadowMap(seed)(bpfMap)
	}

	const identifiers, podsPerIdentifier, workers, opsPerWorker = 3, 3, 12, 400
	pod := func(i, j int) types.NamespacedName {
		return types.NamespacedName{Name: fmt.Sprintf("ds%d-p%d", i, j), Namespace: "ns"}
	}
	ident := func(i int) string { return utils.GetPodIdentifier(pod(i, 0).Name, "ns") }

	var violations int32
	var firstViolation atomic.Value
	stop := make(chan struct{})
	checkerDone := make(chan struct{})
	go func() {
		defer close(checkerDone)
		for {
			select {
			case <-stop:
				return
			default:
			}
			for i := 0; i < identifiers; i++ {
				client.podIdentifierLocks.Lock(ident(i))
				if err := shadowMapsMatchContext(client, ident(i)); err != nil {
					if atomic.AddInt32(&violations, 1) == 1 {
						firstViolation.Store(err.Error())
					}
				}
				client.podIdentifierLocks.Unlock(ident(i))
			}
		}
	}()

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(seedValue int64) {
			defer wg.Done()
			r := rand.New(rand.NewSource(seedValue))
			for op := 0; op < opsPerWorker; op++ {
				i, j := r.Intn(identifiers), r.Intn(podsPerIdentifier)
				switch r.Intn(6) {
				case 0: // CNI ADD
					_, _ = client.AttacheBPFProbes(pod(i, j), ident(i), INTERFACE_COUNT_DEFAULT, true)
				case 1: // reconciler attach
					_, _ = client.AttacheBPFProbes(pod(i, j), ident(i), INTERFACE_COUNT_DEFAULT, false)
				case 2: // CNI DEL
					_ = client.DeleteBPFProbes(pod(i, j), ident(i))
				case 3:
					_ = client.UpdateEbpfMaps(ident(i), nil, nil)
				case 4:
					_ = client.UpdateClusterPolicyEbpfMaps(ident(i), nil, nil)
				case 5:
					_ = client.UpdatePodStateEbpfMaps(ident(i), POD_STATE_MAP_KEY, POLICIES_APPLIED, true, true)
				}
			}
		}(int64(w + 1))
	}
	wg.Wait()
	close(stop)
	<-checkerDone

	for i := 0; i < identifiers; i++ {
		assert.NoError(t, shadowMapsMatchContext(client, ident(i)))
	}
	assert.Zero(t, atomic.LoadInt32(&violations), "first violation: %v", firstViolation.Load())
	assert.Zero(t, client.podIdentifierLocks.len(), "lock entries leaked")

	// Close the program FDs still held by live contexts.
	client.policyEndpointeBPFContext.Range(func(_, value any) bool {
		for _, fd := range []int{value.(BPFContext).ingressPgmInfo.Program.ProgFD, value.(BPFContext).egressPgmInfo.Program.ProgFD} {
			if fd > 0 {
				_ = syscall.Close(fd)
			}
		}
		return true
	})
}

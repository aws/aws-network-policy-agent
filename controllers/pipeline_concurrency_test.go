package controllers

import (
	"context"
	"fmt"
	"math/rand"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/require"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// The pipeline's claim: stage 1 on one worker and stage 2 on many still converge to the state a
// single-threaded rebuild produces from the final API contents. These tests drive random
// policy churn through that setup and check exactly that once everything has quiesced. Run
// them with -race.

// Few policies and short runs per seed, so a stale write is less likely to be masked by a
// later change that happens to reprogram the same identifier; many seeds for coverage.
const (
	stressNamespace  = "stress"
	stressPolicies   = 3
	stressWorkloads  = 4
	stressSeeds      = 40
	stressSteps      = 40
	stressWorkers    = 8
	stressQuiescence = 20 * time.Second
)

var stressCIDRs = []string{"10.0.0.0/8", "10.1.0.0/16", "172.16.0.0/12", "192.168.1.0/24", "192.168.2.2/32"}

func stressScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, policyk8sawsv1.AddToScheme(scheme))
	return scheme
}

// stressPods are each workload's replicas: one on this node and one elsewhere, sharing an
// identifier, plus a local-only replica so an identifier can be selected on this node by
// one slice and elsewhere by another.
func stressPods(workload int) []policyk8sawsv1.PodEndpoint {
	name := fmt.Sprintf("w%d", workload)
	return []policyk8sawsv1.PodEndpoint{
		{Name: name + "-local1", Namespace: stressNamespace, HostIP: policyk8sawsv1.NetworkAddress(fixtureNodeIP), PodIP: policyk8sawsv1.NetworkAddress(fmt.Sprintf("10.10.%d.1", workload))},
		{Name: name + "-local2", Namespace: stressNamespace, HostIP: policyk8sawsv1.NetworkAddress(fixtureNodeIP), PodIP: policyk8sawsv1.NetworkAddress(fmt.Sprintf("10.10.%d.2", workload))},
		{Name: name + "-remote", Namespace: stressNamespace, HostIP: policyk8sawsv1.NetworkAddress(fixtureRemoteIP), PodIP: policyk8sawsv1.NetworkAddress(fmt.Sprintf("10.20.%d.1", workload))},
	}
}

// stressSlice is the test's model of one PolicyEndpoint.
type stressSlice struct {
	name    string
	parent  string
	present bool
	members map[int][]bool // workload -> which of its replicas are selected
	ingress []string
	egress  []string
	isolate bool
}

func (s *stressSlice) object() *policyk8sawsv1.PolicyEndpoint {
	pe := &policyk8sawsv1.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: s.name, Namespace: stressNamespace},
		Spec: policyk8sawsv1.PolicyEndpointSpec{
			PodSelector: &metav1.LabelSelector{},
			PolicyRef:   policyk8sawsv1.PolicyReference{Name: s.parent, Namespace: stressNamespace},
		},
	}
	for w := 0; w < stressWorkloads; w++ {
		for i, pod := range stressPods(w) {
			if !s.members[w][i] {
				continue
			}
			// A policy that selects a workload only on another node leaves the rules this
			// node holds for it as they were when the policy stops selecting it, so the final
			// state would depend on the order of events; only list a remote replica together
			// with a local one of the same workload.
			if i == 2 && !s.members[w][0] && !s.members[w][1] {
				continue
			}
			pe.Spec.PodSelectorEndpoints = append(pe.Spec.PodSelectorEndpoints, pod)
		}
	}
	for _, cidr := range s.ingress {
		pe.Spec.Ingress = append(pe.Spec.Ingress, policyk8sawsv1.EndpointInfo{CIDR: policyk8sawsv1.NetworkAddress(cidr)})
	}
	for _, cidr := range s.egress {
		pe.Spec.Egress = append(pe.Spec.Egress, policyk8sawsv1.EndpointInfo{CIDR: policyk8sawsv1.NetworkAddress(cidr)})
	}
	if s.isolate {
		pe.Spec.PodIsolation = []networking.PolicyType{networking.PolicyTypeIngress, networking.PolicyTypeEgress}
	}
	return pe
}

func randomCIDRs(rng *rand.Rand) []string {
	var cidrs []string
	for _, cidr := range stressCIDRs {
		if rng.Intn(3) == 0 {
			cidrs = append(cidrs, cidr)
		}
	}
	return cidrs
}

// programmingWorkers runs n workers on r's programming queue the way the programming
// controller does, until stop is called. quiesce waits until the queue is empty and no pass
// is in flight.
type programmingWorkers struct {
	inflight atomic.Int64
	wg       sync.WaitGroup
	stop     func()
	quiesce  func(t *testing.T)
}

func runProgrammingWorkers(ctx context.Context, r *PolicyEndpointsReconciler, n int) *programmingWorkers {
	w := &programmingWorkers{}
	for i := 0; i < n; i++ {
		w.wg.Add(1)
		go func() {
			defer w.wg.Done()
			for {
				podIdentifier, shutdown := r.programQueue.Get()
				if shutdown {
					return
				}
				w.inflight.Add(1)
				if err := r.programIdentifier(ctx, podIdentifier); err != nil {
					r.programQueue.AddRateLimited(podIdentifier)
				} else {
					r.programQueue.Forget(podIdentifier)
				}
				r.programQueue.Done(podIdentifier)
				w.inflight.Add(-1)
			}
		}()
	}
	w.stop = func() {
		r.programQueue.ShutDown()
		w.wg.Wait()
	}
	w.quiesce = func(t *testing.T) {
		t.Helper()
		deadline := time.Now().Add(stressQuiescence)
		stable := 0
		for stable < 3 {
			require.True(t, time.Now().Before(deadline), "programming did not quiesce")
			if r.programQueue.Len() == 0 && w.inflight.Load() == 0 {
				stable++
			} else {
				stable = 0
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	return w
}

// stressState is what one identifier's maps hold.
type stressState struct {
	ingress, egress []string
	podState        int
}

func stateOf(bpf *ebpf.MockBpfClient, podIdentifier string) stressState {
	state, ok := bpf.PodStateByIdentifier[ebpf.PodStateKey{PodIdentifier: podIdentifier, MapKey: ebpf.POD_STATE_MAP_KEY}]
	if !ok {
		// Never written, which a sequential rebuild leaves at the baseline too.
		state = DEFAULT_ALLOW
	}
	ingress, egress := cidrsOf(bpf.IngressByIdentifier[podIdentifier]), cidrsOf(bpf.EgressByIdentifier[podIdentifier])
	slices.Sort(ingress)
	slices.Sort(egress)
	return stressState{ingress: ingress, egress: egress, podState: state}
}

// The even workloads' pods are attached up front, as their CNI ADDs would have left them, so
// programming reaches them only through stage 1's queueing. The odd workloads' pods are first
// attached by a programming pass, which stage 1 can run alongside. That interleaving is rare
// here; TestProgramIdentifier_DeselectionDuringFirstAttachIsRewritten forces it.
func TestPipeline_ConcurrentProgrammingMatchesSequentialRebuild(t *testing.T) {
	for seed := int64(1); seed <= stressSeeds; seed++ {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			runPipelineStress(t, seed)
		})
	}
}

func runPipelineStress(t *testing.T, seed int64) {
	rng := rand.New(rand.NewSource(seed))
	ctx := context.Background()
	scheme := stressScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	bpf := &ebpf.MockBpfClient{}
	r := NewPolicyEndpointsReconciler(k8sClient, fixtureNodeIP, bpf, false)
	workers := runProgrammingWorkers(ctx, r, stressWorkers)
	defer workers.stop()

	var model []*stressSlice
	for p := 0; p < stressPolicies; p++ {
		for _, suffix := range []string{"aaaaa", "bbbbb"} {
			s := &stressSlice{name: fmt.Sprintf("np-%d-%s", p, suffix), parent: fmt.Sprintf("np-%d", p),
				members: map[int][]bool{}, ingress: randomCIDRs(rng), egress: randomCIDRs(rng)}
			for w := 0; w < stressWorkloads; w++ {
				s.members[w] = []bool{rng.Intn(3) == 0, rng.Intn(3) == 0, rng.Intn(3) == 0}
			}
			model = append(model, s)
		}
	}

	// apply writes s to the fake API server and runs stage 1 for every parent the event names,
	// as the endpoint event handler would.
	apply := func(s *stressSlice, oldParent string) {
		existing := &policyk8sawsv1.PolicyEndpoint{}
		err := k8sClient.Get(ctx, types.NamespacedName{Name: s.name, Namespace: stressNamespace}, existing)
		switch {
		case !s.present && err == nil:
			require.NoError(t, k8sClient.Delete(ctx, existing))
		case s.present && err == nil:
			obj := s.object()
			obj.ResourceVersion = existing.ResourceVersion
			require.NoError(t, k8sClient.Update(ctx, obj))
		case s.present:
			require.NoError(t, k8sClient.Create(ctx, s.object()))
		}
		for _, parent := range uniqueStrings(oldParent, s.parent) {
			require.NoError(t, r.reconcile(ctx, EndpointRequest{
				Endpoint: types.NamespacedName{Name: s.name, Namespace: stressNamespace}, Parent: parent}))
		}
	}

	for w := 0; w < stressWorkloads; w += 2 {
		for _, pod := range stressPods(w)[:2] {
			_, err := bpf.AttacheBPFProbes(types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace},
				utils.GetPodIdentifier(pod.Name, pod.Namespace), ebpf.INTERFACE_COUNT_UNKNOWN, true)
			require.NoError(t, err)
		}
	}

	for _, s := range model {
		s.present = rng.Intn(4) != 0
		apply(s, s.parent)
	}
	for step := 0; step < stressSteps; step++ {
		s := model[rng.Intn(len(model))]
		oldParent := s.parent
		switch op := rng.Intn(10); {
		case op < 4:
			w := rng.Intn(stressWorkloads)
			replica := rng.Intn(3)
			s.members[w][replica] = !s.members[w][replica]
		case op < 6:
			s.ingress, s.egress = randomCIDRs(rng), randomCIDRs(rng)
		case op == 6:
			s.isolate = !s.isolate
		case op == 7:
			s.present = !s.present
		case op == 8:
			// The slice name moves to another parent, as a delete and recreate folded by a relist.
			s.parent = fmt.Sprintf("np-%d", rng.Intn(stressPolicies))
		default:
			// A resync of an unchanged slice.
		}
		apply(s, oldParent)
		if rng.Intn(20) == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	workers.quiesce(t)

	// Rebuild from the final API contents on one thread, with the same pods attached.
	oracleBPF := &ebpf.MockBpfClient{}
	var identifiers []string
	for w := 0; w < stressWorkloads; w++ {
		podIdentifier := utils.GetPodIdentifier(stressPods(w)[0].Name, stressNamespace)
		identifiers = append(identifiers, podIdentifier)
		if bpf.HasBPFContext(podIdentifier) {
			oracleBPF.AttachIdentifier(podIdentifier)
		}
	}
	oracle := newTestPolicyEndpointsReconciler(t, k8sClient, fixtureNodeIP, oracleBPF, false)
	list := &policyk8sawsv1.PolicyEndpointList{}
	require.NoError(t, k8sClient.List(ctx, list, client.InNamespace(stressNamespace)))
	for i := range list.Items {
		require.NoError(t, oracle.reconcileAndProgram(ctx, peRequestOf(&list.Items[i])))
	}

	for _, podIdentifier := range identifiers {
		require.Equal(t, stateOf(oracleBPF, podIdentifier), stateOf(bpf, podIdentifier),
			"seed %d: %s's maps differ from a sequential rebuild of the final policies", seed, podIdentifier)
	}
}

func uniqueStrings(values ...string) []string {
	return slices.Compact(slices.Sorted(slices.Values(values)))
}

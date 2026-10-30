package controllers

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"sort"
	"strconv"
	"testing"

	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"k8s.io/apimachinery/pkg/types"
)

// Randomized model check of the namespaced policy reconciler, mirroring
// TestClusterPolicySlices_Randomized. Each seed runs a random sequence of slice changes,
// map-write failures, pods leaving the node and duplicate events, reconciling the slices that
// changed and retrying the ones that errored, as the workqueue does. Once failures stop the
// queue must drain, and every identifier that still has programs on the node must hold
// exactly the rules of the parents that select it.
//
// PE_RANDOM_SEEDS and PE_RANDOM_START widen or move the seed range for deeper runs.
func TestPolicySlices_Randomized(t *testing.T) {
	seeds, start := 300, 1
	if v, err := strconv.Atoi(os.Getenv("PE_RANDOM_SEEDS")); err == nil {
		seeds = v
	}
	if v, err := strconv.Atoi(os.Getenv("PE_RANDOM_START")); err == nil {
		start = v
	}
	for seed := start; seed < start+seeds; seed++ {
		seed := int64(seed)
		t.Run(fmt.Sprint(seed), func(t *testing.T) { runRandomizedPolicy(t, seed) })
	}
}

// catchAllCIDR is appended by the reconciler for any direction the policy does not isolate.
// The fixture leaves Spec.PodIsolation unset, so it is always present and is filtered out of
// the rule comparison below.
const catchAllCIDR = "0.0.0.0/0"

func policyCIDRs(rules []fwrp.EbpfFirewallRules) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		if string(r.IPCidr) == catchAllCIDR {
			continue
		}
		out = append(out, string(r.IPCidr))
	}
	return out
}

func runRandomizedPolicy(t *testing.T, seed int64) {
	rng := rand.New(rand.NewSource(seed))
	fx := newPEFixture(t)
	writeFailed := errors.New("injected map write failure")

	workloads := []string{"wa", "wb", "wc", "wd"}
	idOf := func(w string) string { return identifierOf(w + "-x") }
	// Logical slices; a recreated slice gets a new name, as GenerateName gives it.
	slices := []string{"np-1/a", "np-1/b", "np-1/c", "np-2/a", "np-2/b", "np-3/a"}
	parentOf := func(s string) string { return s[:4] }

	type sliceState struct {
		present bool
		gen     int
		members map[string]bool
		rule    int // version of the slice's rules
	}
	st := map[string]*sliceState{}
	for _, s := range slices {
		st[s] = &sliceState{members: map[string]bool{}}
	}
	apiName := func(s string) string { return fmt.Sprintf("%s-%s%d", parentOf(s), s[5:], st[s].gen) }
	// NetworkPolicy rules are allow-only, so only the CIDR varies.
	ruleOf := func(s string, egress bool) ruleRef {
		i := map[string]int{"np-1/a": 1, "np-1/b": 2, "np-1/c": 3, "np-2/a": 4, "np-2/b": 5, "np-3/a": 6}[s]
		dir := 0
		if egress {
			dir = 100
		}
		return allow(fmt.Sprintf("10.%d.%d.0/24", dir+i, st[s].rule))
	}

	podGen := map[string]int{}
	local := map[string]bool{}
	for _, w := range workloads {
		podGen[w] = 1
		local[w] = rng.Intn(3) != 0
	}
	podName := func(w string) string { return fmt.Sprintf("%s-g%d", w, podGen[w]) }

	specs := func() []sliceSpec {
		var out []sliceSpec
		for _, s := range slices {
			ss := st[s]
			if !ss.present {
				continue
			}
			var pods []podRef
			for i, w := range workloads {
				if !ss.members[w] {
					continue
				}
				ip := fmt.Sprintf("10.200.%d.%d", i+1, podGen[w])
				if local[w] {
					pods = append(pods, localPod(podName(w), ip))
				} else {
					pods = append(pods, remotePod(podName(w), ip))
				}
			}
			out = append(out, sliceSpec{name: apiName(s), parent: parentOf(s), pods: pods,
				ingress: []ruleRef{ruleOf(s, false)}, egress: []ruleRef{ruleOf(s, true)}})
		}
		return out
	}

	var trace []string
	logf := func(f string, a ...interface{}) { trace = append(trace, fmt.Sprintf(f, a...)) }
	t.Cleanup(func() {
		if t.Failed() {
			for _, l := range trace {
				t.Log(l)
			}
		}
	})

	dirty := map[string]bool{}
	pendingDelete := map[string]bool{}
	apply := func() {
		before := fx.store
		fx.setSlices(specs()...)
		for name, pe := range fx.store {
			if old, ok := before[name]; !ok || !reflect.DeepEqual(old.Spec, pe.Spec) {
				dirty[name] = true
			}
		}
		for name := range before {
			if _, ok := fx.store[name]; !ok {
				pendingDelete[name] = true
				delete(dirty, name)
			}
		}
	}

	var failing map[string]bool
	injected := func() bool { return len(failing) > 0 }
	reconcile := func(c string) error {
		name := c[2:]
		var err error
		if c[0] == 'R' {
			// Every identifier the parent selects on this node must be programmed in this
			// pass, whatever else fails: that is what keeps one failure from stalling the
			// node. Drop its last write so the check sees only what this pass wrote.
			var mustProgram []string
			saved := map[string][]fwrp.EbpfFirewallRules{}
			parent := fx.store[name].Spec.PolicyRef.Name
			seen := map[string]bool{}
			for _, pe := range fx.store {
				if pe.Spec.PolicyRef.Name != parent {
					continue
				}
				for _, ep := range pe.Spec.PodSelectorEndpoints {
					id := identifierOf(ep.Name)
					if string(ep.HostIP) != fixtureNodeIP || seen[id] || failing[id] ||
						fx.bpf.DeletedPods[types.NamespacedName{Name: ep.Name, Namespace: ep.Namespace}] {
						continue
					}
					seen[id] = true
					mustProgram = append(mustProgram, id)
					if r, ok := fx.bpf.IngressByIdentifier[id]; ok {
						saved[id] = r
					}
					delete(fx.bpf.IngressByIdentifier, id)
				}
			}
			if err = fx.reconcile(name); err == nil {
				delete(dirty, name)
			}
			for _, id := range mustProgram {
				if _, ok := fx.bpf.IngressByIdentifier[id]; !ok {
					t.Errorf("%s did not program %s (err %v, failing %v)", c, id, err, failing)
					if r, had := saved[id]; had {
						fx.bpf.IngressByIdentifier[id] = r
					}
				}
			}
		} else if err = fx.reconcileDeleted(name); err == nil {
			delete(pendingDelete, name)
		}
		if err != nil && !injected() {
			t.Errorf("%s failed with no failure injected: %v", c, err)
		}
		logf("%s -> %v", c, err)
		return err
	}
	queued := func() []string {
		var cands []string
		for n := range dirty {
			cands = append(cands, "R:"+n)
		}
		for n := range pendingDelete {
			cands = append(cands, "D:"+n)
		}
		sort.Strings(cands)
		return cands
	}

	for _, s := range slices {
		st[s].present = rng.Intn(4) != 0
		for _, w := range workloads {
			st[s].members[w] = rng.Intn(2) == 0
		}
	}
	apply()
	logf("init %v", specs())

	failing = map[string]bool{}
	syncFailures := func() {
		m := map[string]error{}
		for id := range failing {
			m[id] = writeFailed
		}
		fx.bpf.UpdateEbpfMapsErrFor = m
	}

	for step := 0; step < 120; step++ {
		switch op := rng.Intn(14); {
		case op < 5:
			if q := queued(); len(q) > 0 {
				_ = reconcile(q[rng.Intn(len(q))])
			}
		case op == 5:
			s := slices[rng.Intn(len(slices))]
			w := workloads[rng.Intn(len(workloads))]
			st[s].members[w] = !st[s].members[w]
			logf("member %s %s=%v", s, w, st[s].members[w])
			apply()
		case op == 13:
			// A slice's deletion starts while it is still listed: the agent sees it with a
			// DeletionTimestamp and runs the delete flow, then the object goes.
			s := slices[rng.Intn(len(slices))]
			if !st[s].present {
				continue
			}
			_ = reconcile("D:" + apiName(s))
			st[s].present = false
			logf("present %s=false after deletion in progress (%s)", s, apiName(s))
			apply()
		case op == 6 || op == 12:
			s := slices[rng.Intn(len(slices))]
			st[s].present = !st[s].present
			if st[s].present {
				st[s].gen++
			}
			logf("present %s=%v (%s)", s, st[s].present, apiName(s))
			apply()
		case op == 7:
			s := slices[rng.Intn(len(slices))]
			st[s].rule++
			logf("rules %s v%d", s, st[s].rule)
			apply()
		case op == 8:
			id := idOf(workloads[rng.Intn(len(workloads))])
			if failing[id] {
				delete(failing, id)
			} else {
				failing[id] = true
			}
			logf("map writes for %s failing=%v", id, failing[id])
			syncFailures()
		case op == 10:
			// The workload's pod on this node is deleted and its programs torn down. A
			// replacement pod starts here or elsewhere; the PEs catch up later.
			w := workloads[rng.Intn(len(workloads))]
			if !local[w] {
				continue
			}
			id := idOf(w)
			fx.detachContext(id)
			if fx.bpf.DeletedPods == nil {
				fx.bpf.DeletedPods = map[types.NamespacedName]bool{}
			}
			fx.bpf.DeletedPods[types.NamespacedName{Name: podName(w), Namespace: fixtureNamespace}] = true
			delete(fx.bpf.IngressByIdentifier, id)
			delete(fx.bpf.EgressByIdentifier, id)
			podGen[w]++
			local[w] = rng.Intn(2) == 0
			logf("pod %s-g%d left, replacement %s local=%v", w, podGen[w]-1, podName(w), local[w])
			// Half the time the PEs still list the deleted pod until the next change.
			if rng.Intn(2) == 0 {
				apply()
			}
		case op == 11:
			// Duplicate or resync event for a slice that has not changed.
			var names []string
			for n := range fx.store {
				names = append(names, n)
			}
			if len(names) == 0 {
				continue
			}
			sort.Strings(names)
			_ = reconcile("R:" + names[rng.Intn(len(names))])
		default:
			continue
		}
	}

	failing = map[string]bool{}
	syncFailures()
	logf("failures cleared, queued %v", queued())
	for i := 0; i < 200 && len(queued()) > 0; i++ {
		q := queued()
		_ = reconcile(q[rng.Intn(len(q))])
	}
	if q := queued(); len(q) > 0 {
		t.Fatalf("queue did not drain once failures stopped: %v", q)
	}

	check := func(phase string) {
		for _, w := range workloads {
			id := idOf(w)
			if !fx.bpf.HasBPFContext(id) {
				continue
			}
			selectedBy := map[string]bool{}
			selectedHere := false
			for _, s := range slices {
				if st[s].present && st[s].members[w] {
					selectedBy[parentOf(s)] = true
					selectedHere = selectedHere || local[w]
				}
			}
			// Every slice of a selecting parent contributes its rules to the identifier.
			var wantIn, wantEg []string
			for _, s := range slices {
				if st[s].present && selectedBy[parentOf(s)] {
					wantIn = append(wantIn, ruleOf(s, false).cidr)
					wantEg = append(wantEg, ruleOf(s, true).cidr)
				}
			}
			for _, dir := range []struct {
				name string
				got  map[string][]fwrp.EbpfFirewallRules
				want []string
			}{{"ingress", fx.bpf.IngressByIdentifier, wantIn}, {"egress", fx.bpf.EgressByIdentifier, wantEg}} {
				rules, written := dir.got[id]
				if !written {
					if selectedHere {
						t.Errorf("%s: %s is selected on this node but its %s map was never written", phase, id, dir.name)
					}
					continue
				}
				got := policyCIDRs(rules)
				sort.Strings(got)
				sort.Strings(dir.want)
				if len(got)+len(dir.want) > 0 && !reflect.DeepEqual(got, dir.want) {
					t.Errorf("%s: %s %s rules = %v, want %v", phase, id, dir.name, got, dir.want)
				}
			}
		}
	}
	check("after drain")

	// Nothing is tracked for PEs or parents that no longer exist.
	fx.r.policyEndpointSelectorMap.Range(func(k, _ interface{}) bool {
		name, _, _ := splitPolicyEndpointIdentifier(k.(string))
		if _, ok := fx.store[name]; !ok {
			t.Errorf("selector map still tracks deleted PE %s", k)
		}
		return true
	})
	parents := map[string]bool{}
	for _, pe := range fx.store {
		parents[pe.Spec.PolicyRef.Name+"/"+pe.Namespace] = true
	}
	fx.r.networkPolicyToPodIdentifierMap.Range(func(k, _ interface{}) bool {
		if !parents[k.(string)] {
			t.Errorf("parent map still tracks %s, which has no PEs", k)
		}
		return true
	})

	// Reconciling everything again, as a resync would, changes nothing and does not error.
	for _, n := range fx.sliceNames() {
		if err := fx.reconcile(n); err != nil {
			t.Errorf("resync of %s: %v", n, err)
		}
	}
	check("after resync")
}

// splitPolicyEndpointIdentifier reverses utils.GetPolicyEndpointIdentifier, which joins the
// PolicyEndpoint name and namespace with "/".
func splitPolicyEndpointIdentifier(id string) (name, namespace string, ok bool) {
	for i := len(id) - 1; i >= 0; i-- {
		if id[i] == '/' {
			return id[:i], id[i+1:], true
		}
	}
	return id, "", false
}

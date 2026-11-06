package controllers

import (
	"bytes"
	"fmt"
	"maps"
	"math/rand"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

// updatePEs and deletePE drive the shared utils writers against r's pod identifier map.
func updatePEs(r *PolicyEndpointsReconciler, podIdentifier, parent string, parentPEList []string) {
	utils.UpdatePodIdentifierToPolicyEndpointMap(&r.podIdentifierToPolicyEndpointMap,
		&r.podIdentifierToPolicyEndpointMapMutex, podIdentifier, parent, parentPEList)
}

func deletePE(r *PolicyEndpointsReconciler, podIdentifier string, policyEndpoint utils.PolicyEndpointRef) {
	utils.DeletePolicyEndpointFromPodIdentifierMap(&r.podIdentifierToPolicyEndpointMap,
		&r.podIdentifierToPolicyEndpointMapMutex, podIdentifier, policyEndpoint)
}

// TestPodIdentifierPEList_MatchesSetModel drives random update/delete sequences, with slice names
// shared across parents, and requires the stored list to equal a set model after every step:
// sorted by name then parent, free of duplicates, and keyed by the parent as well as the name.
func TestPodIdentifierPEList_MatchesSetModel(t *testing.T) {
	compare := func(a, b utils.PolicyEndpointRef) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return strings.Compare(a.Parent, b.Parent)
	}
	for seed := int64(0); seed < 50; seed++ {
		rng := rand.New(rand.NewSource(seed))
		r := NewPolicyEndpointsReconciler(nil, benchNodeIP, nil, false)
		model := map[string]map[utils.PolicyEndpointRef]bool{}
		identifiers := []string{"a@ns", "b@ns", "c@ns"}
		names := make([]string, 30)
		for i := range names {
			names[i] = fmt.Sprintf("np-%05d", rng.Intn(100000))
		}
		names = slices.Compact(slices.Sorted(slices.Values(names)))
		for step := 0; step < 500; step++ {
			id := identifiers[rng.Intn(len(identifiers))]
			parent := fmt.Sprintf("np-%d", rng.Intn(4))
			if rng.Intn(3) == 0 {
				ref := utils.PolicyEndpointRef{Name: names[rng.Intn(len(names))], Parent: parent}
				deletePE(r, id, ref)
				delete(model[id], ref)
				if len(model[id]) == 0 {
					delete(model, id)
				}
			} else {
				// parentPEList comes from a List, so names are distinct and unordered.
				list := make([]string, 0, 8)
				for _, i := range rng.Perm(len(names))[:1+rng.Intn(8)] {
					list = append(list, names[i])
				}
				updatePEs(r, id, parent, list)
				if model[id] == nil {
					model[id] = map[utils.PolicyEndpointRef]bool{}
				}
				for _, name := range list {
					model[id][utils.PolicyEndpointRef{Name: name, Parent: parent}] = true
				}
			}
			for _, id := range identifiers {
				want, wantOK := model[id]
				got, gotOK := r.podIdentifierToPolicyEndpointMap.Load(id)
				assert.Equal(t, wantOK, gotOK, "seed %d step %d id %s presence", seed, step, id)
				if gotOK {
					assert.Equal(t, slices.SortedFunc(maps.Keys(want), compare), got.([]utils.PolicyEndpointRef), "seed %d step %d id %s", seed, step, id)
				}
			}
		}
	}
}

// TestPodIdentifierPEList_ConcurrentReaders exercises the unlocked readers (the CNI RPC path)
// against writers; run with -race.
func TestPodIdentifierPEList_ConcurrentReaders(t *testing.T) {
	r := NewPolicyEndpointsReconciler(nil, benchNodeIP, nil, false)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var unsorted atomic.Bool
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					r.ArePoliciesAvailableInLocalCache("a@ns")
					if v, ok := r.podIdentifierToPolicyEndpointMap.Load("a@ns"); ok {
						// Read every element, as deriveIngressAndEgressFirewallRules does, so an
						// in-place write to a published list is reported by -race, and check the
						// snapshot is still sorted.
						refs := v.([]utils.PolicyEndpointRef)
						for j := 1; j < len(refs); j++ {
							if refs[j-1].Name > refs[j].Name || refs[j-1] == refs[j] ||
								(refs[j-1].Name == refs[j].Name && refs[j-1].Parent > refs[j].Parent) {
								unsorted.Store(true)
							}
						}
					}
				}
			}
		}()
	}
	for i := 0; i < 2000; i++ {
		parent := fmt.Sprintf("parent-%d", i%3)
		updatePEs(r, "a@ns", parent, []string{fmt.Sprintf("np-%d", i%50), fmt.Sprintf("np-%d", (i+1)%50)})
		if i%3 == 0 {
			deletePE(r, "a@ns", utils.PolicyEndpointRef{Name: fmt.Sprintf("np-%d", i%50), Parent: parent})
		}
	}
	close(stop)
	wg.Wait()
	assert.False(t, unsorted.Load(), "a reader observed an unsorted or duplicated PE list")
}

// normalizeTrieValue sorts the 12-byte L4 entries of an eBPF map value. Entry order within a
// value is already unspecified (mergeDuplicateL4Info builds it from a map).
func normalizeTrieValue(v []byte) []byte {
	var chunks [][]byte
	for i := 0; i+12 <= len(v); i += 12 {
		chunks = append(chunks, v[i:i+12])
	}
	slices.SortFunc(chunks, bytes.Compare)
	return bytes.Join(chunks, nil)
}

// TestFirewallRules_IndependentOfPolicyEndpointOrder checks that the eBPF map entries derived
// from a set of PolicyEndpoints do not depend on the order the PEs are walked in, which changes
// from insertion order to sorted order with the sorted pod identifier PE list.
func TestFirewallRules_IndependentOfPolicyEndpointOrder(t *testing.T) {
	tcp, udp := corev1.ProtocolTCP, corev1.ProtocolUDP
	p := func(proto *corev1.Protocol, port int32) policyk8sawsv1.Port {
		return policyk8sawsv1.Port{Protocol: proto, Port: &port}
	}
	cidrs := []policyk8sawsv1.NetworkAddress{"10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24", "10.1.2.3", "10.1.2.3/32", "10.2.0.0/16", "10.161.0.0/8", "192.168.0.0/16", "192.168.1.1"}
	for seed := int64(0); seed < 100; seed++ {
		rng := rand.New(rand.NewSource(seed))
		var pes [][]policyk8sawsv1.EndpointInfo
		for i := 0; i < 4; i++ {
			var eps []policyk8sawsv1.EndpointInfo
			for j := 0; j < 1+rng.Intn(4); j++ {
				ep := policyk8sawsv1.EndpointInfo{CIDR: cidrs[rng.Intn(len(cidrs))]}
				for k := 0; k < rng.Intn(3); k++ {
					proto := &tcp
					if rng.Intn(2) == 0 {
						proto = &udp
					}
					ep.Ports = append(ep.Ports, p(proto, int32(80+rng.Intn(4))))
				}
				if rng.Intn(4) == 0 {
					ep.Except = []policyk8sawsv1.NetworkAddress{"10.1.2.128/25"}
				}
				eps = append(eps, ep)
			}
			pes = append(pes, eps)
		}
		compute := func(order []int) map[string][]byte {
			var rules []fwrp.EbpfFirewallRules
			for _, i := range order {
				for _, ep := range pes[i] {
					rules = append(rules, fwrp.EbpfFirewallRules{IPCidr: ep.CIDR, Except: slices.Clip(ep.Except), L4Info: slices.Clip(ep.Ports)})
				}
			}
			entries, err := fwrp.NewFirewallRuleProcessor(benchNodeIP, "/32", false).ComputeMapEntriesFromEndpointRules(rules)
			assert.NoError(t, err)
			for k, v := range entries {
				entries[k] = normalizeTrieValue(v)
			}
			return entries
		}
		want := compute([]int{0, 1, 2, 3})
		for perm := 0; perm < 10; perm++ {
			assert.Equal(t, want, compute(rng.Perm(len(pes))), "seed %d", seed)
		}
	}
}

// BenchmarkUpdatePodIdentifierToPEMap models the KWOK scale test: an identifier already
// tracking 600 PEs (5 policies x 120 slices), updated with one policy's 120 slices, once per
// selected pod in that policy's PEs.
//
//	go test ./controllers/ -run '^$' -bench BenchmarkUpdatePodIdentifierToPEMap -benchmem
func BenchmarkUpdatePodIdentifierToPEMap(b *testing.B) {
	slicesOf := func(np int) []string {
		var names []string
		for i := 0; i < 120; i++ {
			names = append(names, fmt.Sprintf("wide-peer-%d-%05d", np, i))
		}
		return names
	}
	r := NewPolicyEndpointsReconciler(nil, benchNodeIP, nil, false)
	for np := 0; np < 5; np++ {
		updatePEs(r, "bulk-6b8f9c7d4@npa-kwok", fmt.Sprintf("wide-peer-%d", np), slicesOf(np))
	}
	parent := slicesOf(2)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		updatePEs(r, "bulk-6b8f9c7d4@npa-kwok", "wide-peer-2", parent)
	}
}

// TestClusterFirewallRules_IndependentOfClusterPolicyEndpointOrder is the cluster policy
// counterpart of TestFirewallRules_IndependentOfPolicyEndpointOrder: the cluster pod identifier
// list is also kept sorted, so CPEs are walked in sorted rather than insertion order.
func TestClusterFirewallRules_IndependentOfClusterPolicyEndpointOrder(t *testing.T) {
	tcp, udp := corev1.ProtocolTCP, corev1.ProtocolUDP
	cidrs := []policyk8sawsv1.NetworkAddress{"10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24", "10.1.2.3", "10.1.2.3/32", "10.2.0.0/16", "10.161.0.0/8", "192.168.0.0/16", "192.168.1.1"}
	actions := []policyk8sawsv1.ClusterNetworkPolicyRuleAction{policyk8sawsv1.ClusterNetworkPolicyRuleActionAccept, policyk8sawsv1.ClusterNetworkPolicyRuleActionDeny, policyk8sawsv1.ClusterNetworkPolicyRuleActionPass}
	// 16-byte entries: protocol, priority, start port, end port.
	normalize := func(v []byte) []byte {
		var chunks [][]byte
		for i := 0; i+16 <= len(v); i += 16 {
			chunks = append(chunks, v[i:i+16])
		}
		slices.SortFunc(chunks, bytes.Compare)
		return bytes.Join(chunks, nil)
	}
	for seed := int64(0); seed < 100; seed++ {
		rng := rand.New(rand.NewSource(seed))
		var cpes [][]fwrp.EbpfFirewallRules
		for i := 0; i < 4; i++ {
			priority := rng.Intn(3)
			var rules []fwrp.EbpfFirewallRules
			for j := 0; j < 1+rng.Intn(4); j++ {
				rule := fwrp.EbpfFirewallRules{Priority: priority, Action: actions[rng.Intn(len(actions))], IPCidr: cidrs[rng.Intn(len(cidrs))]}
				for k := 0; k < rng.Intn(3); k++ {
					proto := &tcp
					if rng.Intn(2) == 0 {
						proto = &udp
					}
					port := int32(80 + rng.Intn(4))
					rule.L4Info = append(rule.L4Info, policyk8sawsv1.Port{Protocol: proto, Port: &port})
				}
				rules = append(rules, rule)
			}
			cpes = append(cpes, rules)
		}
		compute := func(order []int) map[string][]byte {
			var rules []fwrp.EbpfFirewallRules
			for _, i := range order {
				for _, rule := range cpes[i] {
					rule.L4Info = slices.Clip(rule.L4Info)
					rules = append(rules, rule)
				}
			}
			entries, err := fwrp.NewFirewallRuleProcessor(benchNodeIP, "/32", false).ComputeClusterPolicyMapEntriesFromEndpointRules(rules)
			assert.NoError(t, err)
			for k, v := range entries {
				entries[k] = normalize(v)
			}
			return entries
		}
		want := compute([]int{0, 1, 2, 3})
		for perm := 0; perm < 10; perm++ {
			assert.Equal(t, want, compute(rng.Perm(len(cpes))), "seed %d", seed)
		}
	}
}

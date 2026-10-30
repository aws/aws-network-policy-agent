package controllers

import (
	"bytes"
	"fmt"
	"math/rand"
	"slices"
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
func updatePEs(r *PolicyEndpointsReconciler, podIdentifier string, parentPEList []string) {
	utils.UpdatePodIdentifierToPolicyEndpointMap(&r.podIdentifierToPolicyEndpointMap,
		&r.podIdentifierToPolicyEndpointMapMutex, podIdentifier, parentPEList)
}

func deletePE(r *PolicyEndpointsReconciler, podIdentifier string, policyEndpoint string) {
	utils.DeletePolicyEndpointFromPodIdentifierMap(&r.podIdentifierToPolicyEndpointMap,
		&r.podIdentifierToPolicyEndpointMapMutex, podIdentifier, policyEndpoint)
}

// referenceUpdate and referenceDelete are the previous insertion-ordered implementations of
// utils.UpdatePodIdentifierToPolicyEndpointMap and utils.DeletePolicyEndpointFromPodIdentifierMap.
func referenceUpdate(m map[string][]string, podIdentifier string, parentPEList []string) {
	var policyEndpoints []string
	if currentPESet, ok := m[podIdentifier]; ok {
		policyEndpoints = currentPESet
		for _, policyEndpointResourceName := range parentPEList {
			addPEResource := true
			for _, pe := range currentPESet {
				if pe == policyEndpointResourceName {
					addPEResource = false
					break
				}
			}
			if addPEResource {
				policyEndpoints = append(policyEndpoints, policyEndpointResourceName)
			}
		}
	} else {
		policyEndpoints = append(policyEndpoints, parentPEList...)
	}
	m[podIdentifier] = policyEndpoints
}

func referenceDelete(m map[string][]string, podIdentifier string, policyEndpoint string) {
	var currentPEList []string
	if policyEndpointList, ok := m[podIdentifier]; ok {
		for _, policyEndpointName := range policyEndpointList {
			if policyEndpointName == policyEndpoint {
				continue
			}
			currentPEList = append(currentPEList, policyEndpointName)
		}
		if len(currentPEList) == 0 {
			delete(m, podIdentifier)
		} else {
			m[podIdentifier] = currentPEList
		}
	}
}

// TestPodIdentifierPEList_MatchesPreviousImplementation drives random update/delete sequences
// through both implementations and requires the same set of PE names after every step, with
// the new list sorted and free of duplicates.
func TestPodIdentifierPEList_MatchesPreviousImplementation(t *testing.T) {
	for seed := int64(0); seed < 50; seed++ {
		rng := rand.New(rand.NewSource(seed))
		r := NewPolicyEndpointsReconciler(nil, benchNodeIP, nil, false)
		ref := map[string][]string{}
		identifiers := []string{"a@ns", "b@ns", "c@ns"}
		pes := make([]string, 30)
		for i := range pes {
			pes[i] = fmt.Sprintf("np-%d-%05d", i%4, rng.Intn(100000))
		}
		pes = slices.Compact(slices.Sorted(slices.Values(pes)))
		for step := 0; step < 500; step++ {
			id := identifiers[rng.Intn(len(identifiers))]
			if rng.Intn(3) == 0 {
				pe := pes[rng.Intn(len(pes))]
				deletePE(r, id, pe)
				referenceDelete(ref, id, pe)
			} else {
				// parentPEList comes from a List, so names are distinct and unordered.
				parent := make([]string, 0, 8)
				for _, i := range rng.Perm(len(pes))[:1+rng.Intn(8)] {
					parent = append(parent, pes[i])
				}
				updatePEs(r, id, parent)
				referenceUpdate(ref, id, parent)
			}
			for _, id := range identifiers {
				want, wantOK := ref[id]
				got, gotOK := r.podIdentifierToPolicyEndpointMap.Load(id)
				assert.Equal(t, wantOK, gotOK, "seed %d step %d id %s presence", seed, step, id)
				if gotOK {
					assert.Equal(t, slices.Sorted(slices.Values(want)), got.([]string), "seed %d step %d id %s", seed, step, id)
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
						names := v.([]string)
						for j := 1; j < len(names); j++ {
							if names[j-1] >= names[j] {
								unsorted.Store(true)
							}
						}
					}
				}
			}
		}()
	}
	for i := 0; i < 2000; i++ {
		updatePEs(r, "a@ns", []string{fmt.Sprintf("np-%d", i%50), fmt.Sprintf("np-%d", (i+1)%50)})
		if i%3 == 0 {
			deletePE(r, "a@ns", fmt.Sprintf("np-%d", i%50))
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
	var all []string
	for np := 0; np < 5; np++ {
		for i := 0; i < 120; i++ {
			all = append(all, fmt.Sprintf("wide-peer-%d-%05d", np, i))
		}
	}
	parent := all[240:360]
	r := NewPolicyEndpointsReconciler(nil, benchNodeIP, nil, false)
	updatePEs(r, "bulk-6b8f9c7d4@npa-kwok", all)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		updatePEs(r, "bulk-6b8f9c7d4@npa-kwok", parent)
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

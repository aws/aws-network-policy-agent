package ebpf

import (
	"errors"
	"sync"
	"testing"

	goebpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func cidrRules(cidrs ...string) []fwrp.EbpfFirewallRules {
	rules := make([]fwrp.EbpfFirewallRules, 0, len(cidrs))
	for _, cidr := range cidrs {
		rules = append(rules, fwrp.EbpfFirewallRules{IPCidr: v1alpha1.NetworkAddress(cidr)})
	}
	return rules
}

// countingCompute stands in for the rule processor and records how often it runs.
type countingCompute struct {
	calls int
	err   error
}

func (c *countingCompute) compute(rules []fwrp.EbpfFirewallRules) (map[string][]byte, error) {
	c.calls++
	if c.err != nil {
		return nil, c.err
	}
	entries := map[string][]byte{}
	for i, r := range rules {
		entries[string(r.IPCidr)] = val(byte(i))
	}
	return entries, nil
}

// cachedTestMap puts a fake-kernel shadow map in a cache, as shadowMapForLocked would.
func cachedTestMap(podIdentifier string) (*sync.Map, *InMemoryBpfMap, *fakeKernel) {
	m, f := newTestMap(nil)
	cache := new(sync.Map)
	cache.Store(podIdentifier, m)
	return cache, m, f
}

func program(cache *sync.Map, podIdentifier string, m *InMemoryBpfMap, c *countingCompute, rules []fwrp.EbpfFirewallRules) error {
	u := newRuleMapUpdate(rules, c.compute)
	u.precompute(cache, podIdentifier)
	return u.apply(m)
}

// Issue #305: reconciling many PolicyEndpoints that select the same pod re-derived the same
// rule union every time, and computing its entries dominated reconcile time. The repeat must
// neither compute nor write.
func TestRuleMapUpdate_RepeatedRulesAreNotRecomputed(t *testing.T) {
	cache, m, f := cachedTestMap("pod")
	c := &countingCompute{}

	assert.NoError(t, program(cache, "pod", m, c, cidrRules("10.0.0.1/32", "10.0.0.2/32")))
	assert.Equal(t, 1, c.calls)
	assert.Len(t, f.entries, 2)

	f.updateErrs[string("10.0.0.1/32")] = errors.New("must not be written again")
	assert.NoError(t, program(cache, "pod", m, c, cidrRules("10.0.0.1/32", "10.0.0.2/32")))
	assert.Equal(t, 1, c.calls, "identical rules must not be recomputed")
}

func TestRuleMapUpdate_ChangedRulesAreProgrammed(t *testing.T) {
	cache, m, f := cachedTestMap("pod")
	c := &countingCompute{}

	assert.NoError(t, program(cache, "pod", m, c, cidrRules("10.0.0.1/32", "10.0.0.2/32")))
	assert.NoError(t, program(cache, "pod", m, c, cidrRules("10.0.0.1/32", "10.0.0.3/32")))
	assert.Equal(t, 2, c.calls)
	assert.Contains(t, f.entries, "10.0.0.3/32")
	assert.NotContains(t, f.entries, "10.0.0.2/32", "the revoked peer must be removed")

	// Going back to rules programmed earlier is a change too.
	assert.NoError(t, program(cache, "pod", m, c, cidrRules("10.0.0.1/32", "10.0.0.2/32")))
	assert.Equal(t, 3, c.calls)
	assert.Contains(t, f.entries, "10.0.0.2/32")
	assert.NotContains(t, f.entries, "10.0.0.3/32")
}

// Failures must leave nothing that would make the retry skip.
func TestRuleMapUpdate_FailuresAreRetried(t *testing.T) {
	t.Run("compute error", func(t *testing.T) {
		cache, m, f := cachedTestMap("pod")
		c := &countingCompute{err: errors.New("bad rule")}
		assert.Error(t, program(cache, "pod", m, c, cidrRules("10.0.0.1/32")))
		c.err = nil
		assert.NoError(t, program(cache, "pod", m, c, cidrRules("10.0.0.1/32")))
		assert.Equal(t, 2, c.calls)
		assert.Contains(t, f.entries, "10.0.0.1/32")
	})
	t.Run("map write error", func(t *testing.T) {
		cache, m, f := cachedTestMap("pod")
		c := &countingCompute{}
		f.updateErrs["10.0.0.1/32"] = errors.New("ENOMEM")
		assert.Error(t, program(cache, "pod", m, c, cidrRules("10.0.0.1/32")))
		delete(f.updateErrs, "10.0.0.1/32")
		assert.NoError(t, program(cache, "pod", m, c, cidrRules("10.0.0.1/32")))
		assert.Equal(t, 2, c.calls)
		assert.Contains(t, f.entries, "10.0.0.1/32")
	})
	t.Run("stale entry delete error", func(t *testing.T) {
		cache, m, f := cachedTestMap("pod")
		c := &countingCompute{}
		assert.NoError(t, program(cache, "pod", m, c, cidrRules("10.0.0.1/32", "10.0.0.2/32")))
		f.deleteErrs["10.0.0.2/32"] = errors.New("EPERM")
		assert.NoError(t, program(cache, "pod", m, c, cidrRules("10.0.0.1/32")))
		delete(f.deleteErrs, "10.0.0.2/32")
		assert.NoError(t, program(cache, "pod", m, c, cidrRules("10.0.0.1/32")))
		assert.Equal(t, 3, c.calls, "the same rules must be recomputed while a revoked entry is stuck")
		assert.NotContains(t, f.entries, "10.0.0.2/32")
	})
}

// precompute's check runs without the identifier lock, so the map can change before apply.
// apply must notice and compute rather than trust the stale hint.
func TestRuleMapUpdate_StaleHintIsRecheckedUnderLock(t *testing.T) {
	cache, m, f := cachedTestMap("pod")
	c := &countingCompute{}
	assert.NoError(t, program(cache, "pod", m, c, cidrRules("10.0.0.1/32")))

	u := newRuleMapUpdate(cidrRules("10.0.0.1/32"), c.compute)
	u.precompute(cache, "pod")
	assert.Equal(t, 1, c.calls, "the hint says the map already holds these rules")

	// Another writer reprograms the map in between.
	other := &countingCompute{}
	assert.NoError(t, program(cache, "pod", m, other, cidrRules("10.0.0.9/32")))

	assert.NoError(t, u.apply(m))
	assert.Equal(t, 2, c.calls)
	assert.Contains(t, f.entries, "10.0.0.1/32")
	assert.NotContains(t, f.entries, "10.0.0.9/32")
}

// A rebuilt shadow map (a reattach, or a new pod after the last one of the identifier left)
// knows nothing about the rules, so it has to be programmed even with unchanged rules.
func TestRuleMapUpdate_NewShadowMapIsProgrammed(t *testing.T) {
	cache, m, _ := cachedTestMap("pod")
	c := &countingCompute{}
	assert.NoError(t, program(cache, "pod", m, c, cidrRules("10.0.0.1/32")))

	fresh, f := newTestMap(nil)
	cache.Store("pod", fresh)
	assert.NoError(t, program(cache, "pod", fresh, c, cidrRules("10.0.0.1/32")))
	assert.Equal(t, 2, c.calls)
	assert.Contains(t, f.entries, "10.0.0.1/32")
}

// End to end through UpdateEbpfMaps with the real rule processor: the second identical call
// leaves the kernel untouched, a changed rule set is still written, and so is a rebuilt map.
func TestBpfClient_UpdateEbpfMaps_SkipsUnchangedRules(t *testing.T) {
	client, _ := newRaceTestBpfClient(t)
	podIdentifier := utils.GetPodIdentifier("app", "ns")
	seedLastPodOfIdentifier(t, client, podIdentifier, utils.GetPodNamespacedName("app", "ns"), 100, 101)

	writes := 0
	origNewInMemoryBpfMap := newInMemoryBpfMap
	defer func() { newInMemoryBpfMap = origNewInMemoryBpfMap }()
	newInMemoryBpfMap = func(bpfMap *goebpfmaps.BpfMap) (*InMemoryBpfMap, error) {
		m, _ := newTestMap(nil)
		m.bpfMap = bpfMap
		inner := m.updateEntry
		m.updateEntry = func(key, value []byte) error { writes++; return inner(key, value) }
		return m, nil
	}

	ingress := cidrRules("10.0.0.1/32", "10.0.0.2/32")
	egress := cidrRules("0.0.0.0/0")
	assert.NoError(t, client.UpdateEbpfMaps(podIdentifier, ingress, egress))
	first := writes
	assert.Greater(t, first, 0)
	ingressMap, _ := client.ingressInMemoryMap.Load(podIdentifier)
	programmed := len(ingressMap.(*InMemoryBpfMap).contents)

	assert.NoError(t, client.UpdateEbpfMaps(podIdentifier, cidrRules("10.0.0.1/32", "10.0.0.2/32"), cidrRules("0.0.0.0/0")))
	assert.Equal(t, first, writes, "unchanged rules must not touch the kernel")
	assert.Len(t, ingressMap.(*InMemoryBpfMap).contents, programmed)

	assert.NoError(t, client.UpdateEbpfMaps(podIdentifier, cidrRules("10.0.0.1/32", "10.0.0.3/32"), cidrRules("0.0.0.0/0")))
	assert.Equal(t, first+1, writes, "only the new ingress peer is written")

	client.ingressInMemoryMap.Delete(podIdentifier)
	client.egressInMemoryMap.Delete(podIdentifier)
	before := writes
	assert.NoError(t, client.UpdateEbpfMaps(podIdentifier, cidrRules("10.0.0.1/32", "10.0.0.3/32"), cidrRules("0.0.0.0/0")))
	assert.Equal(t, before+first, writes, "rebuilt maps are programmed in full")
}

// The cluster-policy maps share the mechanism.
func TestBpfClient_UpdateClusterPolicyEbpfMaps_SkipsUnchangedRules(t *testing.T) {
	client, _ := newRaceTestBpfClient(t)
	podIdentifier := utils.GetPodIdentifier("app", "ns")
	client.policyEndpointeBPFContext.Store(podIdentifier, raceTestBPFContext(7, 100, 9, 101))

	writes := 0
	origNewInMemoryBpfMap := newInMemoryBpfMap
	defer func() { newInMemoryBpfMap = origNewInMemoryBpfMap }()
	newInMemoryBpfMap = func(bpfMap *goebpfmaps.BpfMap) (*InMemoryBpfMap, error) {
		m, _ := newTestMap(nil)
		m.bpfMap = bpfMap
		inner := m.updateEntry
		m.updateEntry = func(key, value []byte) error { writes++; return inner(key, value) }
		return m, nil
	}
	rules := func() []fwrp.EbpfFirewallRules {
		return []fwrp.EbpfFirewallRules{{IPCidr: "10.0.0.1/32", Priority: 10, Action: "Accept"}}
	}

	assert.NoError(t, client.UpdateClusterPolicyEbpfMaps(podIdentifier, rules(), rules()))
	first := writes
	assert.Greater(t, first, 0)
	assert.NoError(t, client.UpdateClusterPolicyEbpfMaps(podIdentifier, rules(), rules()))
	assert.Equal(t, first, writes)

	changed := rules()
	changed[0].Action = "Deny"
	assert.NoError(t, client.UpdateClusterPolicyEbpfMaps(podIdentifier, changed, rules()))
	assert.Equal(t, first+1, writes, "a changed action rewrites the ingress entry")
}

// The rule processor sorts its input by prefix length in place, so the fingerprint has to be
// taken before computing. Taken after, it would describe the sorted list, and the next call
// with the same unsorted rules would never match. Mixed prefixes out of order make the sort
// actually move rules.
func TestRuleMapUpdate_FingerprintIsTakenBeforeTheInPlaceSort(t *testing.T) {
	cache, m, f := cachedTestMap("pod")
	processor := fwrp.NewFirewallRuleProcessor("10.1.1.1", "/32", false)
	calls := 0
	compute := func(rules []fwrp.EbpfFirewallRules) (map[string][]byte, error) {
		calls++
		return processor.ComputeMapEntriesFromEndpointRules(rules)
	}
	unsorted := func() []fwrp.EbpfFirewallRules {
		return cidrRules("10.0.0.1/32", "10.0.0.0/16", "10.0.5.0/24")
	}

	first := unsorted()
	u := newRuleMapUpdate(first, compute)
	u.precompute(cache, "pod")
	assert.NoError(t, u.apply(m))
	assert.NotEqual(t, unsorted()[0].IPCidr, first[0].IPCidr, "fixture must make the compute reorder its input")
	written := len(f.entries)

	u = newRuleMapUpdate(unsorted(), compute)
	u.precompute(cache, "pod")
	assert.NoError(t, u.apply(m))
	assert.Equal(t, 1, calls, "the same unsorted rules must match what the first call programmed")
	assert.Len(t, f.entries, written)
}

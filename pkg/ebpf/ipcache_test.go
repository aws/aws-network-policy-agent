package ebpf

import (
	"errors"
	"net"
	"testing"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func encodedRule(port int32, priority int) []byte {
	tcp := corev1.ProtocolTCP
	return utils.ComputeTrieValueForCPE([]utils.L4Rule{{
		L4PortProtocolInfo: v1alpha1.Port{Protocol: &tcp, Port: &port},
		Action:             v1alpha1.ClusterNetworkPolicyRuleActionAccept,
		Priority:           priority,
	}})
}

func slot(encoded []byte) [ipCacheRuleSize]byte {
	return [ipCacheRuleSize]byte(encoded[:ipCacheRuleSize])
}

func TestMergeIPCacheValue(t *testing.T) {
	const now = 1000
	https, http := encodedRule(443, utils.PE_PRIORITY), encodedRule(80, utils.PE_PRIORITY)

	t.Run("a domain sharing the IP keeps its own rule and expiry", func(t *testing.T) {
		cached := mergeIPCacheValue(ipCacheValue{}, http, now, now+30)
		merged := mergeIPCacheValue(cached, https, now+10, now+40)
		assert.Equal(t, slot(https), merged.Rules[0])
		assert.Equal(t, uint64(now+40), merged.Expiry[0])
		assert.Equal(t, slot(http), merged.Rules[1])
		assert.Equal(t, uint64(now+30), merged.Expiry[1])
	})

	t.Run("expired rules are dropped", func(t *testing.T) {
		cached := mergeIPCacheValue(ipCacheValue{}, http, now, now+30)
		merged := mergeIPCacheValue(cached, https, now+31, now+60)
		assert.Equal(t, slot(https), merged.Rules[0])
		assert.Equal(t, [ipCacheRuleSize]byte{}, merged.Rules[1])
		assert.Equal(t, ipCacheValue{}, mergeIPCacheValue(cached, nil, now+31, 0))
	})

	t.Run("the same rule keeps the later expiry", func(t *testing.T) {
		cached := mergeIPCacheValue(ipCacheValue{}, https, now, now+60)
		merged := mergeIPCacheValue(cached, https, now+1, now+5)
		assert.Equal(t, uint64(now+60), merged.Expiry[0])
		assert.Equal(t, [ipCacheRuleSize]byte{}, merged.Rules[1])
	})

	t.Run("new rules win the slots when full", func(t *testing.T) {
		var cached ipCacheValue
		for i := 0; i < ipCacheSlots; i++ {
			cached = mergeIPCacheValue(cached, encodedRule(int32(1000+i), utils.PE_PRIORITY), now, now+30)
		}
		merged := mergeIPCacheValue(cached, https, now, now+30)
		assert.Equal(t, slot(https), merged.Rules[0])
		assert.NotEqual(t, [ipCacheRuleSize]byte{}, merged.Rules[ipCacheSlots-1])
	})
}

func TestKeepIPCacheRules(t *testing.T) {
	https, http := encodedRule(443, utils.PE_PRIORITY), encodedRule(80, utils.PE_PRIORITY)
	cached := mergeIPCacheValue(mergeIPCacheValue(ipCacheValue{}, http, 0, 30), https, 0, 60)

	kept := keepIPCacheRules(cached, func(rule [ipCacheRuleSize]byte, _ uint64) bool { return rule == slot(http) })
	assert.Equal(t, slot(http), kept.Rules[0])
	assert.Equal(t, uint64(30), kept.Expiry[0])
	assert.Equal(t, [ipCacheRuleSize]byte{}, kept.Rules[1])

	assert.Equal(t, ipCacheValue{}, keepIPCacheRules(cached, func(_ [ipCacheRuleSize]byte, expiry uint64) bool { return expiry > 60 }))
}

// fakeIPCacheMap is an ipCacheMap with room for capacity entries.
type fakeIPCacheMap struct {
	entries  map[string]ipCacheValue
	capacity int
}

func (f *fakeIPCacheMap) get(key []byte) (ipCacheValue, bool) {
	value, ok := f.entries[string(key)]
	return value, ok
}

func (f *fakeIPCacheMap) put(key []byte, value ipCacheValue) error {
	if _, ok := f.entries[string(key)]; !ok && len(f.entries) >= f.capacity {
		return errors.New("map full")
	}
	f.entries[string(key)] = value
	return nil
}

func (f *fakeIPCacheMap) remove(key []byte) { delete(f.entries, string(key)) }

func (f *fakeIPCacheMap) keys() ([]string, error) {
	var keys []string
	for k := range f.entries {
		keys = append(keys, k)
	}
	return keys, nil
}

func ipKey(ip string) string {
	return string(utils.ComputeTrieKey(net.IPNet{IP: net.ParseIP(ip).To4(), Mask: net.CIDRMask(32, 32)}, false))
}

func TestWriteIPCache(t *testing.T) {
	const now = uint64(1000)
	https, http := encodedRule(443, utils.PE_PRIORITY), encodedRule(80, utils.PE_PRIORITY)

	t.Run("writes each IPv4 answer with its TTL", func(t *testing.T) {
		m := &fakeIPCacheMap{entries: map[string]ipCacheValue{}, capacity: 8}
		answers := []npatypes.IPWithTTL{{IP: net.ParseIP("192.0.2.1"), TTL: 30}, {IP: net.ParseIP("2001:db8::1"), TTL: 30}, {IP: net.ParseIP("192.0.2.2"), TTL: 5}}
		assert.NoError(t, writeIPCache(m, answers, https, now, always))
		assert.Len(t, m.entries, 2, "IPv6 answers are skipped")
		assert.Equal(t, now+30e9, m.entries[ipKey("192.0.2.1")].Expiry[0])
		assert.Equal(t, now+5e9, m.entries[ipKey("192.0.2.2")].Expiry[0])

		assert.NoError(t, writeIPCache(m, answers[:1], http, now, always))
		assert.Equal(t, slot(http), m.entries[ipKey("192.0.2.1")].Rules[0])
		assert.Equal(t, slot(https), m.entries[ipKey("192.0.2.1")].Rules[1], "the rule of the other domain stays")
	})

	t.Run("a full map makes room by deleting expired entries", func(t *testing.T) {
		m := &fakeIPCacheMap{entries: map[string]ipCacheValue{}, capacity: 1}
		assert.NoError(t, writeIPCache(m, []npatypes.IPWithTTL{{IP: net.ParseIP("192.0.2.1"), TTL: 30}}, https, now, always))
		assert.Error(t, writeIPCache(m, []npatypes.IPWithTTL{{IP: net.ParseIP("192.0.2.2"), TTL: 30}}, https, now, always), "nothing has expired yet")
		assert.Error(t, writeIPCache(m, []npatypes.IPWithTTL{{IP: net.ParseIP("192.0.2.2"), TTL: 30}}, https, now+31e9, never), "no sweep allowed yet")
		assert.NoError(t, writeIPCache(m, []npatypes.IPWithTTL{{IP: net.ParseIP("192.0.2.2"), TTL: 30}}, https, now+31e9, always))
		assert.Equal(t, []string{ipKey("192.0.2.2")}, func() []string { k, _ := m.keys(); return k }())
	})

	t.Run("an IP that does not fit leaves the others written", func(t *testing.T) {
		m := &fakeIPCacheMap{entries: map[string]ipCacheValue{}, capacity: 1}
		assert.NoError(t, writeIPCache(m, []npatypes.IPWithTTL{{IP: net.ParseIP("192.0.2.1"), TTL: 30}}, https, now, always))
		err := writeIPCache(m, []npatypes.IPWithTTL{{IP: net.ParseIP("192.0.2.2"), TTL: 30}, {IP: net.ParseIP("192.0.2.1"), TTL: 60}}, https, now, never)
		assert.ErrorContains(t, err, "192.0.2.2")
		assert.Equal(t, now+60e9, m.entries[ipKey("192.0.2.1")].Expiry[0], "the cached IP is still refreshed")
	})
}

func always() bool { return true }
func never() bool  { return false }

func TestPruneIPCache(t *testing.T) {
	https, http := encodedRule(443, utils.PE_PRIORITY), encodedRule(80, utils.PE_PRIORITY)
	admin := encodedRule(8443, 10)
	m := &fakeIPCacheMap{entries: map[string]ipCacheValue{}, capacity: 8}
	assert.NoError(t, writeIPCache(m, []npatypes.IPWithTTL{{IP: net.ParseIP("192.0.2.1"), TTL: 30}}, append(append([]byte{}, https...), http...), 0, always))
	assert.NoError(t, writeIPCache(m, []npatypes.IPWithTTL{{IP: net.ParseIP("192.0.2.2"), TTL: 30}}, append(append([]byte{}, https...), admin...), 0, always))

	pruneIPCache(m, https)
	assert.Equal(t, slot(http), m.entries[ipKey("192.0.2.1")].Rules[0], "the other rules stay")
	assert.Equal(t, [ipCacheRuleSize]byte{}, m.entries[ipKey("192.0.2.1")].Rules[1])
	assert.Equal(t, slot(admin), m.entries[ipKey("192.0.2.2")].Rules[0])

	pruneIPCache(m, admin)
	assert.NotContains(t, m.entries, ipKey("192.0.2.2"), "an entry with no remaining rule is deleted")
	assert.Contains(t, m.entries, ipKey("192.0.2.1"))
}

func TestCanSweepIPCache(t *testing.T) {
	c := NewMockBpfClient()
	assert.True(t, c.canSweepIPCache("app@ns", 5e9))
	assert.False(t, c.canSweepIPCache("app@ns", 5e9+999e6), "at most one sweep a second")
	assert.True(t, c.canSweepIPCache("other@ns", 5e9+999e6), "per pod identifier")
	assert.True(t, c.canSweepIPCache("app@ns", 6e9))
	assert.False(t, c.canSweepIPCache("app@ns", 5e9), "a waiter that read the clock before the last sweep does not sweep again")
	assert.False(t, c.canSweepIPCache("app@ns", 6e9+999e6), "nor moves the last sweep back")
}

// The rules of a write and of a prune are computed with the pod identifier's lock held: a write
// matched before a prune is pruned, and one matched after it no longer has the pruned rules.
func TestIPCacheRulesAreComputedUnderThePodIdentifierLock(t *testing.T) {
	c := NewMockBpfClient()
	var held []int
	rules := func() []byte {
		held = append(held, c.podIdentifierLocks.len())
		return encodedRule(443, utils.PE_PRIORITY)
	}
	_ = c.UpdateIPCache("app@ns", nil, rules)
	_ = c.PruneIPCache("app@ns", rules)
	assert.Equal(t, []int{1, 1}, held)
}

func TestIPCacheNeedsABPFContext(t *testing.T) {
	c := NewMockBpfClient()
	rules := func() []byte { return encodedRule(443, utils.PE_PRIORITY) }
	assert.ErrorContains(t, c.UpdateIPCache("app@ns", nil, rules), "no bpf context")
	assert.ErrorContains(t, c.PruneIPCache("app@ns", rules), "no bpf context")
	none := func() []byte { return nil }
	assert.NoError(t, c.UpdateIPCache("app@ns", nil, none), "no rules, nothing to write")
	assert.NoError(t, c.PruneIPCache("app@ns", none))
}

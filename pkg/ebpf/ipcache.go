package ebpf

import (
	"errors"
	"fmt"
	"net"
	"unsafe"

	goebpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
)

const (
	ipCacheRuleSize = 16 // struct lpm_cp_trie_val
	ipCacheSlots    = 24 // MAX_PORT_PROTOCOL
)

// ipCacheValue mirrors struct ipcache_value in tc.v4egress.bpf.c.
type ipCacheValue struct {
	Rules  [ipCacheSlots][ipCacheRuleSize]byte
	Expiry [ipCacheSlots]uint64
}

// ipCacheMap is the IP cache map of one pod identifier; tests replace it.
type ipCacheMap interface {
	get(key []byte) (ipCacheValue, bool)
	put(key []byte, value ipCacheValue) error
	remove(key []byte)
	keys() ([]string, error)
}

type bpfIPCacheMap struct{ m goebpfmaps.BpfMap }

func (b bpfIPCacheMap) get(key []byte) (ipCacheValue, bool) {
	var value ipCacheValue
	return value, b.m.GetMapEntry(uintptr(unsafe.Pointer(&key[0])), uintptr(unsafe.Pointer(&value))) == nil
}

func (b bpfIPCacheMap) put(key []byte, value ipCacheValue) error {
	return b.m.CreateUpdateMapEntry(uintptr(unsafe.Pointer(&key[0])), uintptr(unsafe.Pointer(&value)), 0)
}

func (b bpfIPCacheMap) remove(key []byte) {
	_ = b.m.DeleteMapEntry(uintptr(unsafe.Pointer(&key[0])))
}

func (b bpfIPCacheMap) keys() ([]string, error) {
	return b.m.GetAllMapKeys()
}

// UpdateIPCache allows the rules encodedRules returns (utils.ComputeTrieValueForCPE output, possibly
// concatenated) to the IPs of a DNS answer for podIdentifier, each until its TTL runs out.
// encodedRules is called under the pod identifier's lock, which PruneIPCache holds too, so rules
// matched before a prune are pruned and rules matched after it no longer include what it removed.
func (l *bpfClient) UpdateIPCache(podIdentifier string, answers []npatypes.IPWithTTL, encodedRules func() []byte) error {
	now, err := utils.KtimeGetNs()
	if err != nil {
		return err
	}

	l.podIdentifierLocks.Lock(podIdentifier)
	defer l.podIdentifierLocks.Unlock(podIdentifier)

	rules := encodedRules()
	if len(rules) == 0 {
		return nil
	}
	ipCache, err := l.ipCacheLocked(podIdentifier)
	if err != nil {
		return err
	}
	return writeIPCache(ipCache, answers, rules, now, func() bool { return l.canSweepIPCache(podIdentifier, now) })
}

// canSweepIPCache rate limits the sweeps of a full IP cache: a sweep is about two syscalls per
// entry, and once a second is enough to make room.
func (l *bpfClient) canSweepIPCache(podIdentifier string, now uint64) bool {
	// now is read before the lock, so a waiter can bring an older time than the last sweep's.
	if last, ok := l.ipCacheSweeps.Load(podIdentifier); ok && now < last.(uint64)+1e9 {
		return false
	}
	l.ipCacheSweeps.Store(podIdentifier, now)
	return true
}

// PruneIPCache removes the rules staleRules returns from every cached IP of podIdentifier, so the IPs
// learned for the rules of a changed or deleted policy stop being allowed before their TTL runs out.
// staleRules is called under the pod identifier's lock, like the rules of UpdateIPCache.
func (l *bpfClient) PruneIPCache(podIdentifier string, staleRules func() []byte) error {
	l.podIdentifierLocks.Lock(podIdentifier)
	defer l.podIdentifierLocks.Unlock(podIdentifier)

	stale := staleRules()
	if len(stale) == 0 {
		return nil
	}
	ipCache, err := l.ipCacheLocked(podIdentifier)
	if err != nil {
		return err
	}
	pruneIPCache(ipCache, stale)
	return nil
}

func (l *bpfClient) ipCacheLocked(podIdentifier string) (ipCacheMap, error) {
	value, ok := l.policyEndpointeBPFContext.Load(podIdentifier)
	if !ok {
		return nil, fmt.Errorf("no bpf context registered for pod %s", podIdentifier)
	}
	ipCache, ok := value.(BPFContext).egressPgmInfo.Maps[utils.TC_IPCACHE_MAP]
	if !ok {
		return nil, fmt.Errorf("no ip cache map for pod %s", podIdentifier)
	}
	return bpfIPCacheMap{m: ipCache}, nil
}

func writeIPCache(ipCache ipCacheMap, answers []npatypes.IPWithTTL, encodedRules []byte, now uint64, canSweep func() bool) error {
	var errs error
	for _, answer := range answers {
		ip := answer.IP.To4()
		if ip == nil {
			continue
		}
		key := utils.ComputeTrieKey(net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, false)
		cached, _ := ipCache.get(key) // a miss leaves it empty
		merged := mergeIPCacheValue(cached, encodedRules, now, now+uint64(answer.TTL)*1e9)
		err := ipCache.put(key, merged)
		if err != nil && canSweep() {
			// The map has no eviction: make room by deleting fully expired entries, then retry once.
			sweepIPCache(ipCache, func(_ [ipCacheRuleSize]byte, expiry uint64) bool { return expiry > now })
			err = ipCache.put(key, merged)
		}
		if err != nil {
			// The other IPs are still written: refreshing an IP the cache has may succeed when adding one fails.
			errs = errors.Join(errs, fmt.Errorf("failed to write %s to the ip cache: %w", ip, err))
		}
	}
	return errs
}

func pruneIPCache(ipCache ipCacheMap, staleRules []byte) {
	stale := map[[ipCacheRuleSize]byte]bool{}
	for i := 0; i+ipCacheRuleSize <= len(staleRules); i += ipCacheRuleSize {
		stale[[ipCacheRuleSize]byte(staleRules[i:i+ipCacheRuleSize])] = true
	}
	sweepIPCache(ipCache, func(rule [ipCacheRuleSize]byte, _ uint64) bool { return !stale[rule] })
}

// mergeIPCacheValue adds or refreshes rules with expiry and keeps the cached rules that have not
// expired, so domains sharing an IP keep their own rules. New rules take the free slots first.
func mergeIPCacheValue(cached ipCacheValue, encodedRules []byte, now, expiry uint64) ipCacheValue {
	var merged ipCacheValue
	n := 0
	add := func(rule [ipCacheRuleSize]byte, ruleExpiry uint64) {
		for i := 0; i < n; i++ {
			if merged.Rules[i] == rule {
				merged.Expiry[i] = max(merged.Expiry[i], ruleExpiry)
				return
			}
		}
		if n < len(merged.Rules) {
			merged.Rules[n], merged.Expiry[n] = rule, ruleExpiry
			n++
		}
	}
	for i := 0; i+ipCacheRuleSize <= len(encodedRules); i += ipCacheRuleSize {
		rule := [ipCacheRuleSize]byte(encodedRules[i : i+ipCacheRuleSize])
		if rule != [ipCacheRuleSize]byte{} {
			add(rule, expiry)
		}
	}
	for i, rule := range cached.Rules {
		if cached.Expiry[i] > now {
			add(rule, cached.Expiry[i])
		}
	}
	return merged
}

// keepIPCacheRules returns the rules of cached for which keep is true.
func keepIPCacheRules(cached ipCacheValue, keep func(rule [ipCacheRuleSize]byte, expiry uint64) bool) ipCacheValue {
	var kept ipCacheValue
	n := 0
	for i, rule := range cached.Rules {
		if rule != [ipCacheRuleSize]byte{} && keep(rule, cached.Expiry[i]) {
			kept.Rules[n], kept.Expiry[n] = rule, cached.Expiry[i]
			n++
		}
	}
	return kept
}

// sweepIPCache applies keepIPCacheRules to every entry and deletes the entries left empty.
func sweepIPCache(ipCache ipCacheMap, keep func(rule [ipCacheRuleSize]byte, expiry uint64) bool) {
	keys, err := ipCache.keys()
	if err != nil {
		log().Errorf("failed to list the ip cache: %v", err)
		return
	}
	for _, k := range keys {
		key := []byte(k)
		cached, ok := ipCache.get(key)
		if !ok {
			continue
		}
		switch kept := keepIPCacheRules(cached, keep); kept {
		case cached:
		case ipCacheValue{}:
			ipCache.remove(key)
		default:
			_ = ipCache.put(key, kept)
		}
	}
}

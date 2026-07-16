package fwruleprocessor

import (
	"net"
)

type cidrTrieNode struct {
	children [2]*cidrTrieNode
	cidrKeys []string
}

// cidrTrie keeps IPv4 and IPv6 in separate sub-tries to avoid cross-family prefix collisions.
type cidrTrie struct {
	v4Root *cidrTrieNode
	v6Root *cidrTrieNode
}

func newCIDRTrie() *cidrTrie {
	return &cidrTrie{
		v4Root: &cidrTrieNode{},
		v6Root: &cidrTrieNode{},
	}
}

func normalizeIP(ip net.IP) (normalized net.IP, isV6 bool) {
	if v4 := ip.To4(); v4 != nil {
		return v4, false
	}
	if v6 := ip.To16(); v6 != nil {
		return v6, true
	}
	return nil, false
}

func (t *cidrTrie) rootFor(isV6 bool) *cidrTrieNode {
	if isV6 {
		return t.v6Root
	}
	return t.v4Root
}

func (t *cidrTrie) insert(cidrStr string, ipNet *net.IPNet) {
	if ipNet == nil {
		log().Debugf("cidrTrie.insert: skipping key %q: nil ipNet", cidrStr)
		return
	}
	ip, isV6 := normalizeIP(ipNet.IP)
	if ip == nil {
		log().Debugf("cidrTrie.insert: skipping key %q: unparseable network IP", cidrStr)
		return
	}

	ones, bits := ipNet.Mask.Size()
	if bits == 0 {
		log().Debugf("cidrTrie.insert: skipping key %q: non-canonical mask", cidrStr)
		return
	}

	if !isV6 && bits == 128 {
		ones -= 96
	}

	maxBits := len(ip) * 8
	if ones < 0 || ones > maxBits {
		log().Debugf("cidrTrie.insert: skipping key %q: prefix length %d out of range for %d-bit family", cidrStr, ones, maxBits)
		return
	}

	node := t.rootFor(isV6)
	for i := 0; i < ones; i++ {
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		bit := (ip[byteIdx] >> uint(bitIdx)) & 1

		if node.children[bit] == nil {
			node.children[bit] = &cidrTrieNode{}
		}
		node = node.children[bit]
	}
	node.cidrKeys = append(node.cidrKeys, cidrStr)
}

func (t *cidrTrie) findContainingKeys(ip net.IP) []string {
	var result []string

	ipBytes, isV6 := normalizeIP(ip)
	if ipBytes == nil {
		return result
	}

	node := t.rootFor(isV6)
	if len(node.cidrKeys) > 0 {
		result = append(result, node.cidrKeys...)
	}

	maxBits := len(ipBytes) * 8
	for i := 0; i < maxBits; i++ {
		byteIdx := i / 8
		if byteIdx >= len(ipBytes) {
			break
		}
		bitIdx := 7 - (i % 8)
		bit := (ipBytes[byteIdx] >> uint(bitIdx)) & 1

		if node.children[bit] == nil {
			break
		}
		node = node.children[bit]

		if len(node.cidrKeys) > 0 {
			result = append(result, node.cidrKeys...)
		}
	}

	return result
}

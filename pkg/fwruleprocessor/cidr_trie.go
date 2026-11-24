package fwruleprocessor

import "net/netip"

type cidrTrieNode struct {
	children [2]*cidrTrieNode
	cidrKey  netip.Prefix
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

func (t *cidrTrie) rootFor(isV6 bool) *cidrTrieNode {
	if isV6 {
		return t.v6Root
	}
	return t.v4Root
}

// insert adds a CIDR key to the trie at the position determined by the network
// prefix bits. The key is stored at the node corresponding to the last prefix bit,
// so findContainingKeys can collect it when traversing an address that falls within
// this prefix.
func (t *cidrTrie) insert(prefix netip.Prefix) {
	if !prefix.IsValid() {
		return
	}
	prefix = canonicalPrefix(prefix)
	ip := prefix.Addr().As16()
	if prefix.Addr().Is4() {
		v4 := prefix.Addr().As4()
		copy(ip[:], v4[:])
	}

	node := t.rootFor(prefix.Addr().Is6())
	for i := 0; i < prefix.Bits(); i++ {
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		bit := (ip[byteIdx] >> uint(bitIdx)) & 1

		if node.children[bit] == nil {
			node.children[bit] = &cidrTrieNode{}
		}
		node = node.children[bit]
	}
	// Store the canonical form (host bits masked) so the key matches
	// what the caller uses in the nonHostCIDRs map.
	node.cidrKey = prefix
}

// findContainingKeys walks the trie from root to leaf along the bits of ip,
// collecting all CIDR keys whose prefix contains the given address.
// Returns results from shortest prefix (closest to root) to longest.
func (t *cidrTrie) findContainingKeys(ip netip.Addr) []netip.Prefix {
	var result []netip.Prefix

	if !ip.IsValid() {
		return result
	}
	ip = ip.Unmap()
	ipBytes := ip.As16()
	if ip.Is4() {
		v4 := ip.As4()
		copy(ipBytes[:], v4[:])
	}

	node := t.rootFor(ip.Is6())
	if node.cidrKey.IsValid() {
		result = append(result, node.cidrKey)
	}

	maxBits := ip.BitLen()
	for i := 0; i < maxBits; i++ {
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		bit := (ipBytes[byteIdx] >> uint(bitIdx)) & 1

		if node.children[bit] == nil {
			break
		}
		node = node.children[bit]

		if node.cidrKey.IsValid() {
			result = append(result, node.cidrKey)
		}
	}

	return result
}

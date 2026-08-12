// Package fwruleprocessor builds eBPF firewall map entries from PolicyEndpoint specs.
//
// # CIDR Trie: Storage Layout and Debugging
//
// The cidrTrie accelerates the "which CIDRs contain this IP?" query that runs once
// per firewall rule during reconcile. Without it, the lookup was O(rules × CIDRs)
// with a net.ParseCIDR call per pair; with the trie it is O(address-bits) per lookup.
//
// ## IP Storage Format
//
// IPs are stored as raw byte slices in their canonical form:
//   - IPv4: 4 bytes (net.IP.To4)
//   - IPv6: 16 bytes (net.IP.To16)
//   - v4-mapped IPv6 (::ffff:x.x.x.x): normalized to 4-byte IPv4 form
//
// This normalization (see normalizeIP) ensures that a v4-mapped address matches
// against v4 CIDRs in the v4 sub-trie, not the v6 sub-trie.
//
// ## Trie Layout
//
// The trie has two independent roots: v4Root and v6Root. Each node has:
//   - children [2]*cidrTrieNode — left (bit=0) and right (bit=1)
//   - cidrKeys []string          — CIDR strings stored at this prefix depth
//
// Insertion walks the network prefix bits (MSB-first) from root, creating nodes
// as needed, and appends the CIDR string key at the node corresponding to the
// last prefix bit. For example, inserting "10.0.0.0/8" stores the key at depth 8
// in the v4 sub-trie.
//
// Why cidrKeys is a slice: net.ParseCIDR normalizes host bits away, so two
// different CIDR strings can map to the same trie node. For example, a PE spec
// containing "10.0.0.1/8" (port 80) and "10.0.0.0/8" (port 443) — both parse
// to network 10.0.0.0, mask /8. They are distinct map keys in nonHostCIDRs
// (different L4 rules), but walk the same 8 bits in the trie and land on the
// same node. The slice ensures neither key is lost; findContainingKeys returns
// both, and the caller collects L4 info from each.
//
// ## Query Semantics (findContainingKeys)
//
// Given an IP, the trie walks from root along the IP's bits, collecting cidrKeys
// at every node visited. This yields all CIDRs whose prefix contains the IP,
// ordered from shortest prefix (most general) to longest (most specific).
//
// The caller then looks up each returned key in the nonHostCIDRs map to collect
// the associated L4 port info, skipping entries where the IP falls in an Except block.
//
// ## Lifecycle
//
// The trie is built once per reconcile (in ComputeMapEntriesFromEndpointRules) from
// the non-host CIDR rules in the PolicyEndpoint spec, queried for every host-CIDR
// rule to find overlapping port permissions, and discarded after reconcile completes.
// It is never shared across goroutines.
package fwruleprocessor

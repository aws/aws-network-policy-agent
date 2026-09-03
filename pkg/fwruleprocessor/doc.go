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
//   - cidrKey  string              — canonical CIDR string stored at this prefix depth
//
// Insertion walks the network prefix bits (MSB-first) from root, creating nodes
// as needed, and appends the CIDR string key at the node corresponding to the
// last prefix bit. For example, inserting "10.0.0.0/8" stores the key at depth 8
// in the v4 sub-trie.
//
// The CIDR is stored in canonical form (ipNet.String() — host bits masked).
// The caller canonicalizes CIDRs before insertion (fw_rule_processor.go line 112),
// and insert() itself calls net.ParseCIDR which masks host bits, so the stored
// key always matches what the nonHostCIDRs map uses as its key.
//
// ## Query Semantics (findContainingKeys)
//
// Given an IP, the trie walks from root along the IP's bits, collecting cidrKey
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

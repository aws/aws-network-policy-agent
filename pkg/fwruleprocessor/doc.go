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
// Addresses use netip.Addr, and CIDR keys use canonical netip.Prefix values:
//   - IPv4: walked using its 4 address bytes
//   - IPv6: walked using its 16 address bytes
//   - v4-mapped IPv6 (::ffff:x.x.x.x): unmapped to IPv4 if masking preserves the mapped address
//
// This normalization (see canonicalPrefix) ensures that a v4-mapped address matches
// against v4 CIDRs in the v4 sub-trie, not the v6 sub-trie.
//
// ## Trie Layout
//
// The trie has two independent roots: v4Root and v6Root. Each node has:
//   - children [2]*cidrTrieNode — left (bit=0) and right (bit=1)
//   - cidrKey  netip.Prefix        — canonical prefix stored at this depth; zero means no key
//
// Insertion walks the network prefix bits (MSB-first) from root, creating nodes
// as needed, and stores the parsed prefix at the node corresponding to the
// last prefix bit. For example, inserting "10.0.0.0/8" stores the key at depth 8
// in the v4 sub-trie.
//
// The compiler parses CIDRs once before processing rules. Both the compiler
// and insert use canonicalPrefix to mask host bits and normalize mapped addresses,
// so the stored key matches what the nonHostCIDRs map uses as its key.
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
// The trie is built once per compilation (in ComputeMapEntriesFromEndpointRules)
// from the non-host CIDR rules, queried for rules to find overlapping port
// permissions, and discarded after compilation completes.
// It is never shared across goroutines.
package fwruleprocessor

#ifndef __TC_SHARED_H
#define __TC_SHARED_H

// Types of the node-wide maps that tc.shared.bpf.c defines and the TC
// programs reference: aws_tc_config and aws_tcp_reset_pending. They live in
// one header because the binary that creates the maps and every program that
// uses them must agree on their key and value layouts; a mismatch would read
// garbage rather than fail to load.
//
// They are not in the events binary, which also defines the agent's
// conntrack map: a change to that binary makes the agent recreate the
// conntrack map, which drops the state of every allowed flow on the node.
// Keeping these maps in their own binary lets them change without that.

// aws_tc_config is an array with one entry, at TC_CONFIG_KEY: an array's entry
// always exists, so the lookup never misses.
#define TC_CONFIG_KEY 0

struct tc_config {
	// __u32 rather than bool: the agent writes this struct from Go
	// (tcConfig in bpf_client.go), and a fixed-size field keeps the two
	// layouts identical.
	__u32 tcp_reset_on_deny;
};

// aws_tcp_reset_pending marks the RSTs the ingress program sent, so the egress
// program can pass them (see consume_pending_reset). Not skb->mark: on 5.10, a
// redirect to a device's ingress clears it.
struct tcp_reset_pending_key {
	// The RST's addresses and ports, which is what the egress program can
	// see. 16 bytes holds an IPv6 address; an IPv4 address fills the first 4
	// and the rest stays zero, so one key type serves both families.
	__u8 saddr[16];
	__u8 daddr[16];
	__be16 sport;
	__be16 dport;
	// The pod's host veth, so one pod's entry can't be consumed by another
	// pod's egress program, as in the agent's conntrack map.
	__u32 ifindex;
};

// An entry lives microseconds, from the redirect to the egress program; the LRU
// evicts the rare ones whose RST the host dropped. At 5,000 denied SYNs/s the
// map held at most one entry, so 8,192 is a wide margin (well under 1 MiB).
#define TCP_RESET_PENDING_MAX_ENTRIES 8192

#endif // __TC_SHARED_H

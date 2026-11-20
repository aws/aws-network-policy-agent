#ifndef __RST_ON_DENY_H
#define __RST_ON_DENY_H

// Answers a denied TCP SYN with a RST instead of dropping it silently, when
// the agent runs with --enable-tcp-reset-on-deny. Why, and the alternatives
// considered: docs/proposals/tcp-reset-on-deny.md.
//
// Includers must declare aws_tc_config and aws_tcp_reset_pending first (see
// tc_shared.h for their types).

#include <bpf/bpf_endian.h>
#include "tc_shared.h"

// Every IP packet needs a TTL (IPv6: hop limit), or the first router discards
// it. 64 is the Linux default (net.ipv4.ip_default_ttl), what the pod's own
// stack would have used.
#define RST_TTL 64

// The RST sets Don't Fragment like the pod's own TCP packets, since Linux sets
// DF on TCP by default (path MTU discovery, net.ipv4.ip_no_pmtu_disc=0). At 40
// bytes it never needs fragmenting, so this can't affect delivery.
#define IPV4_DF 0x4000

// The IPv4 header length (ihl, RFC 791) and the TCP data offset (doff, RFC
// 9293 3.1) count 32-bit words, not bytes, so a 20-byte header is written as 5.
#define HEADER_LEN_WORDS(bytes) ((bytes) / 4)

// Reads skb->data or data_end with one explicit ctx load. With plain field
// reads, clang may reuse a ctx+offset pointer computed earlier (in the ct-deny
// build, shorten_denied_syn_v4 reads both just before), which the verifier
// rejects as "dereference of modified ctx ptr".
#define SKB_PACKET_PTR(skb, field) ({						\
	void *__p;								\
	asm volatile("%0 = *(u32 *)(%1 + %2)"					\
		     : "=r"(__p)						\
		     : "r"(skb), "i"(__builtin_offsetof(struct __sk_buff, field))); \
	__p;									\
})

// The RST's IP and TCP headers, built on the stack because resizing the packet
// invalidates every packet pointer, and filling them needs the SYN's fields.
// The Ethernet header is kept separate: in one struct the IP header would be
// either padded off its wire offset or, packed, misaligned on the stack, which
// the verifier rejects.
struct tcp_reset_v4 {
	struct iphdr ip;
	struct tcphdr tcp;
};

struct tcp_reset_v6 {
	struct ipv6hdr ip;
	struct tcphdr tcp;
};

// The TCP checksum covers a pseudo header (addresses, protocol, TCP length;
// RFC 9293 3.1, RFC 8200 8.1) followed by the TCP header. bpf_csum_diff sums
// one contiguous buffer of a multiple of 4 bytes, so they are copied into one
// (32 and 60 bytes).
struct tcp_csum_input_v4 {
	__be32 saddr;
	__be32 daddr;
	__u8 zero;
	__u8 protocol;
	__be16 tcp_len;
	struct tcphdr tcp;
};

struct tcp_csum_input_v6 {
	struct in6_addr saddr;
	struct in6_addr daddr;
	__be32 tcp_len;
	__u8 zero[3];
	__u8 nexthdr;
	struct tcphdr tcp;
};

// Turns bpf_csum_diff's 32-bit running sum into the 16-bit checksum the
// headers need (no helper does); the second fold absorbs the first's carry.
// bpf_l3/l4_csum_replace adjust an existing checksum, and these headers are
// new.
static __always_inline __u16 csum_fold(__s64 sum)
{
	__u32 csum = (__u32)sum;

	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return (__u16)~csum;
}

// Read from a map at run time so that programs pods already run follow a flag
// change without being reloaded. The entry is zero (off) until the agent
// writes it; the NULL check only satisfies the verifier.
static __always_inline bool tcp_reset_on_deny_enabled(void)
{
	__u32 key = TC_CONFIG_KEY;
	struct tc_config *config = bpf_map_lookup_elem(&aws_tc_config, &key);

	return config && config->tcp_reset_on_deny;
}

// Only a bare SYN's silent drop leaves the half-open entry this feature frees.
// Other denied packets (ACKs, data, SYN-ACKs, SYN-FINs, RSTs) aren't connection
// attempts, so they are still dropped.
static __always_inline bool is_bare_syn(struct tcphdr *tcp)
{
	return tcp->syn && !tcp->ack && !tcp->rst && !tcp->fin;
}

// RFC 9293 3.10.7.1: seq 0, acking the SYN's seq + 1. The client accepts a
// RST only if its ack matches the SYN, which is what fails the connection.
static __always_inline void fill_reset_tcp(struct tcphdr *rst, struct tcphdr *syn)
{
	rst->source = syn->dest;
	rst->dest = syn->source;
	rst->seq = 0;
	rst->ack_seq = bpf_htonl(bpf_ntohl(syn->seq) + 1);
	rst->doff = HEADER_LEN_WORDS(sizeof(struct tcphdr));
	rst->rst = 1;
	rst->ack = 1;
}

// The RST enters the host from the pod's side: to the host veth's MAC (the
// SYN's source), from the pod's (its destination). The host drops a frame not
// addressed to it.
static __always_inline void fill_reset_eth(struct ethhdr *rst, struct ethhdr *syn)
{
	__builtin_memcpy(rst->h_dest, syn->h_source, sizeof(rst->h_dest));
	__builtin_memcpy(rst->h_source, syn->h_dest, sizeof(rst->h_source));
	rst->h_proto = syn->h_proto;
}

// The ingress program runs as the SYN leaves the pod's host veth toward the
// pod, so redirecting to that veth's ingress makes the host receive the RST as
// if the pod sent it and route it back as a reply. Returns BPF_DROP (today's
// behavior) if any step fails.
static __always_inline int send_reset(struct __sk_buff *skb, struct ethhdr *eth, void *rst, __u32 rst_len,
				      struct tcp_reset_pending_key *pending)
{
	__u8 present = 1;

	// Recorded before the redirect: the egress program runs on the redirected
	// packet and needs the entry to pass it.
	if (bpf_map_update_elem(&aws_tcp_reset_pending, pending, &present, BPF_ANY))
		return BPF_DROP;
	// Cut to the RST's length, which drops the SYN's options and payload. On
	// failure the entry is removed: left behind, it would let a RST the pod
	// sends on these ports skip evaluation.
	if (bpf_skb_change_tail(skb, sizeof(*eth) + rst_len, 0) ||
	    bpf_skb_store_bytes(skb, 0, eth, sizeof(*eth), 0) ||
	    bpf_skb_store_bytes(skb, sizeof(*eth), rst, rst_len, 0)) {
		bpf_map_delete_elem(&aws_tcp_reset_pending, pending);
		return BPF_DROP;
	}
	// The SYN's checksum state (e.g. CHECKSUM_COMPLETE from the NIC) no
	// longer matches the packet; make the stack verify it in software.
	bpf_csum_level(skb, BPF_CSUM_LEVEL_RESET);
	return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
}

// Every deny path in the ingress program returns this instead of BPF_DROP, so
// drop versus RST is decided in one place. Callers pass IPv4 packets without IP
// options, as the programs' parsing assumes.
static __always_inline int deny_verdict_v4(struct __sk_buff *skb)
{
	void *data = SKB_PACKET_PTR(skb, data);
	void *data_end = SKB_PACKET_PTR(skb, data_end);
	struct ethhdr *syn_eth = data;
	struct iphdr *syn_ip = data + sizeof(*syn_eth);
	struct tcphdr *syn_tcp = data + sizeof(*syn_eth) + sizeof(*syn_ip);

	// The verifier needs the bounds check; a shorter packet can't be answered.
	if ((void *)(syn_tcp + 1) > data_end)
		return BPF_DROP;
	// With IP options, syn_tcp would point into the IP header.
	if (syn_ip->ihl != HEADER_LEN_WORDS(sizeof(struct iphdr)) || syn_ip->protocol != IPPROTO_TCP || !is_bare_syn(syn_tcp))
		return BPF_DROP;
	// After the packet checks, so other denied packets skip the lookup.
	if (!tcp_reset_on_deny_enabled())
		return BPF_DROP;

	struct ethhdr eth;
	struct tcp_reset_v4 rst = {};
	fill_reset_eth(&eth, syn_eth);
	// The SYN's IP header isn't reused: its length, ID and options belong to
	// the SYN.
	rst.ip.version = 4;
	rst.ip.ihl = HEADER_LEN_WORDS(sizeof(struct iphdr));
	rst.ip.tot_len = bpf_htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
	rst.ip.frag_off = bpf_htons(IPV4_DF);
	rst.ip.ttl = RST_TTL;
	rst.ip.protocol = IPPROTO_TCP;
	rst.ip.saddr = syn_ip->daddr;
	rst.ip.daddr = syn_ip->saddr;
	fill_reset_tcp(&rst.tcp, syn_tcp);

	// New headers, so full checksums. bpf_csum_diff only fails for sizes not a
	// multiple of 4 or over 512 bytes, so its result isn't checked.
	__s64 sum = bpf_csum_diff(NULL, 0, (__be32 *)&rst.ip, sizeof(rst.ip), 0);
	rst.ip.check = csum_fold(sum);

	struct tcp_csum_input_v4 csum_input = {
		.saddr = rst.ip.saddr,
		.daddr = rst.ip.daddr,
		.protocol = IPPROTO_TCP,
		.tcp_len = bpf_htons(sizeof(struct tcphdr)),
		.tcp = rst.tcp,
	};
	sum = bpf_csum_diff(NULL, 0, (__be32 *)&csum_input, sizeof(csum_input), 0);
	rst.tcp.check = csum_fold(sum);

	// The RST's own addresses and ports (what egress sees) and the veth.
	struct tcp_reset_pending_key pending = {
		.sport = rst.tcp.source,
		.dport = rst.tcp.dest,
		.ifindex = skb->ifindex,
	};
	__builtin_memcpy(pending.saddr, &rst.ip.saddr, sizeof(rst.ip.saddr));
	__builtin_memcpy(pending.daddr, &rst.ip.daddr, sizeof(rst.ip.daddr));
	return send_reset(skb, &eth, &rst, sizeof(rst), &pending);
}

// As deny_verdict_v4, for IPv6 packets whose next header is TCP (the programs
// don't parse extension headers).
static __always_inline int deny_verdict_v6(struct __sk_buff *skb)
{
	void *data = SKB_PACKET_PTR(skb, data);
	void *data_end = SKB_PACKET_PTR(skb, data_end);
	struct ethhdr *syn_eth = data;
	struct ipv6hdr *syn_ip = data + sizeof(*syn_eth);
	struct tcphdr *syn_tcp = data + sizeof(*syn_eth) + sizeof(*syn_ip);

	// The same checks as deny_verdict_v4. A SYN behind an extension header
	// has nexthdr != IPPROTO_TCP, so it is dropped as today.
	if ((void *)(syn_tcp + 1) > data_end)
		return BPF_DROP;
	if (syn_ip->nexthdr != IPPROTO_TCP || !is_bare_syn(syn_tcp))
		return BPF_DROP;
	if (!tcp_reset_on_deny_enabled())
		return BPF_DROP;

	struct ethhdr eth;
	struct tcp_reset_v6 rst = {};
	fill_reset_eth(&eth, syn_eth);
	// IPv6 has no header checksum; only the TCP checksum is computed.
	rst.ip.version = 6;
	rst.ip.payload_len = bpf_htons(sizeof(struct tcphdr));
	rst.ip.nexthdr = IPPROTO_TCP;
	rst.ip.hop_limit = RST_TTL;
	rst.ip.saddr = syn_ip->daddr;
	rst.ip.daddr = syn_ip->saddr;
	fill_reset_tcp(&rst.tcp, syn_tcp);

	struct tcp_csum_input_v6 csum_input = {
		.saddr = rst.ip.saddr,
		.daddr = rst.ip.daddr,
		.tcp_len = bpf_htonl(sizeof(struct tcphdr)),
		.nexthdr = IPPROTO_TCP,
		.tcp = rst.tcp,
	};
	__s64 sum = bpf_csum_diff(NULL, 0, (__be32 *)&csum_input, sizeof(csum_input), 0);
	rst.tcp.check = csum_fold(sum);

	struct tcp_reset_pending_key pending = {
		.sport = rst.tcp.source,
		.dport = rst.tcp.dest,
		.ifindex = skb->ifindex,
	};
	__builtin_memcpy(pending.saddr, &rst.ip.saddr, sizeof(rst.ip.saddr));
	__builtin_memcpy(pending.daddr, &rst.ip.daddr, sizeof(rst.ip.daddr));
	return send_reset(skb, &eth, &rst, sizeof(rst), &pending);
}

// Tells the RSTs send_reset sent apart from the pod's own, which are evaluated
// as usual. Deleting the entry limits it to that one packet. Callers check the
// RST flag first, so other traffic skips the lookup.
static __always_inline bool consume_pending_reset(struct tcp_reset_pending_key *pending)
{
	if (!bpf_map_lookup_elem(&aws_tcp_reset_pending, pending))
		return false;
	bpf_map_delete_elem(&aws_tcp_reset_pending, pending);
	return true;
}

// Build the key from the packet exactly as deny_verdict_v4/v6 did; any
// difference (such as bytes after an IPv4 address, which stay zero) and every
// RST would miss and be evaluated as pod traffic.
static __always_inline bool is_pending_reset_v4(struct __sk_buff *skb, __be32 saddr, __be32 daddr,
						__be16 sport, __be16 dport)
{
	struct tcp_reset_pending_key pending = {
		.sport = sport,
		.dport = dport,
		.ifindex = skb->ifindex,
	};

	__builtin_memcpy(pending.saddr, &saddr, sizeof(saddr));
	__builtin_memcpy(pending.daddr, &daddr, sizeof(daddr));
	return consume_pending_reset(&pending);
}

static __always_inline bool is_pending_reset_v6(struct __sk_buff *skb, struct in6_addr *saddr,
						struct in6_addr *daddr, __be16 sport, __be16 dport)
{
	struct tcp_reset_pending_key pending = {
		.sport = sport,
		.dport = dport,
		.ifindex = skb->ifindex,
	};

	__builtin_memcpy(pending.saddr, saddr, sizeof(*saddr));
	__builtin_memcpy(pending.daddr, daddr, sizeof(*daddr));
	return consume_pending_reset(&pending);
}

#endif // __RST_ON_DENY_H

#ifndef __CT_DENY_H
#define __CT_DENY_H

// Shortens the kernel (netfilter) conntrack entry of a TCP connection the
// ingress program denies.
//
// The ingress program runs at TC egress of the pod's host-side veth, after
// POSTROUTING has confirmed the kernel conntrack entry for the packet. When
// the SYN is dropped the entry is never answered and sits in SYN_SENT for
// nf_conntrack_tcp_timeout_syn_sent (120 s by default), so enough denied
// connection attempts fill nf_conntrack_max and take down allowed traffic on
// the node. Setting the entry's timeout to NPA_DENIED_CT_TIMEOUT_MS bounds
// that to rate x (timeout + conntrack GC lag).
//
// Only built with -DNPA_CT_SHORTEN_ON_DENY, as a second set of ingress objects
// (tc.v4ingress.ctdeny.bpf.o, tc.v6ingress.ctdeny.bpf.o) built from the same
// sources. This has to be a separate build rather than a runtime switch: a
// kfunc call is resolved when the program is loaded, even if it never runs, so
// one object containing these calls would fail to load on kernels without the
// kfuncs (6.0+ with BTF is needed; AL2's 5.10 lacks them). The agent loads the
// ct-deny objects when the kernel has the kfuncs and the regular objects
// otherwise. Without the define, the regular objects' instructions are
// unchanged.
#ifdef NPA_CT_SHORTEN_ON_DENY

#include <bpf/bpf_endian.h>

// New timeout for a denied SYN's conntrack entry, in milliseconds (the unit
// bpf_ct_change_timeout takes), replacing nf_conntrack_tcp_timeout_syn_sent
// (120 s by default). The kernel frees expired entries lazily, mostly from its
// conntrack garbage collector, so under load an entry lives a few seconds
// past this.
#define NPA_DENIED_CT_TIMEOUT_MS 1000

// BPF_F_CURRENT_NETNS from the kernel's uapi bpf.h, defined here because not
// every generated vmlinux.h has that enum.
#define NPA_BPF_F_CURRENT_NETNS (-1)

struct nf_conn;

// 12-byte (pre-zone) layout of struct bpf_ct_opts. It is accepted by every
// kernel that has the kfuncs: 6.0 to 6.11 require exactly this size, and 6.12+
// also accept a 16-byte layout. The struct is only in nf_conntrack's module
// BTF, so it is not in vmlinux.h.
struct bpf_ct_opts___local {
	__s32 netns_id;
	__s32 error;
	__u8 l4proto;
	__u8 dir;
	__u8 reserved[2];
};

extern struct nf_conn *bpf_skb_ct_lookup(struct __sk_buff *skb, struct bpf_sock_tuple *bpf_tuple,
					 __u32 tuple__sz, struct bpf_ct_opts___local *opts,
					 __u32 opts__sz) __ksym;
extern int bpf_ct_change_timeout(struct nf_conn *nfct, __u32 timeout) __ksym;
extern void bpf_ct_release(struct nf_conn *nfct) __ksym;

// Looks up the entry for tuple in the host netns (skb->dev is the host veth)
// and shortens its timeout.
//
// There is no check that the entry never saw a reply (IPS_SEEN_REPLY): reading
// nf_conn fields portably needs CO-RE, which the agent's loader does not do.
// Callers only pass pure SYNs the agent drops. Their entry is normally
// unanswered. A SYN retransmitted after a policy change may belong to an entry
// the server already answered, and shortening that is fine too: the connection
// is now denied.
static __always_inline void shorten_ct(struct __sk_buff *skb, struct bpf_sock_tuple *tuple, __u32 tuple_sz)
{
	struct bpf_ct_opts___local opts = {
		// The namespace of skb->dev. The program runs on the pod's
		// host-side veth, so this is the host namespace, where the kernel
		// created the entry for the SYN.
		.netns_id = NPA_BPF_F_CURRENT_NETNS,
		.l4proto = IPPROTO_TCP,
	};
	// Returns a referenced entry, or NULL if there is no entry for this tuple
	// or the lookup failed (opts.error has the reason, unused here). The
	// verifier requires the NULL check before ct is used, and a matching
	// bpf_ct_release on every path once it is non-NULL.
	struct nf_conn *ct = bpf_skb_ct_lookup(skb, tuple, tuple_sz, &opts, sizeof(opts));

	if (!ct)
		return;
	// Fails harmlessly with -EPERM for IPS_FIXED_TIMEOUT entries and -ETIME
	// for dying ones.
	bpf_ct_change_timeout(ct, NPA_DENIED_CT_TIMEOUT_MS);
	bpf_ct_release(ct);
}

// The packet reaches the pod's veth after any NAT the node applied, so its
// tuple matches the entry's ORIGINAL tuple only for direct-to-pod traffic. For
// Service and NodePort traffic, ORIGINAL holds the pre-DNAT destination (and,
// with SNAT, the pre-SNAT source). The reversed packet tuple, however, is the
// entry's REPLY tuple in every case, so one lookup by the reversed tuple finds
// the entry. The kernel keeps tuples unique across both directions, so no
// other entry can match it.
static __always_inline void shorten_denied_ct_v4(struct __sk_buff *skb, __be32 saddr, __be32 daddr,
						 __be16 sport, __be16 dport)
{
	struct bpf_sock_tuple tuple = {};

	tuple.ipv4.saddr = daddr;
	tuple.ipv4.daddr = saddr;
	tuple.ipv4.sport = dport;
	tuple.ipv4.dport = sport;
	shorten_ct(skb, &tuple, sizeof(tuple.ipv4));
}

static __always_inline void shorten_denied_ct_v6(struct __sk_buff *skb, struct in6_addr *saddr,
						 struct in6_addr *daddr, __be16 sport, __be16 dport)
{
	struct bpf_sock_tuple tuple = {};

	__builtin_memcpy(tuple.ipv6.saddr, daddr, sizeof(tuple.ipv6.saddr));
	__builtin_memcpy(tuple.ipv6.daddr, saddr, sizeof(tuple.ipv6.daddr));
	tuple.ipv6.sport = dport;
	tuple.ipv6.dport = sport;
	shorten_ct(skb, &tuple, sizeof(tuple.ipv6));
}

// The drop sites call these instead of reusing the program's parsed headers.
// They re-read the headers from skb, so nothing from the program's own parse
// has to stay live across the policy evaluation before the drop. Keeping those
// values live multiplied the verifier's states and slowed loading the program
// (on kernel 6.18, to twice the regular program's load time). They assume the
// same layout the programs parse: TCP right after a fixed-size IP header.
static __always_inline void shorten_denied_syn_v4(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *ip = data + sizeof(struct ethhdr);
	struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

	if ((void *)(tcp + 1) > data_end)
		return;
	// Only a pure SYN's entry is unanswered; see the callers.
	if (ip->protocol != IPPROTO_TCP || !tcp->syn || tcp->ack)
		return;
	shorten_denied_ct_v4(skb, ip->saddr, ip->daddr, tcp->source, tcp->dest);
}

static __always_inline void shorten_denied_syn_v6(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ipv6hdr *ip = data + sizeof(struct ethhdr);
	struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

	if ((void *)(tcp + 1) > data_end)
		return;
	if (ip->nexthdr != IPPROTO_TCP || !tcp->syn || tcp->ack)
		return;
	shorten_denied_ct_v6(skb, &ip->saddr, &ip->daddr, tcp->source, tcp->dest);
}

#endif // NPA_CT_SHORTEN_ON_DENY
#endif // __CT_DENY_H

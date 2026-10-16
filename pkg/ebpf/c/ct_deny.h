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

#define NPA_DENIED_CT_TIMEOUT_MS 1000
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
// and shortens its timeout. Returns 1 if an entry was found.
//
// There is no check that the entry never saw a reply (IPS_SEEN_REPLY): reading
// nf_conn fields portably needs CO-RE, which the agent's loader does not do.
// Callers only pass pure SYNs of connections the agent has no state for, and
// established flows are admitted by aws_conntrack_map before policy runs.
static __always_inline int shorten_ct(struct __sk_buff *skb, struct bpf_sock_tuple *tuple, __u32 tuple_sz)
{
	struct bpf_ct_opts___local opts = {
		.netns_id = NPA_BPF_F_CURRENT_NETNS,
		.l4proto = IPPROTO_TCP,
	};
	struct nf_conn *ct = bpf_skb_ct_lookup(skb, tuple, tuple_sz, &opts, sizeof(opts));

	if (!ct)
		return 0;
	// Fails harmlessly with -EPERM for IPS_FIXED_TIMEOUT entries and -ETIME
	// for dying ones.
	bpf_ct_change_timeout(ct, NPA_DENIED_CT_TIMEOUT_MS);
	bpf_ct_release(ct);
	return 1;
}

// Tries the packet's own tuple first, which is the entry's ORIGINAL tuple for
// direct-to-pod traffic. If that misses, the connection was DNATed (Service or
// NodePort traffic, where the ORIGINAL destination is the ClusterIP or node IP),
// so look it up by the reversed tuple, which is the entry's REPLY tuple either
// way. Both directions are hashed, so either lookup returns the same entry.
static __always_inline void shorten_denied_ct_v4(struct __sk_buff *skb, __be32 saddr, __be32 daddr,
						 __be16 sport, __be16 dport)
{
	struct bpf_sock_tuple tuple = {};

	tuple.ipv4.saddr = saddr;
	tuple.ipv4.daddr = daddr;
	tuple.ipv4.sport = sport;
	tuple.ipv4.dport = dport;
	if (shorten_ct(skb, &tuple, sizeof(tuple.ipv4)))
		return;

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

	__builtin_memcpy(tuple.ipv6.saddr, saddr, sizeof(tuple.ipv6.saddr));
	__builtin_memcpy(tuple.ipv6.daddr, daddr, sizeof(tuple.ipv6.daddr));
	tuple.ipv6.sport = sport;
	tuple.ipv6.dport = dport;
	if (shorten_ct(skb, &tuple, sizeof(tuple.ipv6)))
		return;

	__builtin_memcpy(tuple.ipv6.saddr, daddr, sizeof(tuple.ipv6.saddr));
	__builtin_memcpy(tuple.ipv6.daddr, saddr, sizeof(tuple.ipv6.daddr));
	tuple.ipv6.sport = dport;
	tuple.ipv6.dport = sport;
	shorten_ct(skb, &tuple, sizeof(tuple.ipv6));
}

#endif // NPA_CT_SHORTEN_ON_DENY
#endif // __CT_DENY_H

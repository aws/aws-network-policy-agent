#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define BPF_F_NO_PREALLOC 1
#define ETH_HLEN 14
#define BPF_MAP_ID_INGRESS_MAP 2
#define MAX_RULES 256
#define MIN_RULES 128
#define PIN_GLOBAL_NS 2
#define RESERVED_IP_PROTOCOL 255
#define ANY_IP_PROTOCOL 254
#define ANY_PORT 0
#define MAX_PORT_PROTOCOL 24
#define CT_VAL_DEFAULT_ALLOW 0
#define CT_VAL_POLICIES_APPLIED 1
#define POLICIES_APPLIED 0
#define DEFAULT_ALLOW 1
#define DEFAULT_DENY 2

struct bpf_map_def_pvt {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	__u32 pinning;
	__u32 inner_map_fd;
};

struct keystruct
{
  __u32 prefix_len;
  __u8  ip[16];
};

struct lpm_trie_key {
    __u32 prefixlen;
    __u8  ip[16];
};

struct lpm_trie_val {
	__u32 protocol;
	__u32 start_port;
	__u32 end_port;
};


struct conntrack_key {
	struct	in6_addr saddr;
	__u16 src_port;
	struct	in6_addr daddr;
	__u16 dest_port;
	__u8  protocol;
	struct in6_addr owner_addr;
};

struct conntrack_value {
	__u8 val; // 0 => default-allow, 1 => policies-applied
};

struct data_t {
	struct	in6_addr src_ip;	
	__u32  src_port;
	struct	in6_addr dest_ip;
	__u32  dest_port;
	__u32  protocol;
	__u32  verdict;
	__u32 packet_sz;
	__u8 is_egress;
};

struct bpf_map_def_pvt SEC("maps") egress_map = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = sizeof(struct lpm_trie_key),
	.value_size = sizeof(struct lpm_trie_val[MAX_PORT_PROTOCOL]),
	.max_entries = 65536,
	.map_flags = BPF_F_NO_PREALLOC,
	.pinning = PIN_GLOBAL_NS,
};

struct pod_state {
    __u8 state; // 0 => POLICIES_APPLIED, 1 => DEFAULT_ALLOW, 2 => DEFAULT_DENY
};

struct bpf_map_def_pvt SEC("maps") egress_pod_state_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u32), // default key = 0. We are storing a single state per pod identifier
    .value_size  = sizeof(struct pod_state),
    .max_entries = 1,
	.map_flags = BPF_F_NO_PREALLOC,
    .pinning     = PIN_GLOBAL_NS,
};

struct bpf_map_def_pvt aws_conntrack_map;
struct bpf_map_def_pvt policy_events;

static inline int evaluateByLookUp(struct keystruct trie_key, struct conntrack_key flow_key, struct pod_state *pst, struct data_t evt, struct ipv6hdr *ip, __u32 l4_dst_port) {
	struct lpm_trie_val *trie_val;
	//Check if it's in the allowed list
	trie_val = bpf_map_lookup_elem(&egress_map, &trie_key);
	if (trie_val == NULL) {
		evt.verdict = 0;
		bpf_ringbuf_output(&policy_events, &evt, sizeof(evt), 0);
		return BPF_DROP;
	}

	for (int i = 0; i < MAX_PORT_PROTOCOL; i++, trie_val++){
		if (trie_val->protocol == RESERVED_IP_PROTOCOL) {
			evt.verdict = 0;
			bpf_ringbuf_output(&policy_events, &evt, sizeof(evt), 0);
			return BPF_DROP;
		}

		// 1. ANY_IP_PROTOCOL:
		//    - If the rule specifies ANY_IP_PROTOCOL (i.e., applies to all L4 protocols),
		//    - Then match if:
		//        - start_port is ANY_PORT → rule applies to all ports
		//        - OR l4_dst_port is exactly the start_port
		//        - OR l4_dst_port falls within (start_port, end_port] range
		//
		// 2. Specific Protocol Match:
		//    - If trie_val->protocol matches the packet's IP protocol (e.g., TCP or UDP),
		//    - Then apply the same port match logic as above.
		if ((trie_val->protocol == ANY_IP_PROTOCOL &&
			((trie_val->start_port == ANY_PORT) || (l4_dst_port == trie_val->start_port) ||
			(l4_dst_port > trie_val->start_port && l4_dst_port <= trie_val->end_port))) ||
			(trie_val->protocol == ip->nexthdr &&
			((trie_val->start_port == ANY_PORT) || (l4_dst_port == trie_val->start_port) || 
			(l4_dst_port > trie_val->start_port && l4_dst_port <= trie_val->end_port)))) {
			//Inject in to conntrack map
			struct conntrack_value new_flow_val = {};
			if (pst->state == DEFAULT_ALLOW) {
				new_flow_val.val = CT_VAL_DEFAULT_ALLOW;
			} else {
				new_flow_val.val = CT_VAL_POLICIES_APPLIED;
			}
			bpf_map_update_elem(&aws_conntrack_map, &flow_key, &new_flow_val, 0); // 0 - BPF_ANY
			evt.verdict = 1;
			bpf_ringbuf_output(&policy_events, &evt, sizeof(evt), 0);
			return BPF_OK;
		}
	}
	evt.verdict = 0;
	bpf_ringbuf_output(&policy_events, &evt, sizeof(evt), 0);
	return BPF_DROP;
}

SEC("tc_cls")
int handle_egress(struct __sk_buff *skb)
{
	
	struct keystruct trie_key;
	struct lpm_trie_val *trie_val;
	__u16 l4_src_port = 0;
	__u16 l4_dst_port = 0;
	struct conntrack_key flow_key;
	struct conntrack_value *flow_val;
	struct conntrack_key reverse_flow_key;
	struct conntrack_value *reverse_flow_val;
	struct data_t evt = {};
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

 	__builtin_memset(&flow_key, 0, sizeof(flow_key));
	__builtin_memset(&reverse_flow_key, 0, sizeof(reverse_flow_key));

	struct ethhdr *ether = data;
	if (data + sizeof(*ether) > data_end) {
		return BPF_OK;
	}

	if (ether->h_proto == 0xdd86) {  // htons(ETH_P_IPV6) -> 0x086ddU
		data += sizeof(*ether);
		struct ipv6hdr *ip = data;
		struct tcphdr *l4_tcp_hdr = data + sizeof(struct ipv6hdr);
		struct udphdr *l4_udp_hdr = data + sizeof(struct ipv6hdr);
		struct sctphdr *l4_sctp_hdr = data + sizeof(struct ipv6hdr);

		if (data + sizeof(*ip) > data_end) {
			return BPF_OK;
		}

		if (ip->version != 6) {
			return BPF_OK;
		}

		//ICMPv6 - Neighbor Discovery Packets
        if (ip->nexthdr == 58) {
        	return BPF_OK;
        }
   
		switch (ip->nexthdr) {
			case IPPROTO_TCP:
				if (data + sizeof(*ip) + sizeof(*l4_tcp_hdr) > data_end) {
					return BPF_OK;
				}
				l4_src_port = (((((unsigned short)(l4_tcp_hdr->source) & 0xFF)) << 8) | (((unsigned short)(l4_tcp_hdr->source) & 0xFF00) >> 8));
				l4_dst_port = (((((unsigned short)(l4_tcp_hdr->dest) & 0xFF)) << 8) | (((unsigned short)(l4_tcp_hdr->dest) & 0xFF00) >> 8));
				break;
			case IPPROTO_UDP:
				if (data + sizeof(*ip) + sizeof(*l4_udp_hdr) > data_end) {
					return BPF_OK;
				}
				l4_src_port = (((((unsigned short)(l4_udp_hdr->source) & 0xFF)) << 8) | (((unsigned short)(l4_udp_hdr->source) & 0xFF00) >> 8));
				l4_dst_port = (((((unsigned short)(l4_udp_hdr->dest) & 0xFF)) << 8) | (((unsigned short)(l4_udp_hdr->dest) & 0xFF00) >> 8));
				break;
			case IPPROTO_SCTP:
				if (data + sizeof(*ip) + sizeof(*l4_sctp_hdr) > data_end) {
					return BPF_OK;
				}
				l4_src_port = (((((unsigned short)(l4_sctp_hdr->source) & 0xFF)) << 8) | (((unsigned short)(l4_sctp_hdr->source) & 0xFF00) >> 8));
				l4_dst_port = (((((unsigned short)(l4_sctp_hdr->dest) & 0xFF)) << 8) | (((unsigned short)(l4_sctp_hdr->dest) & 0xFF00) >> 8));
				break;
		}

		trie_key.prefix_len = 128;
			
		//Fill the IP Key to be used for lookup
		for (int i=0; i<16; i++){
			trie_key.ip[i] = ip->daddr.in6_u.u6_addr8[i];
		}

		//Check for the an existing flow in the conntrack table
		flow_key.saddr = ip->saddr;
		flow_key.daddr = ip->daddr;
		flow_key.src_port = l4_src_port;
		flow_key.dest_port = l4_dst_port;
		flow_key.protocol = ip->nexthdr;
		flow_key.owner_addr = ip->saddr;

		evt.src_ip = ip->saddr;
		evt.dest_ip = ip->daddr;	
		evt.src_port = flow_key.src_port;
		evt.dest_port = flow_key.dest_port;
		evt.protocol = flow_key.protocol;
		evt.is_egress = 1;
		evt.packet_sz = skb->len;

		__u32 key = 0; 
		struct pod_state *pst = bpf_map_lookup_elem(&egress_pod_state_map, &key);
		// There should always be an entry in pod_state_map. pst returned in above line should never be null.
		if (pst == NULL) {
			evt.verdict = 0;
			bpf_ringbuf_output(&policy_events, &evt, sizeof(evt), 0);
			return BPF_DROP;
		}

		if (pst->state == DEFAULT_DENY) {
			evt.verdict = 0;
			bpf_ringbuf_output(&policy_events, &evt, sizeof(evt), 0);
			return BPF_DROP;
		}

		//Check if it's an existing flow
		flow_val = (struct conntrack_value *)bpf_map_lookup_elem(&aws_conntrack_map, &flow_key);
		if (flow_val != NULL) { 
			// If it's a "default allow" flow, check if pod has flipped to "policies applied" state
			if (flow_val->val == CT_VAL_DEFAULT_ALLOW && pst->state == DEFAULT_ALLOW) {
				return BPF_OK;
			}
			if (flow_val->val == CT_VAL_POLICIES_APPLIED && pst->state == POLICIES_APPLIED) {
				return BPF_OK;
			}
			if (flow_val->val == CT_VAL_POLICIES_APPLIED && pst->state == DEFAULT_ALLOW) {
				flow_val->val = CT_VAL_DEFAULT_ALLOW;
				bpf_map_update_elem(&aws_conntrack_map, &flow_key, flow_val, 0); // 0 -> BPF_ANY
				return BPF_OK;
			}
			if (flow_val->val == CT_VAL_DEFAULT_ALLOW && pst->state == POLICIES_APPLIED) {
				int ret = evaluateByLookUp(trie_key, flow_key, pst, evt, ip, l4_dst_port);
				if (ret == BPF_DROP) {
					bpf_map_delete_elem(&aws_conntrack_map, &flow_key);
					return BPF_DROP;
				} 
				return BPF_OK;
			}
		}

		//Check for the reverse flow entry in the conntrack table
		reverse_flow_key.saddr = ip->daddr;
		reverse_flow_key.daddr = ip->saddr;
		reverse_flow_key.src_port = l4_dst_port;
		reverse_flow_key.dest_port = l4_src_port;
		reverse_flow_key.protocol = ip->nexthdr;
		reverse_flow_key.owner_addr = ip->saddr;
			
		//Check if it's a response packet
		reverse_flow_val = (struct conntrack_value *)bpf_map_lookup_elem(&aws_conntrack_map, &reverse_flow_key);
		if (reverse_flow_val != NULL) { 
			return BPF_OK;
		}

		if (pst->state == DEFAULT_ALLOW) {
			struct conntrack_value new_flow_val = {};
			new_flow_val.val = CT_VAL_DEFAULT_ALLOW;
			bpf_map_update_elem(&aws_conntrack_map, &flow_key, &new_flow_val, 0); // 0 - BPF_ANY
			evt.verdict = 1;
			bpf_ringbuf_output(&policy_events, &evt, sizeof(evt), 0);
			return BPF_OK;
		}

		return evaluateByLookUp(trie_key, flow_key, pst, evt, ip, l4_dst_port);
	}
	return BPF_OK;
}

char _license[] SEC("license") = "GPL";

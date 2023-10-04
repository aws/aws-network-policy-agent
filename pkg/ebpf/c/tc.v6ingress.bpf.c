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

#define IN6_ARE_ADDR_EQUAL(a, b)			\
    (__builtin_memcmp(&(a)->in6_u.u6_addr8[0], &(b)->in6_u.u6_addr8[0], sizeof(struct in6_addr)) == 0)

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
};

struct conntrack_value {
	struct in6_addr addr;
};

struct data_t {
	struct	in6_addr src_ip;	
	__u32  src_port;
	struct	in6_addr dest_ip;
	__u32  dest_port;
	__u32  protocol;
	__u32  verdict;
};

struct bpf_map_def_pvt SEC("maps") ingress_map = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size =sizeof(struct lpm_trie_key),
	.value_size = sizeof(struct lpm_trie_val[8]),
	.max_entries = 65536,
	.map_flags = BPF_F_NO_PREALLOC,
	.pinning = PIN_GLOBAL_NS,
};

struct bpf_map_def_pvt aws_conntrack_map;
struct bpf_map_def_pvt policy_events;


SEC("tc_cls")
int handle_ingress(struct __sk_buff *skb)
{
	struct keystruct trie_key;
	struct lpm_trie_val *trie_val;
	__u16 l4_src_port = 0;
	__u16 l4_dst_port = 0;
	struct conntrack_key flow_key;
    	struct conntrack_value *flow_val;
	struct conntrack_value *reverse_flow_val;
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct data_t evt = {};

    	__builtin_memset(&flow_key, 0, sizeof(flow_key));

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
             trie_key.ip[i] = ip->saddr.in6_u.u6_addr8[i];
        }
	
	//Check for the an existing flow in the conntrack table
	flow_key.saddr = ip->saddr;
	flow_key.daddr = ip->daddr;
	flow_key.src_port = l4_src_port;
	flow_key.dest_port = l4_dst_port;
	flow_key.protocol = ip->nexthdr;

	//Check if it's an existing flow
	flow_val = (struct conntrack_value *)bpf_map_lookup_elem(&aws_conntrack_map, &flow_key);
	if (flow_val != NULL && (flow_val->addr.in6_u.u6_addr8[12] == flow_key.daddr.in6_u.u6_addr8[12] 
			         && flow_val->addr.in6_u.u6_addr8[13] == flow_key.daddr.in6_u.u6_addr8[13] 
				 && flow_val->addr.in6_u.u6_addr8[14] == flow_key.daddr.in6_u.u6_addr8[14]
				 && flow_val->addr.in6_u.u6_addr8[15] == flow_key.daddr.in6_u.u6_addr8[15])) {
		return BPF_OK;	
	}

	evt.src_ip = ip->saddr;
	evt.dest_ip = ip->daddr;
	evt.src_port = flow_key.src_port;
	evt.dest_port = flow_key.dest_port;
	evt.protocol = flow_key.protocol;

	//Swap to check reverse flow
	flow_key.daddr = ip->saddr;
	flow_key.saddr = ip->daddr;
	flow_key.src_port =  flow_key.dest_port;
	flow_key.dest_port =  l4_src_port;
	

	//Check if it's a response packet
	reverse_flow_val = (struct conntrack_value *)bpf_map_lookup_elem(&aws_conntrack_map, &flow_key);
	if (reverse_flow_val != NULL && (reverse_flow_val->addr.in6_u.u6_addr8[12] == flow_key.saddr.in6_u.u6_addr8[12] 
			         && reverse_flow_val->addr.in6_u.u6_addr8[13] == flow_key.saddr.in6_u.u6_addr8[13] 
				 && reverse_flow_val->addr.in6_u.u6_addr8[14] == flow_key.saddr.in6_u.u6_addr8[14]
				 && reverse_flow_val->addr.in6_u.u6_addr8[15] == flow_key.saddr.in6_u.u6_addr8[15])) {
		return BPF_OK;	
	}

	//Check if it's in the allowed list
	trie_val = bpf_map_lookup_elem(&ingress_map, &trie_key);
	if (trie_val == NULL) {
		bpf_ringbuf_output(&policy_events, &evt, sizeof(evt), 0);
		return BPF_DROP;
	}

	for (int i=0; i<4; i++, trie_val++){
		if (trie_val->protocol == RESERVED_IP_PROTOCOL) {
			bpf_ringbuf_output(&policy_events, &evt, sizeof(evt), 0);
			return BPF_DROP;
		}

		if ((trie_val->protocol == ANY_IP_PROTOCOL) || (trie_val->protocol == ip->nexthdr &&
					((trie_val->start_port == ANY_PORT) || (l4_dst_port == trie_val->start_port) ||
					(l4_dst_port > trie_val->start_port && l4_dst_port <= trie_val->end_port)))) {
				//Inject in to conntrack map
			struct conntrack_value new_flow_val;
			__builtin_memset(&new_flow_val, 0, sizeof(new_flow_val));
			new_flow_val.addr = ip->daddr;

			//Reswap before adding to conntrack
			flow_key.saddr = ip->saddr;
			flow_key.daddr = ip->daddr;
			flow_key.dest_port = flow_key.src_port; 
			flow_key.src_port = l4_src_port;

			bpf_map_update_elem(&aws_conntrack_map, &flow_key, &new_flow_val, 0); // 0 - BPF_ANY
			evt.verdict = 1;
			bpf_ringbuf_output(&policy_events, &evt, sizeof(evt), 0);
			return BPF_OK;
			}
	}
	bpf_ringbuf_output(&policy_events, &evt, sizeof(evt), 0);
	return BPF_DROP;
	}
	return BPF_OK;
}

char _license[] SEC("license") = "GPL";

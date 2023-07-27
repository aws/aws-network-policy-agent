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
	__u8  src_ip[16];
	__u16 src_port;
	__u8  dest_ip[16];
	__u16 dest_port;
	__u8  protocol;
};

struct conntrack_value {
	__u8 val[16];
};

struct data_t {
	__u8   src_ip[16];
	__u32  src_port;
	__u8   dest_ip[16];
	__u32  dest_port;
	__u32  protocol;
	__u32  verdict;
};

struct bpf_map_def_pvt SEC("maps") egress_map = {
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
int handle_egress(struct __sk_buff *skb)
{
	struct keystruct trie_key;
	struct lpm_trie_val *trie_val;
    __u32 l4_src_port = 0;
    __u32 l4_dst_port = 0;
    struct conntrack_key flow_key;
    struct conntrack_value *flow_val;
    struct conntrack_key reverse_flow_key;
    struct conntrack_value *reverse_flow_val;
    struct data_t evt = {};
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	__u8 src_ip[16];

    memset(&flow_key, 0, sizeof(flow_key));
    memset(&src_ip, 0, sizeof(src_ip));
    memset(&reverse_flow_key, 0, sizeof(reverse_flow_key));

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
              src_ip[i] = ip->saddr.in6_u.u6_addr8[i];
              flow_key.src_ip[i] = ip->saddr.in6_u.u6_addr8[i];
              flow_key.dest_ip[i] = ip->daddr.in6_u.u6_addr8[i];
              reverse_flow_key.src_ip[i] = ip->daddr.in6_u.u6_addr8[i];
              reverse_flow_key.dest_ip[i] = ip->saddr.in6_u.u6_addr8[i];
              evt.src_ip[i] = ip->saddr.in6_u.u6_addr8[i];
              evt.dest_ip[i] = ip->daddr.in6_u.u6_addr8[i];
        }

		//Check for the an existing flow in the conntrack table
		flow_key.src_port = l4_src_port;
		flow_key.dest_port = l4_dst_port;
		flow_key.protocol = ip->nexthdr;


		//Check if it's an existing flow
		flow_val = (struct conntrack_value *)bpf_map_lookup_elem(&aws_conntrack_map, &flow_key);
		if (flow_val != NULL &&(flow_val->val[12] == src_ip[12] && flow_val->val[13] == src_ip[13]
					&& flow_val->val[14] == src_ip[14] && flow_val->val[15] == src_ip[15])) {
			return BPF_OK;
		}

		evt.src_port = flow_key.src_port;
		evt.dest_port = flow_key.dest_port;
		evt.protocol = flow_key.protocol;

		//Check for the reverse flow entry in the conntrack table
		reverse_flow_key.src_port = l4_dst_port;
		reverse_flow_key.dest_port = l4_src_port;
		reverse_flow_key.protocol = ip->nexthdr;


		//Check if it's a response packet
		reverse_flow_val = (struct conntrack_value *)bpf_map_lookup_elem(&aws_conntrack_map, &reverse_flow_key);
		if (reverse_flow_val != NULL &&(reverse_flow_val->val[12] == src_ip[12] && reverse_flow_val->val[13] == src_ip[13]
					&& reverse_flow_val->val[14] == src_ip[14] && reverse_flow_val->val[15] == src_ip[15])) {
			return BPF_OK;
		}

		//Check if it's in the allowed list
		trie_val = bpf_map_lookup_elem(&egress_map, &trie_key);
		if (trie_val == NULL) {
			evt.verdict = 0;
			bpf_ringbuf_output(&policy_events, &evt, sizeof(evt), 0);
			return BPF_DROP;
		}

		for (int i=0; i<4; i++, trie_val++){
			if (trie_val->protocol == RESERVED_IP_PROTOCOL) {
				evt.verdict = 0;
				bpf_ringbuf_output(&policy_events, &evt, sizeof(evt), 0);
				return BPF_DROP;
			}

			if ((trie_val->protocol == ANY_IP_PROTOCOL) || (trie_val->protocol == ip->nexthdr &&
						((trie_val->start_port == ANY_PORT) || (l4_dst_port == trie_val->start_port) ||
						 (l4_dst_port > trie_val->start_port && l4_dst_port <= trie_val->end_port)))) {
				//Inject in to conntrack map
				struct conntrack_value new_flow_val = {};
				new_flow_val.val[0]=src_ip[0];
				new_flow_val.val[1]=src_ip[1];
				new_flow_val.val[2]=src_ip[2];
				new_flow_val.val[3]=src_ip[3];
				new_flow_val.val[4]=src_ip[4];
                new_flow_val.val[5]=src_ip[5];
                new_flow_val.val[6]=src_ip[6];
                new_flow_val.val[7]=src_ip[7];
                new_flow_val.val[8]=src_ip[8];
                new_flow_val.val[9]=src_ip[9];
                new_flow_val.val[10]=src_ip[10];
                new_flow_val.val[11]=src_ip[11];
                new_flow_val.val[12]=src_ip[12];
                new_flow_val.val[13]=src_ip[13];
                new_flow_val.val[14]=src_ip[14];
                new_flow_val.val[15]=src_ip[15];
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
	return BPF_OK;
}

char _license[] SEC("license") = "GPL";

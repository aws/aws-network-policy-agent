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
#define POLICIES_APPLIED 0
#define DEFAULT_ALLOW 1
#define DEFAULT_DENY 2
#define ERROR_TIER 0
#define ADMIN_TIER 1
#define NETWORK_POLICY_TIER 2
#define BASELINE_TIER 3
#define DEFAULT_TIER 4
#define ACTION_DENY 0
#define ACTION_ALLOW 1
#define ACTION_PASS 2
#define MAX_RULE_PRIORITY 65536
#define ADMIN_TIER_PRIORITY_LIMIT 1000
#define CT_VAL_DEFAULT_ALLOW 0
#define CT_VAL_DEFAULT_ALLOW_DEFAULT_ALLOW 2
#define CT_VAL_DEFAULT_ALLOW_DEFAULT_DENY 3
#define CT_VAL_DEFAULT_ALLOW_POLICIES_APPLIED 4
#define CT_VAL_POLICIES_APPLIED_DEFAULT_ALLOW 5
#define CT_VAL_POLICIES_APPLIED_DEFAULT_DENY 6
#define CT_VAL_POLICIES_APPLIED_POLICIES_APPLIED 7

#define GET_CT_VAL(a, b) \
    ((a) == DEFAULT_ALLOW && (b) == DEFAULT_ALLOW ? CT_VAL_DEFAULT_ALLOW_DEFAULT_ALLOW : \
     (a) == DEFAULT_ALLOW && (b) == DEFAULT_DENY  ? CT_VAL_DEFAULT_ALLOW_DEFAULT_DENY  : \
     (a) == DEFAULT_ALLOW && (b) == POLICIES_APPLIED ? CT_VAL_DEFAULT_ALLOW_POLICIES_APPLIED : \
     (a) == POLICIES_APPLIED && (b) == DEFAULT_ALLOW ? CT_VAL_POLICIES_APPLIED_DEFAULT_ALLOW : \
     (a) == POLICIES_APPLIED && (b) == DEFAULT_DENY  ? CT_VAL_POLICIES_APPLIED_DEFAULT_DENY  : \
     (a) == POLICIES_APPLIED && (b) == POLICIES_APPLIED ? CT_VAL_POLICIES_APPLIED_POLICIES_APPLIED : \
     CT_VAL_POLICIES_APPLIED_POLICIES_APPLIED)

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
  __u8  ip[4];
};

struct lpm_trie_key {
    __u32 prefixlen;
    __u32 ip;
};

struct lpm_trie_val {
	__u32 protocol;
	__u32 start_port;
	__u32 end_port;
};

struct lpm_cp_trie_val {
    __u32 protocol;
    __u32 priority;
    __u32 start_port;
    __u32 end_port;
};

struct conntrack_key {
	__u32 src_ip;
	__u16 src_port;
	__u32 dest_ip;
	__u16 dest_port;
	__u8  protocol;
	__u32 owner_ip;
};

struct conntrack_value {
	__u8 val; // CT value representing pod states
};

struct data_t {
	__u32  src_ip;
	__u32  src_port;
	__u32  dest_ip;
	__u32  dest_port;
	__u32  protocol;
	__u32  verdict;
	__u32 packet_sz;
	__u8 is_egress;
	__u8 tier;
};

struct bpf_map_def_pvt SEC("maps") cp_ingress_map = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size =sizeof(struct lpm_trie_key),
	.value_size = sizeof(struct lpm_cp_trie_val[MAX_PORT_PROTOCOL]),
	.max_entries = 65536,
	.map_flags = BPF_F_NO_PREALLOC,
	.pinning = PIN_GLOBAL_NS,
};

struct bpf_map_def_pvt SEC("maps") ingress_map = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size =sizeof(struct lpm_trie_key),
	.value_size = sizeof(struct lpm_trie_val[MAX_PORT_PROTOCOL]),
	.max_entries = 65536,
	.map_flags = BPF_F_NO_PREALLOC,
	.pinning = PIN_GLOBAL_NS,
};

struct pod_state {
    __u8 state; // 0 => POLICIES_APPLIED, 1 => DEFAULT_ALLOW, 2 => DEFAULT_DENY
};

struct policy_scope {
   __u8 scope;
};

struct bpf_map_def_pvt SEC("maps") ingress_pod_state_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u32), // network policy key 0, cluster policy key 1
    .value_size  = sizeof(struct pod_state),
    .max_entries = 2,
    .map_flags = BPF_F_NO_PREALLOC,
    .pinning     = PIN_GLOBAL_NS,
};

struct bpf_map_def_pvt aws_conntrack_map;
struct bpf_map_def_pvt policy_events;
struct bpf_map_def_pvt policy_events_scope;

static void publishPolicyEvent(struct data_t *evt) {	
	__u32 plsc_key = 0;
	struct policy_scope *plsc = bpf_map_lookup_elem(&policy_events_scope, &plsc_key);
	if (plsc == NULL || plsc->scope >= evt->verdict) {
		bpf_ringbuf_output(&policy_events, evt, sizeof(*evt), 0);
	}
}

static __always_inline int evaluateClusterPolicyByLookUp(struct keystruct trie_key, struct conntrack_key flow_key, __u32 *admin_tier_priority, __u8 *baseline_tier_action) {

	__u32 admin_tier_action = ACTION_PASS;
	*baseline_tier_action = ACTION_PASS;
	*admin_tier_priority = MAX_RULE_PRIORITY;
	__u32 baseline_tier_priority = MAX_RULE_PRIORITY;

	struct lpm_cp_trie_val *trie_val = bpf_map_lookup_elem(&cp_ingress_map, &trie_key);

	if (trie_val == NULL) {
		// No cluster policy rules exist, so we pass by default
		return ACTION_PASS;
	}

	for (int i = 0; i < MAX_PORT_PROTOCOL; i++, trie_val++){

		__u32 priority = trie_val->priority/10;
		__u32 action = trie_val->priority%10;

		if ((trie_val->protocol == ANY_IP_PROTOCOL) || (trie_val->protocol == flow_key.protocol &&
					((trie_val->start_port == ANY_PORT) || (flow_key.dest_port == trie_val->start_port) ||
						(trie_val->end_port > 0 && flow_key.dest_port >= trie_val->start_port && flow_key.dest_port <= trie_val->end_port)))) {
			// Update admin tier
			if (priority < *admin_tier_priority || 
			(priority == *admin_tier_priority && action < admin_tier_action)) {
				*admin_tier_priority = priority;
				admin_tier_action = action;
			}

			// Update baseline tier
			if (priority > ADMIN_TIER_PRIORITY_LIMIT &&
				(priority < baseline_tier_priority ||
				(priority == baseline_tier_priority && action < *baseline_tier_action))) {
				baseline_tier_priority = priority;
				*baseline_tier_action = action;
			}
		}
	}

	return admin_tier_action;
}

static __always_inline int evaluateNamespacePolicyByLookUp(struct keystruct trie_key, struct conntrack_key flow_key	, int pod_state) {
	//Check if it's in the allowed list
	struct lpm_trie_val *trie_val = bpf_map_lookup_elem(&ingress_map, &trie_key);
	if (trie_val == NULL) {
		if (pod_state != POLICIES_APPLIED) {
			// No namespace policy rules exist, so we pass to baseline
			return ACTION_PASS;
		}
		return ACTION_DENY;
	}

	for (int i = 0; i < MAX_PORT_PROTOCOL; i++, trie_val++){
		if (trie_val->protocol == RESERVED_IP_PROTOCOL) {
			return ACTION_DENY;
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
			((trie_val->start_port == ANY_PORT) || (flow_key.dest_port == trie_val->start_port) ||
			(flow_key.dest_port > trie_val->start_port && flow_key.dest_port <= trie_val->end_port))) || 
			(trie_val->protocol == flow_key.protocol &&
			((trie_val->start_port == ANY_PORT) || (flow_key.dest_port == trie_val->start_port) ||
			(flow_key.dest_port > trie_val->start_port && flow_key.dest_port <= trie_val->end_port)))) {

			return ACTION_ALLOW;
		}
	}
	return ACTION_DENY;
}

static __always_inline int evaluateFlow(struct keystruct trie_key, struct conntrack_key flow_key, __u8 pod_state_val, struct data_t *evt, int pod_state) {

		struct conntrack_value flow_val = {};

		__u32 admin_tier_priority;
		__u8 baseline_tier_action;
		
		// 1. Lookup Cluster Network Policy
		//    a. If matched, return the highest priority (lowest numerical value) action from admin tier
		//       and the highest priority action (lowest numerical value > ADMIN_TIER_PRIORITY_LIMIT) from baseline tier
		//    b. If no match or admin tier action is PASS, proceed to check namespace scoped network policy
		// 2. Lookup Namespace Scoped Network Policy
		//    a. If matched, return the action
		//    b. If no match, proceed to evaluate based on baseline tier action from cluster policy
		// 3. If baseline tier action is ALLOW or DENY, enforce that action
		// 4. If baseline tier action is PASS, enforce default pod policy (DEFAULT_ALLOW or DEFAULT_DENY)

		int admin_tier_action = evaluateClusterPolicyByLookUp(trie_key, flow_key, &admin_tier_priority, &baseline_tier_action);

		if (admin_tier_priority <= ADMIN_TIER_PRIORITY_LIMIT) {
			switch (admin_tier_action) {
			case ACTION_DENY: {
				evt->verdict = 0;
				evt->tier = ADMIN_TIER;
				publishPolicyEvent(evt);
				return BPF_DROP;
			}
			case ACTION_ALLOW: {
				flow_val.val = pod_state_val;
				bpf_map_update_elem(&aws_conntrack_map, &flow_key, &flow_val, 0);
				evt->verdict = 1;
				evt->tier = ADMIN_TIER;
				publishPolicyEvent(evt);
				return BPF_OK;
			}
			default:
				break; // ACTION_PASS
			}
		}

		int verdict = evaluateNamespacePolicyByLookUp(trie_key, flow_key, pod_state);
		
		switch (verdict){
		case ACTION_ALLOW:{
			flow_val.val = pod_state_val;
			bpf_map_update_elem(&aws_conntrack_map, &flow_key, &flow_val, 0); // 0 - BPF_ANY
			evt->verdict = 1;
			evt->tier = NETWORK_POLICY_TIER;
			publishPolicyEvent(evt);
			return BPF_OK;
		}
		case ACTION_DENY:{
			evt->verdict = 0;
			evt->tier = NETWORK_POLICY_TIER;
			publishPolicyEvent(evt);
			return BPF_DROP;
		}
		case ACTION_PASS:
			switch (baseline_tier_action) {
			case ACTION_DENY: {
				evt->verdict = 0;
				evt->tier = BASELINE_TIER;
				publishPolicyEvent(evt);
				return BPF_DROP;
			}
			case ACTION_ALLOW: {
				flow_val.val = pod_state_val;
				bpf_map_update_elem(&aws_conntrack_map, &flow_key, &flow_val, 0);
				evt->verdict = 1;
				evt->tier = BASELINE_TIER;
				publishPolicyEvent(evt);
				return BPF_OK;
			}
			case ACTION_PASS:{
				switch (pod_state) {
				case DEFAULT_ALLOW: {
					flow_val.val = pod_state_val;
					bpf_map_update_elem(&aws_conntrack_map, &flow_key, &flow_val, 0);
					evt->verdict = 1;
					evt->tier = DEFAULT_TIER;
					publishPolicyEvent(evt);
					return BPF_OK;
				}
				case DEFAULT_DENY: {
					evt->verdict = 0;
					evt->tier = DEFAULT_TIER;
					publishPolicyEvent(evt);
					return BPF_DROP;
					}
				}
			}
		}
	}
	return BPF_DROP;
}


SEC("tc_cls")
int handle_ingress(struct __sk_buff *skb)
{
	struct keystruct trie_key;
	__u32 l4_src_port = 0;
	__u32 l4_dst_port = 0;
	struct conntrack_key flow_key;
	struct conntrack_value *flow_val;
	struct conntrack_key reverse_flow_key;
	struct conntrack_value *reverse_flow_val;
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	__u8 dest_ip[4];

	__builtin_memset(&flow_key, 0, sizeof(flow_key));
	__builtin_memset(&dest_ip, 0, sizeof(dest_ip));
	__builtin_memset(&reverse_flow_key, 0, sizeof(reverse_flow_key));

	struct ethhdr *ether = data;
	if (data + sizeof(*ether) > data_end) {
		return BPF_OK;
	}

	if (ether->h_proto == 0x08U) {  // htons(ETH_P_IP) -> 0x08U
		data += sizeof(*ether);
		struct iphdr *ip = data;
		struct tcphdr *l4_tcp_hdr = data + sizeof(struct iphdr);
		struct udphdr *l4_udp_hdr = data + sizeof(struct iphdr);
		struct sctphdr *l4_sctp_hdr = data + sizeof(struct iphdr);

		if (data + sizeof(*ip) > data_end) {
			return BPF_OK;
		}
		if (ip->version != 4) {
			return BPF_OK;
		}

		switch (ip->protocol) {
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

		trie_key.prefix_len = 32;
		trie_key.ip[0] = ip->saddr & 0xff;
		trie_key.ip[1] = (ip->saddr >> 8) & 0xff;
		trie_key.ip[2] = (ip->saddr >> 16) & 0xff;
		trie_key.ip[3] = (ip->saddr >> 24) & 0xff;

		dest_ip[0] = ip->daddr & 0xff;
		dest_ip[1] = (ip->daddr >> 8) & 0xff;
		dest_ip[2] = (ip->daddr >> 16) & 0xff;
		dest_ip[3] = (ip->daddr >> 24) & 0xff;

		//Check for the an existing flow in the conntrack table
		flow_key.src_ip = ip->saddr;
		flow_key.src_port = l4_src_port;
		flow_key.dest_ip = ip->daddr;
		flow_key.dest_port = l4_dst_port;
		flow_key.protocol = ip->protocol;
		flow_key.owner_ip = ip->daddr;

		struct data_t evt = {};
		evt.src_ip = flow_key.src_ip;
		evt.src_port = flow_key.src_port;
		evt.dest_ip = flow_key.dest_ip;
		evt.dest_port = flow_key.dest_port;
		evt.protocol = flow_key.protocol;
		evt.packet_sz = skb->len;
		evt.is_egress = 0;

		__u32 NETWORK_POLICY_KEY = 0; 
		__u32 CLUSTER_NETWORK_POLICY_KEY = 1;

		struct pod_state *clusterpolicy_pst = bpf_map_lookup_elem(&ingress_pod_state_map, &CLUSTER_NETWORK_POLICY_KEY);
		struct pod_state *pst = bpf_map_lookup_elem(&ingress_pod_state_map, &NETWORK_POLICY_KEY);

		// There should always be an entry in pod_state_map. pst returned in above line should never be null.
		if ((pst == NULL) || (clusterpolicy_pst == NULL)) {
			evt.verdict = 0;
			evt.tier = ERROR_TIER;
			publishPolicyEvent(&evt);
			return BPF_DROP;
		}

		__u8 ct_pod_state_val = GET_CT_VAL(pst->state, clusterpolicy_pst->state);

		//Check if it's an existing flow
		flow_val = bpf_map_lookup_elem(&aws_conntrack_map, &flow_key);

		if (flow_val != NULL) {
			// If the pod state matches, allow the packet
			if (flow_val->val == ct_pod_state_val) {
				return BPF_OK;
			}

			// Evaluate the flow again if the pod state has changed and take the decision based on it
			if (flow_val->val != ct_pod_state_val) {
				int ret = evaluateFlow(trie_key, flow_key, ct_pod_state_val, &evt, pst->state);
				if (ret == BPF_DROP) {
					bpf_map_delete_elem(&aws_conntrack_map, &flow_key);
					return BPF_DROP;
				}
				return BPF_OK;
			}
		}

		//Check for the reverse flow entry in the conntrack table
		reverse_flow_key.src_ip = ip->daddr;
		reverse_flow_key.src_port = l4_dst_port;
		reverse_flow_key.dest_ip = ip->saddr;
		reverse_flow_key.dest_port = l4_src_port;
		reverse_flow_key.protocol = ip->protocol;
		reverse_flow_key.owner_ip = ip->daddr;

		//Check if it's a response packet
		reverse_flow_val = bpf_map_lookup_elem(&aws_conntrack_map, &reverse_flow_key);

		if (reverse_flow_val != NULL) {
			return BPF_OK;
		}

		// If we reach here, it means it's a new flow or a non-matching response
		return evaluateFlow(trie_key, flow_key, ct_pod_state_val, &evt, pst->state);
	}
	return BPF_OK;
}

char _license[] SEC("license") = "GPL";
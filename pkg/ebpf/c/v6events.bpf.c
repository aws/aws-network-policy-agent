#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct bpf_map_def_pvt {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	__u32 pinning;
	__u32 inner_map_fd;
};

#define PIN_GLOBAL_NS	2

#define BPF_MAP_TYPE_RINGBUF 27

struct data_t {
	__u8   src_ip[16];
	__u32  src_port;
	__u8   dest_ip[16];
	__u32  dest_port;
	__u32  protocol;
	__u32  verdict;
	__u32 packet_sz;
	__u8 is_egress;
	__u8 tier;
};

struct conntrack_key {
	struct	in6_addr saddr;
	__u16 src_port;
	struct	in6_addr daddr;
	__u16 dest_port;
	__u8  protocol;
	struct in6_addr owner_addr;
	__u32 ifindex;
};


struct conntrack_value {
	__u64 val;
	__u64 last_seen;
};

struct bpf_map_def_pvt SEC("maps") aws_conntrack_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size =sizeof(struct conntrack_key),
    .value_size = sizeof(struct conntrack_value),
    .max_entries = 512 * 1024,
    .pinning = PIN_GLOBAL_NS,
};


struct bpf_map_def_pvt SEC("maps") policy_events = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 512 * 1024,
    .pinning = PIN_GLOBAL_NS,
};

// policy_events_drop_count_map: failed bpf_ringbuf_output for DENY events.
// key 0 = ingress, key 1 = egress; per-CPU u64, summed by userspace.
// Created here so it exists at startup; shared with TC programs via PIN_GLOBAL_NS.
struct bpf_map_def_pvt SEC("maps") policy_events_drop_count_map = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 2,
    .pinning = PIN_GLOBAL_NS,
};

char _license[] SEC("license") = "GPL";

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
    __u32  src_ip;
    __u32  src_port;
    __u32  dest_ip;
    __u32  dest_port;
    __u32  protocol;
    __u32  verdict;
    __u32 packet_sz;
    __u8 is_egress;
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
   __u8 val;
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

char _license[] SEC("license") = "GPL";

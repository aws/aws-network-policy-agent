// The maps the TC programs of every pod share. They are in their own binary
// for the reason in tc_shared.h.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "tc_shared.h"

// aws-ebpf-sdk-go's EBPFPinType for a node-wide pin (0 none, 1 object, 2
// global). The agent and every pod's programs must share one copy of each map,
// so the flag it writes and the RSTs ingress records are the ones the programs
// see; the pin also keeps them across agent restarts.
#define PIN_GLOBAL_NS 2

// The map definition layout the agent's loader (aws-ebpf-sdk-go) reads, as in
// the agent's other binaries.
struct bpf_map_def_pvt {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	__u32 pinning;
	__u32 inner_map_fd;
};

struct bpf_map_def_pvt SEC("maps") aws_tc_config = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct tc_config),
	.max_entries = 1,
	.pinning = PIN_GLOBAL_NS,
};

struct bpf_map_def_pvt SEC("maps") aws_tcp_reset_pending = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(struct tcp_reset_pending_key),
	// Only the key's presence matters; a hash map still needs a value.
	.value_size = sizeof(__u8),
	.max_entries = TCP_RESET_PENDING_MAX_ENTRIES,
	.pinning = PIN_GLOBAL_NS,
};

// This binary has no programs, so the kernel never sees a license for it. The
// section is here because aws-ebpf-sdk-go refuses to load an object without
// one ("license missing in elf file").
char _license[] SEC("license") = "GPL";

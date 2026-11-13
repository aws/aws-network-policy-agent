#ifndef __POLICY_EVENTS_H
#define __POLICY_EVENTS_H
// Policy event ring buffer helpers shared by the four TC programs
// (tc.{v4,v6}{ingress,egress}.bpf.c).
//
// Requires the includer to define struct bpf_map_def_pvt before including this
// file. The maps below are only declared here; they are defined (and pinned
// globally) by the events programs (v4events.bpf.c / v6events.bpf.c), so every
// TC program shares one map. Do not define them with SEC("maps") in a TC
// program: that creates a private copy per attached pod.

struct bpf_map_def_pvt policy_events;

// policy_events_drop_count_map: failed bpf_ringbuf_output for DENY events.
// key 0 = ingress, key 1 = egress; per-CPU u64, summed by userspace.
struct bpf_map_def_pvt policy_events_drop_count_map;

#define POLICY_EVENTS_DROP_KEY_INGRESS 0
#define POLICY_EVENTS_DROP_KEY_EGRESS  1

// policy_events_scope_map: --policy-event-logs-scope, written by userspace on
// every agent start. Key 0: 0 = all (ACCEPT and DENY), 1 = deny (DENY only).
// Missing map or entry fails open: ACCEPT events are still emitted.
#define POLICY_EVENT_SCOPE_DENY 1
struct bpf_map_def_pvt policy_events_scope_map;

static __always_inline int policy_scope_allows_accept(void) {
	__u32 key = 0;
	__u32 *scope = bpf_map_lookup_elem(&policy_events_scope_map, &key);
	return !(scope && *scope == POLICY_EVENT_SCOPE_DENY);
}

// Writes a DENY record to the ring buffer; on failure counts the drop per
// direction. A missing map entry fails open (no count). Takes the record as
// void * because the record layout differs between the v4 and v6 programs.
// is_egress is passed by pointer so it is only read on the failure path.
static __always_inline void __emit_deny_event(void *evt, __u32 len, const __u8 *is_egress) {
	if (bpf_ringbuf_output(&policy_events, evt, len, 0) != 0) {
		__u32 key = *is_egress ? POLICY_EVENTS_DROP_KEY_EGRESS : POLICY_EVENTS_DROP_KEY_INGRESS;
		__u64 *cnt = bpf_map_lookup_elem(&policy_events_drop_count_map, &key);
		if (cnt) {
			*cnt += 1; // per-CPU slot: no atomic needed
		}
	}
}

// evt is a pointer to the program's struct data_t.
#define emit_deny_event(evt) __emit_deny_event((evt), sizeof(*(evt)), &(evt)->is_egress)

#endif

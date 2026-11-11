#ifndef __TC_SHARED_H
#define __TC_SHARED_H

// Types of the node-wide maps that tc.shared.bpf.c defines: aws_tc_config.
// They live in one header because the binary that creates the maps and every
// program that uses them must agree on their key and value layouts; a
// mismatch would read garbage rather than fail to load.
//
// They are not in the events binary, which also defines the agent's
// conntrack map: a change to that binary makes the agent recreate the
// conntrack map, which drops the state of every allowed flow on the node.
// Keeping these maps in their own binary lets them change without that.

// aws_tc_config is an array with one entry, at TC_CONFIG_KEY: an array's entry
// always exists, so the lookup never misses.
#define TC_CONFIG_KEY 0

struct tc_config {
	// No TC program reads this field yet, and the agent always writes 0
	// (off), so nothing changes. It is the real field rather than an empty
	// or reserved struct because the kernel rejects an array map with a
	// value_size of 0, and a reserved field would have to be renamed,
	// along with the agent's Go mirror, once a program reads it.
	//
	// __u32 rather than bool: the agent writes this struct from Go
	// (tcConfig in bpf_client.go), and a fixed-size field keeps the two
	// layouts identical.
	__u32 tcp_reset_on_deny;
};

#endif // __TC_SHARED_H

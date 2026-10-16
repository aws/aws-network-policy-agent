package utils

import (
	"errors"
	"strings"

	"golang.org/x/sys/unix"
)

// retryableMapErrnos are errnos a BPF map mutation can return for a reason that
// clears on its own within microseconds, so retrying the identical syscall is
// expected to succeed.
//
// ENOMEM is the kernel >= 6.13 LPM-trie case. Since commit 3d8dc43eb2a3 ("bpf:
// Switch to bpf mem allocator for LPM trie") trie nodes come from the bpf mem
// allocator, whose per-CPU free list is seeded with a SINGLE object when
// unit_size > 256 - every NPA policy trie is 324..432 bytes - and is refilled
// only by an irq_work delivered through a self-IPI. unit_alloc() has no
// direct-allocation fallback, so the allocation that drains the list returns
// -ENOMEM even with tens of GB free. The failing allocation raises the refill on
// its own CPU and the refill lands before the errno reaches userspace, which is
// why an immediate retry works. A saturated trie returns ENOSPC, not ENOMEM, so
// this list cannot spin on a full map.
//
// See amazonlinux/amazon-linux-2023#1129 and aws/aws-network-policy-agent#686.
var retryableMapErrnos = []unix.Errno{unix.ENOMEM, unix.EAGAIN, unix.EINTR}

// knownMapErrnos backs the errno metric label. Their rendered strings are
// distinct, which is what makes the substring fallback in MapErrnoLabel safe.
var knownMapErrnos = []unix.Errno{
	unix.ENOMEM, unix.ENOSPC, unix.E2BIG, unix.EINVAL, unix.EBADF,
	unix.EFAULT, unix.EPERM, unix.EACCES, unix.EEXIST, unix.ENOENT,
	unix.EAGAIN, unix.EINTR,
}

// IsErrno reports whether err is, wraps, or renders errno.
//
// aws-ebpf-sdk-go flattens the syscall errno into the message with %s instead of
// %w on its map-mutation paths (pkg/maps/loader.go CreateUpdateMapEntry,
// DeleteMapEntry, GetMapEntry), so errors.Is alone returns false there. The
// fallback compares against errno.Error() rather than a hardcoded literal, so
// the needle is produced by the same syscall errno table the SDK renders from
// and the two cannot drift.
//
// errors.Is runs first and short-circuits, so this becomes exact with no edit
// here if the SDK switches to %w. Keep call sites narrow - the direct return
// value of a single SDK call - to bound substring false positives.
func IsErrno(err error, errno unix.Errno) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errno) {
		return true
	}
	return strings.Contains(err.Error(), errno.Error())
}

// IsRetryableMapErrno reports whether a failed BPF map mutation is worth
// retrying with the identical arguments.
func IsRetryableMapErrno(err error) bool {
	for _, errno := range retryableMapErrnos {
		if IsErrno(err, errno) {
			return true
		}
	}
	return false
}

// MapErrnoLabel returns a stable, low-cardinality metric label naming the errno
// behind a map-mutation failure, or "unknown".
//
// A non-zero "unknown" series is the tripwire that this classifier has stopped
// recognising the SDK's error text - e.g. after an SDK message change - and that
// the retry above has therefore silently become a no-op. Alert on it.
func MapErrnoLabel(err error) string {
	if err == nil {
		return ""
	}
	var errno unix.Errno
	if errors.As(err, &errno) {
		if name := unix.ErrnoName(errno); name != "" {
			return name
		}
		return "unknown"
	}
	msg := err.Error()
	for _, candidate := range knownMapErrnos {
		if strings.Contains(msg, candidate.Error()) {
			if name := unix.ErrnoName(candidate); name != "" {
				return name
			}
		}
	}
	return "unknown"
}

package utils

import (
	"errors"
	"strings"

	"golang.org/x/sys/unix"
)

// retryableMapErrnos are transient errnos worth retrying. ENOMEM comes from
// the bpf_mem_alloc LPM trie allocator on kernels >= 6.13, whose per-CPU cache
// can be briefly empty (amazonlinux/amazon-linux-2023#1129).
var retryableMapErrnos = []unix.Errno{unix.ENOMEM, unix.EAGAIN, unix.EINTR}

// knownMapErrnos are the errnos MapErrnoLabel can name.
var knownMapErrnos = []unix.Errno{
	unix.ENOMEM, unix.ENOSPC, unix.E2BIG, unix.EINVAL, unix.EBADF,
	unix.EFAULT, unix.EPERM, unix.EACCES, unix.EEXIST, unix.ENOENT,
	unix.EAGAIN, unix.EINTR,
}

// IsErrno reports whether err is, wraps, or contains the text of errno. The
// text match is needed because aws-ebpf-sdk-go formats map errnos with %s.
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

// MapErrnoLabel returns the errno name for a map mutation error, or "unknown".
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

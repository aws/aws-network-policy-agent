package utils

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// sdkWrap reproduces the real error chain from a failed BPF_MAP_UPDATE_ELEM:
// aws-ebpf-sdk-go renders the errno with the given verb, then NPA wraps it with
// %w on the way up and finally joins it. verb is "%s" for the currently pinned
// SDK (which discards the typed errno) and "%w" for a future SDK that preserves
// it; IsErrno must handle both.
func sdkWrap(verb string, errno unix.Errno) error {
	sdk := fmt.Errorf("unable to update map: "+verb, errno)
	hop := fmt.Errorf("ingress map write: %w", sdk)
	return errors.Join(hop)
}

func TestIsErrno(t *testing.T) {
	for _, verb := range []string{"%s", "%w"} {
		t.Run("verb="+verb, func(t *testing.T) {
			err := sdkWrap(verb, unix.ENOMEM)

			assert.True(t, IsErrno(err, unix.ENOMEM),
				"ENOMEM must be detected through the SDK's %s flattening", verb)
			assert.False(t, IsErrno(err, unix.EINVAL))
			assert.False(t, IsErrno(err, unix.ENOSPC))
		})
	}

	assert.False(t, IsErrno(nil, unix.ENOMEM))
	assert.False(t, IsErrno(errors.New("some unrelated failure"), unix.ENOMEM))
}

func TestIsRetryableMapErrno(t *testing.T) {
	retryable := []unix.Errno{unix.ENOMEM, unix.EAGAIN, unix.EINTR}
	permanent := []unix.Errno{unix.ENOSPC, unix.EINVAL, unix.EBADF, unix.EPERM, unix.EFAULT, unix.E2BIG}

	for _, errno := range retryable {
		assert.True(t, IsRetryableMapErrno(sdkWrap("%s", errno)),
			"%s must be retryable", unix.ErrnoName(errno))
	}
	// A full LPM trie returns ENOSPC, and a malformed key EINVAL. Retrying
	// either only burns the BulkRefresh sleep budget under a lock that is on the
	// CNI pod-add path, so they must be classified permanent.
	for _, errno := range permanent {
		assert.False(t, IsRetryableMapErrno(sdkWrap("%s", errno)),
			"%s must not be retryable", unix.ErrnoName(errno))
	}

	assert.False(t, IsRetryableMapErrno(nil))
	assert.False(t, IsRetryableMapErrno(errors.New("some unrelated failure")))
}

func TestMapErrnoLabel(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"enomem flattened", sdkWrap("%s", unix.ENOMEM), "ENOMEM"},
		{"enomem wrapped", sdkWrap("%w", unix.ENOMEM), "ENOMEM"},
		{"enospc", sdkWrap("%s", unix.ENOSPC), "ENOSPC"},
		{"einval", sdkWrap("%s", unix.EINVAL), "EINVAL"},
		{"ebadf", sdkWrap("%s", unix.EBADF), "EBADF"},
		{"enoent", sdkWrap("%s", unix.ENOENT), "ENOENT"},
		// The tripwire: anything this classifier cannot recognise must land in
		// "unknown" rather than be silently attributed to a real errno.
		{"unrecognised", errors.New("some unrelated failure"), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, MapErrnoLabel(tt.err))
		})
	}
}

// TestErrnoTextIsStable pins the string the ENOMEM retry depends on. The SDK
// discards the typed errno, so IsErrno's only fallback is this rendered text; if
// a toolchain change alters the errno table, fail here loudly rather than let the
// retry silently become a no-op in production.
func TestErrnoTextIsStable(t *testing.T) {
	assert.Equal(t, "cannot allocate memory", unix.ENOMEM.Error())
	assert.Equal(t, "ENOMEM", unix.ErrnoName(unix.ENOMEM))
}

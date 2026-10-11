package utils

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// sdkWrap builds the SDK error with verb (%s today, %w if the SDK changes),
// then wraps and joins it as NPA does.
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
		{"unrecognised", errors.New("some unrelated failure"), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, MapErrnoLabel(tt.err))
		})
	}
}

// IsErrno matches on this text, so pin it.
func TestErrnoTextIsStable(t *testing.T) {
	assert.Equal(t, "cannot allocate memory", unix.ENOMEM.Error())
	assert.Equal(t, "ENOMEM", unix.ErrnoName(unix.ENOMEM))
}

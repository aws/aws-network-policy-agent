package events

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"
)

func TestPolicyEventReadFailure(t *testing.T) {
	closedWrapped := fmt.Errorf("ringbuffer: %w", ringbuf.ErrClosed)
	corrupt := fmt.Errorf("read sample data: %w", io.ErrUnexpectedEOF)
	epoll := errors.New("epoll_wait: bad file descriptor")

	retry, msg := policyEventReadFailure(closedWrapped)
	if retry || msg != "" {
		t.Fatalf("ErrClosed: retry=%v msg=%q, want stop with no extra message", retry, msg)
	}

	retry, msg = policyEventReadFailure(corrupt)
	if retry {
		t.Fatal("ErrUnexpectedEOF: got retry, want stop")
	}
	if !strings.Contains(msg, "unexpected EOF") || !strings.Contains(msg, "will not recover") {
		t.Fatalf("ErrUnexpectedEOF message = %q, want a clear statement that the ring will not recover", msg)
	}

	retry, msg = policyEventReadFailure(epoll)
	if !retry || msg != "" {
		t.Fatalf("epoll error: retry=%v msg=%q, want retry", retry, msg)
	}

	plainEOF := fmt.Errorf("read: %w", io.EOF)
	retry, msg = policyEventReadFailure(plainEOF)
	if !retry || msg != "" {
		t.Fatalf("io.EOF: retry=%v msg=%q, want retry (only ErrUnexpectedEOF stops)", retry, msg)
	}
}

func TestPolicyEventReadDelay(t *testing.T) {
	if got := nextPolicyEventReadDelay(0); got != policyEventReadDelayInitial {
		t.Fatalf("delay(0) = %s, want %s", got, policyEventReadDelayInitial)
	}
	if got := nextPolicyEventReadDelay(-time.Second); got != policyEventReadDelayInitial {
		t.Fatalf("delay(negative) = %s, want %s", got, policyEventReadDelayInitial)
	}

	got := policyEventReadDelayInitial
	var steps []time.Duration
	for i := 0; i < 12; i++ {
		steps = append(steps, got)
		got = nextPolicyEventReadDelay(got)
	}
	wantPrefix := []time.Duration{
		50 * time.Millisecond,
		100 * time.Millisecond,
		200 * time.Millisecond,
		400 * time.Millisecond,
		800 * time.Millisecond,
		1600 * time.Millisecond,
		3200 * time.Millisecond,
	}
	for i, want := range wantPrefix {
		if steps[i] != want {
			t.Fatalf("step %d = %s, want %s (steps %v)", i, steps[i], want, steps)
		}
	}
	if steps[7] != policyEventReadDelayMax {
		t.Fatalf("step 7 = %s, want cap %s (steps %v)", steps[7], policyEventReadDelayMax, steps)
	}
	for _, d := range steps[7:] {
		if d != policyEventReadDelayMax {
			t.Fatalf("delay stayed above the cap: %v", steps)
		}
	}
	if next := nextPolicyEventReadDelay(policyEventReadDelayMax); next != policyEventReadDelayMax {
		t.Fatalf("delay(cap) = %s, want %s", next, policyEventReadDelayMax)
	}
}

type scriptPolicyEventReader struct {
	errs []error
	n    int
}

func (r *scriptPolicyEventReader) ReadInto(rec *ringbuf.Record) error {
	if r.n >= len(r.errs) {
		return ringbuf.ErrClosed
	}
	err := r.errs[r.n]
	r.n++
	if err == nil {
		rec.RawSample = nil
	}
	return err
}

func consumeWithSleeps(t *testing.T, errs []error) (n int, sleeps []time.Duration) {
	t.Helper()
	rd := &scriptPolicyEventReader{errs: errs}
	consumePolicyEvents(context.Background(), rd, "node-a", zap.NewNop(), false, false, false, func(d time.Duration) {
		sleeps = append(sleeps, d)
	})
	return rd.n, sleeps
}

func TestPolicyEventReadStopsOnUnexpectedEOF(t *testing.T) {
	corrupt := fmt.Errorf("read record header: %w", io.ErrUnexpectedEOF)
	n, sleeps := consumeWithSleeps(t, []error{corrupt, errors.New("must not be read")})
	if n != 1 {
		t.Fatalf("ReadInto calls = %d, want 1 (unexpected EOF is not retried)", n)
	}
	if len(sleeps) != 0 {
		t.Fatalf("slept %v after unexpected EOF, want no retry", sleeps)
	}
}

func TestPolicyEventReadErrClosedDoesNotSleep(t *testing.T) {
	n, sleeps := consumeWithSleeps(t, []error{ringbuf.ErrClosed, errors.New("must not be read")})
	if n != 1 {
		t.Fatalf("ReadInto calls = %d, want 1", n)
	}
	if len(sleeps) != 0 {
		t.Fatalf("slept %v on ErrClosed, want none", sleeps)
	}
}

func TestPolicyEventReadBackoffResetsAfterRead(t *testing.T) {
	n, sleeps := consumeWithSleeps(t, []error{
		errors.New("epoll_wait: bad file descriptor"),
		errors.New("epoll_wait: invalid argument"),
		nil,
		errors.New("epoll_wait: bad file descriptor"),
		ringbuf.ErrClosed,
	})
	want := []time.Duration{
		policyEventReadDelayInitial,
		policyEventReadDelayInitial * 2,
		policyEventReadDelayInitial,
	}
	if n != 5 {
		t.Fatalf("ReadInto calls = %d, want 5", n)
	}
	if len(sleeps) != len(want) {
		t.Fatalf("sleeps = %v, want %v", sleeps, want)
	}
	for i := range want {
		if sleeps[i] != want[i] {
			t.Fatalf("sleeps = %v, want %v", sleeps, want)
		}
	}
}

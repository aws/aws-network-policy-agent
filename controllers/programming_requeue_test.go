package controllers

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	policyendpoint "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	mock_client "github.com/aws/aws-network-policy-agent/mocks/controller-runtime/client"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	controllerruntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// TestErrProgrammingIncompleteSurvivesWrapping pins the linchpin of the requeue
// design. reconcilePolicyEndpoint wraps the sentinel and the joined per-pod
// errors into one fmt.Errorf with two %w verbs; if errors.Is stopped matching,
// Reconcile would fall through to `return err` and controller-runtime's own
// limiter would escalate to a 1000s inter-retry gap - longer than the outage
// this change exists to fix.
func TestErrProgrammingIncompleteSurvivesWrapping(t *testing.T) {
	inner := errors.Join(
		fmt.Errorf("podIdentifier a: %w", errors.New("update key 01: cannot allocate memory")),
		fmt.Errorf("podIdentifier b: %w", errors.New("update key 02: cannot allocate memory")),
	)
	wrapped := fmt.Errorf("%w for policy endpoint %s/%s: %w", ErrProgrammingIncomplete, "ns", "pe-1", inner)

	assert.True(t, errors.Is(wrapped, ErrProgrammingIncomplete))
	assert.Contains(t, wrapped.Error(), "cannot allocate memory")
	assert.Contains(t, wrapped.Error(), "podIdentifier a")
	assert.Contains(t, wrapped.Error(), "podIdentifier b")

	// An unrelated reconcile error must NOT be mistaken for the sentinel, or a
	// genuine failure would be downgraded to a silent requeue.
	assert.False(t, errors.Is(errors.New("some other reconcile failure"), ErrProgrammingIncomplete))
}

func TestNextRequeueDelay(t *testing.T) {
	var attempts sync.Map
	key := types.NamespacedName{Name: "pe-1", Namespace: "ns"}

	// Jitter is +[0, jitter*d), so each delay lands in [want, want*1.2).
	wantBase := []time.Duration{
		programmingRequeueBase,
		programmingRequeueBase * 2,
		programmingRequeueBase * 4,
		programmingRequeueBase * 8,
	}
	for i, want := range wantBase {
		got := nextRequeueDelay(&attempts, key)
		assert.GreaterOrEqual(t, got, want, "attempt %d", i)
		assert.Less(t, got, time.Duration(float64(want)*(1+programmingRequeueJitter)), "attempt %d", i)
	}

	// Keep climbing; every value must stay under the cap plus its jitter. This is
	// the property that matters: the gap must never approach the ~781s outage
	// reported in aws/aws-network-policy-agent#686.
	maxWithJitter := time.Duration(float64(programmingRequeueCap) * (1 + programmingRequeueJitter))
	for range 40 {
		got := nextRequeueDelay(&attempts, key)
		assert.Less(t, got, maxWithJitter, "delay must stay bounded by the cap")
	}

	// A different endpoint has its own ladder and starts at the base.
	other := types.NamespacedName{Name: "pe-2", Namespace: "ns"}
	got := nextRequeueDelay(&attempts, other)
	assert.GreaterOrEqual(t, got, programmingRequeueBase)
	assert.Less(t, got, time.Duration(float64(programmingRequeueBase)*(1+programmingRequeueJitter)))
}

// peForNode builds a PolicyEndpoint selecting one pod local to nodeIP, which is
// what makes reconcilePolicyEndpoint reach configureeBPFProbes.
func peForNode(name, namespace, nodeIP string) *policyendpoint.PolicyEndpoint {
	return &policyendpoint.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: policyendpoint.PolicyEndpointSpec{
			PolicyRef: policyendpoint.PolicyReference{Name: "np-1", Namespace: namespace},
			PodSelectorEndpoints: []policyendpoint.PodEndpoint{
				{
					Name:      "pod-1",
					Namespace: namespace,
					HostIP:    policyendpoint.NetworkAddress(nodeIP),
					PodIP:     "10.1.1.5",
				},
			},
		},
	}
}

// newRequeueTestReconciler wires a reconciler whose Get returns pe and whose
// List returns just pe, so the full reconcile path runs against the mock agent.
func newRequeueTestReconciler(t *testing.T, pe *policyendpoint.PolicyEndpoint, bpf *ebpf.MockBpfClient) *PolicyEndpointsReconciler {
	t.Helper()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockClient := mock_client.NewMockClient(ctrl)
	mockClient.EXPECT().
		Get(gomock.Any(), gomock.Any(), gomock.AssignableToTypeOf(&policyendpoint.PolicyEndpoint{}), gomock.Any()).
		DoAndReturn(func(_ context.Context, _ types.NamespacedName, out client.Object, _ ...client.GetOption) error {
			pe.DeepCopyInto(out.(*policyendpoint.PolicyEndpoint))
			return nil
		}).AnyTimes()
	mockClient.EXPECT().
		List(gomock.Any(), gomock.AssignableToTypeOf(&policyendpoint.PolicyEndpointList{}), gomock.Any()).
		DoAndReturn(func(_ context.Context, out client.ObjectList, _ ...client.ListOption) error {
			out.(*policyendpoint.PolicyEndpointList).Items = []policyendpoint.PolicyEndpoint{*pe}
			return nil
		}).AnyTimes()

	return &PolicyEndpointsReconciler{
		k8sClient:        mockClient,
		scheme:           runtime.NewScheme(),
		nodeIP:           "192.0.2.10",
		ebpfClient:       bpf,
		trackerStartTime: time.Now(),
	}
}

// The #686 fix: a failed eBPF map write must produce a bounded RequeueAfter and
// a nil error, never a silent success. Before this change reconcilePolicyEndpoint
// returned nil, controller-runtime called Queue.Forget, and nothing on the node
// ever retried.
func TestReconcile_ProgrammingFailureRequeues(t *testing.T) {
	pe := peForNode("pe-1", "ns", "192.0.2.10")
	bpf := &ebpf.MockBpfClient{
		UpdateEbpfMapsErr: fmt.Errorf("ingress map write: %w",
			errors.New("unable to update map: cannot allocate memory")),
	}
	r := newRequeueTestReconciler(t, pe, bpf)
	req := controllerruntime.Request{NamespacedName: types.NamespacedName{Name: "pe-1", Namespace: "ns"}}

	res, err := r.Reconcile(context.Background(), req)

	assert.NoError(t, err, "must not return a raw error: that branch skips Queue.Forget and escalates to a 1000s gap")
	assert.Greater(t, res.RequeueAfter, time.Duration(0), "a failed write must be requeued")
	assert.GreaterOrEqual(t, res.RequeueAfter, programmingRequeueBase)
	assert.Less(t, res.RequeueAfter,
		time.Duration(float64(programmingRequeueCap)*(1+programmingRequeueJitter)))

	// The ladder advances across consecutive failures.
	res2, err := r.Reconcile(context.Background(), req)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, res2.RequeueAfter, programmingRequeueBase*2)
}

// Once programming succeeds the ladder must reset, so a later unrelated failure
// starts back at the base delay instead of inheriting a long backoff.
func TestReconcile_SuccessClearsTheLadder(t *testing.T) {
	pe := peForNode("pe-1", "ns", "192.0.2.10")
	bpf := &ebpf.MockBpfClient{UpdateEbpfMapsErr: errors.New("cannot allocate memory")}
	r := newRequeueTestReconciler(t, pe, bpf)
	req := controllerruntime.Request{NamespacedName: types.NamespacedName{Name: "pe-1", Namespace: "ns"}}

	for range 3 {
		_, err := r.Reconcile(context.Background(), req)
		assert.NoError(t, err)
	}
	_, ok := r.programmingAttempts.Load(req.NamespacedName)
	assert.True(t, ok, "failures must be tracked")

	bpf.UpdateEbpfMapsErr = nil
	res, err := r.Reconcile(context.Background(), req)
	assert.NoError(t, err)
	assert.Zero(t, res.RequeueAfter, "a successful reconcile must not requeue")

	_, ok = r.programmingAttempts.Load(req.NamespacedName)
	assert.False(t, ok, "success must clear the attempt counter")
}

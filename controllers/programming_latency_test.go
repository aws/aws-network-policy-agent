package controllers

import (
	"context"
	"testing"
	"time"

	policyendpoint "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	mock_client "github.com/aws/aws-network-policy-agent/mocks/controller-runtime/client"
	"github.com/golang/mock/gomock"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	controllerruntime "sigs.k8s.io/controller-runtime"
)

// histSampleCount reads the cumulative sample count of a package-level
// histogram. Tests assert on before/after deltas so they stay independent of
// execution order and -count=N reruns; do not add t.Parallel() to tests that
// share these histograms.
func histSampleCount(t *testing.T, h prometheus.Histogram) uint64 {
	t.Helper()
	m := &dto.Metric{}
	assert.NoError(t, h.Write(m))
	return m.GetHistogram().GetSampleCount()
}

func newPEWithTriggerTime(name, namespace, triggerTime string) *policyendpoint.PolicyEndpoint {
	pe := &policyendpoint.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}
	if triggerTime != "" {
		pe.Annotations = map[string]string{LastChangeTriggerTimeAnnotation: triggerTime}
	}
	return pe
}

func TestObservePolicyProgrammingLatency(t *testing.T) {
	now := time.Now()
	fresh := now.Add(-2 * time.Second).UTC().Format(time.RFC3339Nano)
	fresher := now.Add(-1 * time.Second).UTC().Format(time.RFC3339Nano)
	beforeStart := now.Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano)
	future := now.Add(1 * time.Hour).UTC().Format(time.RFC3339Nano)

	type observeCall struct {
		pe                   *policyendpoint.PolicyEndpoint
		programmingSucceeded bool
	}
	obs := func(pe *policyendpoint.PolicyEndpoint) observeCall {
		return observeCall{pe: pe, programmingSucceeded: true}
	}

	tests := []struct {
		name     string
		calls    []observeCall
		observed uint64 // expected number of new observations
	}{
		{
			name:     "no annotations",
			calls:    []observeCall{obs(newPEWithTriggerTime("pe-1", "ns", ""))},
			observed: 0,
		},
		{
			name:     "unparseable annotation",
			calls:    []observeCall{obs(newPEWithTriggerTime("pe-1", "ns", "not-a-timestamp"))},
			observed: 0,
		},
		{
			name:     "annotation predates agent start (restart guard)",
			calls:    []observeCall{obs(newPEWithTriggerTime("pe-1", "ns", beforeStart))},
			observed: 0,
		},
		{
			name:     "fresh annotation observed once",
			calls:    []observeCall{obs(newPEWithTriggerTime("pe-1", "ns", fresh))},
			observed: 1,
		},
		{
			name: "repeat reconcile with unchanged annotation is skipped (issue #644)",
			calls: []observeCall{
				obs(newPEWithTriggerTime("pe-1", "ns", fresh)),
				obs(newPEWithTriggerTime("pe-1", "ns", fresh)),
				obs(newPEWithTriggerTime("pe-1", "ns", fresh)),
			},
			observed: 1,
		},
		{
			name: "changed annotation observed again",
			calls: []observeCall{
				obs(newPEWithTriggerTime("pe-1", "ns", fresh)),
				obs(newPEWithTriggerTime("pe-1", "ns", fresh)),
				obs(newPEWithTriggerTime("pe-1", "ns", fresher)),
			},
			observed: 2,
		},
		{
			name: "same annotation on different PEs observed per PE",
			calls: []observeCall{
				obs(newPEWithTriggerTime("pe-1", "ns", fresh)),
				obs(newPEWithTriggerTime("pe-2", "ns", fresh)),
			},
			observed: 2,
		},
		{
			name: "negative latency (clock skew) skipped but consumed",
			calls: []observeCall{
				obs(newPEWithTriggerTime("pe-1", "ns", future)),
				obs(newPEWithTriggerTime("pe-1", "ns", future)),
			},
			observed: 0,
		},
		{
			name: "programming failure suppresses observation AND consumes trigger time",
			// a later resync of the same annotation must not emit an inflated value
			calls: []observeCall{
				{pe: newPEWithTriggerTime("pe-1", "ns", fresh), programmingSucceeded: false},
				{pe: newPEWithTriggerTime("pe-1", "ns", fresh), programmingSucceeded: true},
			},
			observed: 0,
		},
		{
			name: "new annotation after programming failure is observed",
			calls: []observeCall{
				{pe: newPEWithTriggerTime("pe-1", "ns", fresh), programmingSucceeded: false},
				{pe: newPEWithTriggerTime("pe-1", "ns", fresher), programmingSucceeded: true},
			},
			observed: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &PolicyEndpointsReconciler{
				trackerStartTime: now.Add(-1 * time.Hour),
			}
			before := histSampleCount(t, policyProgrammingLatency)
			for _, c := range tt.calls {
				r.observePolicyProgrammingLatency(c.pe, c.programmingSucceeded)
			}
			assert.Equal(t, tt.observed, histSampleCount(t, policyProgrammingLatency)-before)
		})
	}
}

func TestObservePolicyProgrammingLatency_CleanupResetsTracking(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockClient := mock_client.NewMockClient(mockCtrl)
	mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyendpoint.PolicyEndpointList{}), gomock.Any()).Return(nil).AnyTimes()

	now := time.Now()
	fresh := now.Add(-2 * time.Second).UTC().Format(time.RFC3339Nano)
	r := &PolicyEndpointsReconciler{k8sClient: mockClient, trackerStartTime: now.Add(-1 * time.Hour)}
	pe := newPEWithTriggerTime("pe-1", "ns", fresh)

	before := histSampleCount(t, policyProgrammingLatency)
	r.observePolicyProgrammingLatency(pe, true)
	r.observePolicyProgrammingLatency(pe, true) // duplicate, skipped
	assert.Equal(t, uint64(1), histSampleCount(t, policyProgrammingLatency)-before)

	// the real cleanup path must delete the tracking entry
	err := r.cleanUpPolicyEndpoint(context.TODO(), controllerruntime.Request{
		NamespacedName: types.NamespacedName{Name: "pe-1", Namespace: "ns"},
	})
	assert.NoError(t, err)

	// a recreated PE with a fresh annotation is observed again
	r.observePolicyProgrammingLatency(pe, true)
	assert.Equal(t, uint64(2), histSampleCount(t, policyProgrammingLatency)-before)
}

func TestObserveClusterPolicyProgrammingLatency(t *testing.T) {
	now := time.Now()
	fresh := now.Add(-2 * time.Second).UTC().Format(time.RFC3339Nano)
	fresher := now.Add(-1 * time.Second).UTC().Format(time.RFC3339Nano)
	freshest := now.Add(-500 * time.Millisecond).UTC().Format(time.RFC3339Nano)

	r := &ClusterPolicyEndpointsReconciler{trackerStartTime: now.Add(-1 * time.Hour)}
	cpe := &policyendpoint.ClusterPolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "cpe-1",
			Annotations: map[string]string{LastChangeTriggerTimeAnnotation: fresh},
		},
	}

	before := histSampleCount(t, clusterPolicyProgrammingLatency)
	r.observeClusterPolicyProgrammingLatency(cpe, true)
	r.observeClusterPolicyProgrammingLatency(cpe, true) // duplicate, skipped
	assert.Equal(t, uint64(1), histSampleCount(t, clusterPolicyProgrammingLatency)-before)

	cpe.Annotations[LastChangeTriggerTimeAnnotation] = fresher
	r.observeClusterPolicyProgrammingLatency(cpe, false) // programming failed: consumed, not observed
	r.observeClusterPolicyProgrammingLatency(cpe, true)  // same annotation: stays consumed
	assert.Equal(t, uint64(1), histSampleCount(t, clusterPolicyProgrammingLatency)-before)

	cpe.Annotations[LastChangeTriggerTimeAnnotation] = freshest
	r.observeClusterPolicyProgrammingLatency(cpe, true) // changed annotation, observed
	assert.Equal(t, uint64(2), histSampleCount(t, clusterPolicyProgrammingLatency)-before)
}

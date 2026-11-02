package controllers

import (
	"context"
	"testing"
	"time"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	selTestNamespace     = "app-ns"
	selTestPodIdentifier = "probe@app-ns"
	selTestDenyPE        = "default-deny-abcde"
	selTestDNSPE         = "dns-fghij"
)

func selTestPod(name string, podLabels map[string]string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: selTestNamespace, Labels: podLabels}}
}

// selTestDenyPolicyEndpoint mirrors the PE generated for
// `podSelector: {}, policyTypes: [Egress]` with no egress rules.
func selTestDenyPolicyEndpoint() *policyk8sawsv1.PolicyEndpoint {
	return &policyk8sawsv1.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: selTestDenyPE, Namespace: selTestNamespace},
		Spec: policyk8sawsv1.PolicyEndpointSpec{
			PodSelector:  &metav1.LabelSelector{},
			PolicyRef:    policyk8sawsv1.PolicyReference{Name: "default-deny", Namespace: selTestNamespace},
			PodIsolation: []networking.PolicyType{networking.PolicyTypeEgress},
		},
	}
}

// selTestDNSPolicyEndpoint mirrors the PE generated for an egress allow to
// kube-dns on UDP 53, selecting pods with the given selector.
func selTestDNSPolicyEndpoint(selector *metav1.LabelSelector) *policyk8sawsv1.PolicyEndpoint {
	udp := corev1.ProtocolUDP
	port := int32(53)
	return &policyk8sawsv1.PolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{Name: selTestDNSPE, Namespace: selTestNamespace},
		Spec: policyk8sawsv1.PolicyEndpointSpec{
			PodSelector:  selector,
			PolicyRef:    policyk8sawsv1.PolicyReference{Name: "dns", Namespace: selTestNamespace},
			PodIsolation: []networking.PolicyType{networking.PolicyTypeEgress},
			Egress: []policyk8sawsv1.EndpointInfo{
				{CIDR: "10.100.0.10", Ports: []policyk8sawsv1.Port{{Protocol: &udp, Port: &port}}},
			},
		},
	}
}

// newSelTestReconciler builds a reconciler whose recorded identifier->PE list
// holds only recorded, reproducing the partial state behind.
func newSelTestReconciler(t *testing.T, enableMatching bool, recorded []string, objs ...client.Object) *PolicyEndpointsReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, policyk8sawsv1.AddToScheme(scheme))
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()

	r := NewPolicyEndpointsReconciler(k8sClient, "10.0.0.1", &ebpf.MockBpfClient{}, false)
	if enableMatching {
		r.EnablePodSelectorMatching(nil)
	}
	if recorded != nil {
		r.podIdentifierToPolicyEndpointMap.Store(selTestPodIdentifier, recorded)
	}
	return r
}

// Only the default-deny PE is recorded for the identifier.
// Selector matching must add the DNS PE so egress is allowed to DNS rather
// than isolated with no rules.
func TestDeriveRules_PartialRecordedList_SelectorMatchingAddsMissingPE(t *testing.T) {
	r := newSelTestReconciler(t, true, []string{selTestDenyPE},
		selTestPod("probe-1", map[string]string{"app": "probe"}),
		selTestDenyPolicyEndpoint(),
		selTestDNSPolicyEndpoint(&metav1.LabelSelector{}),
	)

	_, egress, _, egressIsolated, err := r.deriveIngressAndEgressFirewallRules(context.Background(),
		selTestPodIdentifier, selTestNamespace, "", false)

	require.NoError(t, err)
	require.Len(t, egress, 1)
	assert.Equal(t, "10.100.0.10", string(egress[0].IPCidr))
	assert.False(t, egressIsolated, "egress must not be isolated with no rules")
}

// With matching disabled the result is exactly today's: deny-only.
func TestDeriveRules_PartialRecordedList_MatchingDisabled_Unchanged(t *testing.T) {
	r := newSelTestReconciler(t, false, []string{selTestDenyPE},
		selTestPod("probe-1", map[string]string{"app": "probe"}),
		selTestDenyPolicyEndpoint(),
		selTestDNSPolicyEndpoint(&metav1.LabelSelector{}),
	)

	_, egress, _, egressIsolated, err := r.deriveIngressAndEgressFirewallRules(context.Background(),
		selTestPodIdentifier, selTestNamespace, "", false)

	require.NoError(t, err)
	assert.Empty(t, egress)
	assert.True(t, egressIsolated)
}

// A PE whose podSelector doesn't match the identifier's pods is not added.
func TestDeriveRules_SelectorDoesNotMatch_PENotAdded(t *testing.T) {
	r := newSelTestReconciler(t, true, []string{selTestDenyPE},
		selTestPod("probe-1", map[string]string{"app": "probe"}),
		selTestDenyPolicyEndpoint(),
		selTestDNSPolicyEndpoint(&metav1.LabelSelector{MatchLabels: map[string]string{"app": "other"}}),
	)

	_, egress, _, egressIsolated, err := r.deriveIngressAndEgressFirewallRules(context.Background(),
		selTestPodIdentifier, selTestNamespace, "", false)

	require.NoError(t, err)
	assert.Empty(t, egress)
	assert.True(t, egressIsolated)
}

// In the delete flow the deleted NP's PEs stay excluded even if they match.
func TestDeriveRules_DeleteFlow_DeletedNPStaysExcluded(t *testing.T) {
	r := newSelTestReconciler(t, true, []string{selTestDenyPE},
		selTestPod("probe-1", map[string]string{"app": "probe"}),
		selTestDenyPolicyEndpoint(),
		selTestDNSPolicyEndpoint(&metav1.LabelSelector{}),
	)

	_, egress, _, egressIsolated, err := r.deriveIngressAndEgressFirewallRules(context.Background(),
		selTestPodIdentifier, selTestNamespace, selTestDNSPE, true)

	require.NoError(t, err)
	assert.Empty(t, egress)
	assert.True(t, egressIsolated)
}

// A PE that is being deleted is not re-applied by selector matching.
func TestDeriveRules_TerminatingPE_NotAdded(t *testing.T) {
	dns := selTestDNSPolicyEndpoint(&metav1.LabelSelector{})
	now := metav1.NewTime(time.Now())
	dns.DeletionTimestamp = &now
	dns.Finalizers = []string{"test.k8s.aws/hold"}
	r := newSelTestReconciler(t, true, []string{selTestDenyPE},
		selTestPod("probe-1", map[string]string{"app": "probe"}),
		selTestDenyPolicyEndpoint(),
		dns,
	)

	_, egress, _, egressIsolated, err := r.deriveIngressAndEgressFirewallRules(context.Background(),
		selTestPodIdentifier, selTestNamespace, "", false)

	require.NoError(t, err)
	assert.Empty(t, egress)
	assert.True(t, egressIsolated)
}

// Pods of other identifiers don't pull PEs into this identifier's set.
func TestDeriveRules_NoLocalPodOfIdentifier_RecordedListOnly(t *testing.T) {
	r := newSelTestReconciler(t, true, []string{selTestDenyPE},
		selTestPod("other-1", map[string]string{"app": "probe"}),
		selTestDenyPolicyEndpoint(),
		selTestDNSPolicyEndpoint(&metav1.LabelSelector{}),
	)

	_, egress, _, egressIsolated, err := r.deriveIngressAndEgressFirewallRules(context.Background(),
		selTestPodIdentifier, selTestNamespace, "", false)

	require.NoError(t, err)
	assert.Empty(t, egress)
	assert.True(t, egressIsolated)
}

// Pods sharing an identifier can carry different labels; a PE matching any
// of them applies to the identifier's shared maps.
func TestDeriveRules_AnyLocalPodOfIdentifierMatches(t *testing.T) {
	r := newSelTestReconciler(t, true, []string{selTestDenyPE},
		selTestPod("probe-1", map[string]string{"app": "probe"}),
		selTestPod("probe-2", map[string]string{"app": "probe", "tier": "dns-client"}),
		selTestDenyPolicyEndpoint(),
		selTestDNSPolicyEndpoint(&metav1.LabelSelector{MatchLabels: map[string]string{"tier": "dns-client"}}),
	)

	_, egress, _, _, err := r.deriveIngressAndEgressFirewallRules(context.Background(),
		selTestPodIdentifier, selTestNamespace, "", false)

	require.NoError(t, err)
	assert.Len(t, egress, 1)
}

// The recorded list is shared state; deriving rules must not modify it.
func TestPolicyEndpointsForPodIdentifier_DoesNotMutateRecordedList(t *testing.T) {
	recorded := make([]string, 1, 4) // spare capacity would expose an aliasing append
	recorded[0] = selTestDenyPE
	r := newSelTestReconciler(t, true, recorded,
		selTestPod("probe-1", map[string]string{"app": "probe"}),
		selTestDenyPolicyEndpoint(),
		selTestDNSPolicyEndpoint(&metav1.LabelSelector{}),
	)

	got := r.policyEndpointsForPodIdentifier(context.Background(), selTestPodIdentifier, selTestNamespace, nil)

	assert.ElementsMatch(t, []string{selTestDenyPE, selTestDNSPE}, got)
	stored, ok := r.podIdentifierToPolicyEndpointMap.Load(selTestPodIdentifier)
	require.True(t, ok)
	assert.Equal(t, []string{selTestDenyPE}, stored.([]string))
	assert.Equal(t, []string{selTestDenyPE, ""}, recorded[:2], "backing array must not be written")
}

// selTestPodReader stands in for the uncached API reader and records Gets.
type selTestPodReader struct {
	client.Reader
	pods map[types.NamespacedName]*corev1.Pod
	gets int
}

func (s *selTestPodReader) Get(_ context.Context, key client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
	s.gets++
	pod, ok := s.pods[key]
	if !ok {
		return apierrors.NewNotFound(corev1.Resource("pods"), key.Name)
	}
	pod.DeepCopyInto(obj.(*corev1.Pod))
	return nil
}

var selTestNewPod = types.NamespacedName{Name: "probe-9", Namespace: selTestNamespace}

// The CNI sets up a pod the pod cache has not received yet: its labels are
// read from the API server, so the DNS PE is still included.
func TestDeriveRulesForNewPod_NotInCache_ReadsLabelsFromAPI(t *testing.T) {
	r := newSelTestReconciler(t, false, []string{selTestDenyPE},
		selTestDenyPolicyEndpoint(),
		selTestDNSPolicyEndpoint(&metav1.LabelSelector{MatchLabels: map[string]string{"app": "probe"}}),
	)
	reader := &selTestPodReader{pods: map[types.NamespacedName]*corev1.Pod{
		selTestNewPod: selTestPod(selTestNewPod.Name, map[string]string{"app": "probe"}),
	}}
	r.EnablePodSelectorMatching(reader)

	_, egress, err := r.DeriveFireWallRulesForNewPod(selTestPodIdentifier, selTestNewPod)

	require.NoError(t, err)
	require.Len(t, egress, 1)
	assert.Equal(t, "10.100.0.10", string(egress[0].IPCidr))
	assert.Equal(t, 1, reader.gets)
}

// The pod is already in the cache: no API read.
func TestDeriveRulesForNewPod_InCache_NoAPIRead(t *testing.T) {
	r := newSelTestReconciler(t, false, []string{selTestDenyPE},
		selTestPod(selTestNewPod.Name, map[string]string{"app": "probe"}),
		selTestDenyPolicyEndpoint(),
		selTestDNSPolicyEndpoint(&metav1.LabelSelector{}),
	)
	reader := &selTestPodReader{}
	r.EnablePodSelectorMatching(reader)

	_, egress, err := r.DeriveFireWallRulesForNewPod(selTestPodIdentifier, selTestNewPod)

	require.NoError(t, err)
	assert.Len(t, egress, 1)
	assert.Equal(t, 0, reader.gets)
}

// The API read fails too: fall back to the recorded list, exactly as without
// selector matching (deny-only here, so the egress rules are empty).
func TestDeriveRulesForNewPod_APIReadFails_FallsBackToRecordedList(t *testing.T) {
	r := newSelTestReconciler(t, false, []string{selTestDenyPE},
		selTestDenyPolicyEndpoint(),
		selTestDNSPolicyEndpoint(&metav1.LabelSelector{}),
	)
	reader := &selTestPodReader{}
	r.EnablePodSelectorMatching(reader)

	ingress, egress, err := r.DeriveFireWallRulesForNewPod(selTestPodIdentifier, selTestNewPod)

	require.NoError(t, err)
	assert.Empty(t, egress)
	assert.Len(t, ingress, 1, "ingress gets the existing catch-all entry")
	assert.Equal(t, 1, reader.gets)
}

// Only the CNI path reads from the API server. Reconcile and cleanup derive
// rules for identifiers whose pods may already be gone, and must not.
func TestDeriveRulesPerPodIdentifier_NoLocalPods_NoAPIRead(t *testing.T) {
	r := newSelTestReconciler(t, false, []string{selTestDenyPE},
		selTestDenyPolicyEndpoint(),
		selTestDNSPolicyEndpoint(&metav1.LabelSelector{}),
	)
	reader := &selTestPodReader{}
	r.EnablePodSelectorMatching(reader)

	_, _, err := r.DeriveFireWallRulesPerPodIdentifier(selTestPodIdentifier, selTestNamespace)
	require.NoError(t, err)
	_, _, _, _, err = r.deriveIngressAndEgressFirewallRules(context.Background(), selTestPodIdentifier, selTestNamespace, "", false)
	require.NoError(t, err)

	assert.Equal(t, 0, reader.gets)
}

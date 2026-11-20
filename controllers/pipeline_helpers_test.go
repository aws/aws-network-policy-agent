package controllers

import (
	"context"
	"errors"
	"maps"
	"os"
	"slices"
	"sync"
	"testing"

	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/priorityqueue"
)

func TestMain(m *testing.M) {
	// Initialize the package logger before tests run passes concurrently, as main does;
	// its lazy initialization is not safe for concurrent first use.
	logger.Get()
	os.Exit(m.Run())
}

// drainProgramming runs one programming pass for every identifier ready in queue, as the
// programming workers would, and returns the passes' failures. A failed identifier is queued
// again, so the next drain retries it.
func drainProgramming(ctx context.Context, queue priorityqueue.PriorityQueue[string], program func(context.Context, string) error) error {
	var errs error
	var failed []string
	for queue.Len() > 0 {
		podIdentifier, _ := queue.Get()
		if err := program(ctx, podIdentifier); err != nil {
			errs = errors.Join(errs, err)
			failed = append(failed, podIdentifier)
		}
		queue.Done(podIdentifier)
	}
	for _, podIdentifier := range failed {
		queue.Add(podIdentifier)
	}
	return errs
}

// reconcileAndProgram runs stage 1 for req, then drains stage 2, returning both stages' errors.
func (r *PolicyEndpointsReconciler) reconcileAndProgram(ctx context.Context, req EndpointRequest) error {
	return errors.Join(r.reconcile(ctx, req), r.drainProgramming(ctx))
}

func (r *PolicyEndpointsReconciler) drainProgramming(ctx context.Context) error {
	return drainProgramming(ctx, r.programQueue, r.programIdentifier)
}

// reconcileAndProgram runs stage 1 for req, then drains stage 2, returning both stages' errors.
func (r *ClusterPolicyEndpointsReconciler) reconcileAndProgram(ctx context.Context, req EndpointRequest) error {
	return errors.Join(r.reconcile(ctx, req), r.drainProgramming(ctx))
}

func (r *ClusterPolicyEndpointsReconciler) drainProgramming(ctx context.Context) error {
	return drainProgramming(ctx, r.programQueue, r.programIdentifier)
}

// localIdentifiers returns the identifiers parent selects on this node, as its last reconcile recorded.
func (r *PolicyEndpointsReconciler) localIdentifiers(namespace, parent string) []string {
	return localIdentifiersIn(&r.networkPolicyToLocalPodsMap, utils.GetNetworkPolicyIdentifier(parent, namespace))
}

// localPods returns parent's recorded pods on this node across every identifier.
func (r *PolicyEndpointsReconciler) localPods(namespace, parent string) []npatypes.Pod {
	return localPodsIn(&r.networkPolicyToLocalPodsMap, utils.GetNetworkPolicyIdentifier(parent, namespace))
}

// identifierFirewallRules derives podIdentifier's rules as a programming pass does.
func (r *PolicyEndpointsReconciler) identifierFirewallRules(ctx context.Context, podIdentifier string) ([]fwrp.EbpfFirewallRules,
	[]fwrp.EbpfFirewallRules, bool, bool, error) {
	namespace, _ := utils.GetPodNamespaceFromPodIdentifier(podIdentifier)
	return r.identifierFirewallRulesIn(ctx, podIdentifier, namespace)
}

// identifierFirewallRulesIn derives podIdentifier's rules from the PolicyEndpoints in namespace.
func (r *PolicyEndpointsReconciler) identifierFirewallRulesIn(ctx context.Context, podIdentifier, namespace string) ([]fwrp.EbpfFirewallRules,
	[]fwrp.EbpfFirewallRules, bool, bool, error) {
	policyEndpoints, err := r.policyEndpointsOf(ctx, namespace, podIdentifier, r.policyEndpointRefs(podIdentifier))
	if err != nil {
		return nil, nil, false, false, err
	}
	ingress, egress, isIngressIsolated, isEgressIsolated := r.deriveFirewallRules(policyEndpoints)
	return ingress, egress, isIngressIsolated, isEgressIsolated, nil
}

// localIdentifiers returns the identifiers parent selects on this node, as its last reconcile recorded.
func (r *ClusterPolicyEndpointsReconciler) localIdentifiers(parent string) []string {
	return localIdentifiersIn(&r.clusterNetworkPolicyToLocalPodsMap, parent)
}

// localPods returns parent's recorded pods on this node across every identifier.
func (r *ClusterPolicyEndpointsReconciler) localPods(parent string) []npatypes.Pod {
	return localPodsIn(&r.clusterNetworkPolicyToLocalPodsMap, parent)
}

func localIdentifiersIn(policyToLocalPods *sync.Map, policyKey string) []string {
	v, ok := policyToLocalPods.Load(policyKey)
	if !ok {
		return nil
	}
	return slices.Sorted(maps.Keys(v.(map[string][]npatypes.Pod)))
}

func localPodsIn(policyToLocalPods *sync.Map, policyKey string) []npatypes.Pod {
	var pods []npatypes.Pod
	for _, podIdentifier := range localIdentifiersIn(policyToLocalPods, policyKey) {
		v, _ := policyToLocalPods.Load(policyKey)
		pods = append(pods, v.(map[string][]npatypes.Pod)[podIdentifier]...)
	}
	return pods
}

// synchronousPipeline runs both stages on the calling worker, so a test that waits on a stage-1
// reconcile also sees the programming it queued.
type synchronousPipeline struct {
	reconcileAndProgram func(context.Context, EndpointRequest) error
}

func (p synchronousPipeline) Reconcile(ctx context.Context, req EndpointRequest) (ctrl.Result, error) {
	return ctrl.Result{}, p.reconcileAndProgram(ctx, req)
}

// seedPolicyLocalPods records pods as parent's selected pods on this node from an earlier
// reconcile, with their identifiers attached, as that reconcile's programming would leave them.
// An identifier the test detached stays detached.
func seedPolicyLocalPods(r *PolicyEndpointsReconciler, bpf *ebpf.MockBpfClient, namespace, parent string, pods []npatypes.Pod) {
	r.networkPolicyToLocalPodsMap.Store(utils.GetNetworkPolicyIdentifier(parent, namespace), byIdentifier(bpf, pods))
}

// seedClusterPolicyLocalPods is seedPolicyLocalPods for a ClusterNetworkPolicy.
func seedClusterPolicyLocalPods(r *ClusterPolicyEndpointsReconciler, bpf *ebpf.MockBpfClient, parent string, pods []npatypes.Pod) {
	r.clusterNetworkPolicyToLocalPodsMap.Store(parent, byIdentifier(bpf, pods))
}

func byIdentifier(bpf *ebpf.MockBpfClient, pods []npatypes.Pod) map[string][]npatypes.Pod {
	localPods := map[string][]npatypes.Pod{}
	for _, pod := range pods {
		podIdentifier := utils.GetPodIdentifier(pod.Name, pod.Namespace)
		localPods[podIdentifier] = append(localPods[podIdentifier], pod)
		if !bpf.PodIdentifiersWithoutBPFContext[podIdentifier] {
			bpf.AttachIdentifier(podIdentifier)
		}
	}
	return localPods
}

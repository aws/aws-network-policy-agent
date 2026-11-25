package controllers

import (
	"context"
	"slices"
	"testing"
	"time"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/config"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

// TestPipeline_Envtest runs both stages as the agent wires them, SetupWithManager included, so
// the programming controller's pre-built queue, its workers and its lack of watches are
// exercised against a real API server rather than the tests' synchronous drain.
func TestPipeline_Envtest(t *testing.T) {
	cfg, direct, scheme := startAPIServer(t)
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:     scheme,
		Metrics:    metricsserver.Options{BindAddress: "0"},
		Controller: config.Controller{SkipNameValidation: ptr.To(true)},
	})
	require.NoError(t, err)
	bpf := &ebpf.MockBpfClient{}
	pe := NewPolicyEndpointsReconciler(mgr.GetClient(), fixtureNodeIP, bpf, false)
	cpe := NewClusterPolicyEndpointsReconciler(mgr.GetClient(), fixtureNodeIP, bpf)
	require.NoError(t, pe.SetupWithManager(context.Background(), mgr))
	require.NoError(t, cpe.SetupWithManager(context.Background(), mgr))

	// Queued before the manager starts: the programming queue exists from construction, so
	// adding to it must neither block nor lose the identifier.
	early := utils.GetPodIdentifier("early-aaa", envtestNamespace)
	bpf.AttachIdentifier(early)
	pe.programQueue.Add(early)
	cpe.programQueue.Add(early)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = mgr.Start(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	// Each programming controller runs one worker. This checks only the count; what one worker
	// does during a rollout is TestProgramIdentifier_RolloutIntervalIsWrittenOnlyByAPassInsideIt.
	workers := func(controller string) float64 {
		families, err := crmetrics.Registry.Gather()
		require.NoError(t, err)
		for _, f := range families {
			if f.GetName() != "controller_runtime_max_concurrent_reconciles" {
				continue
			}
			for _, m := range f.GetMetric() {
				for _, l := range m.GetLabel() {
					if l.GetName() == "controller" && l.GetValue() == controller {
						return m.GetGauge().GetValue()
					}
				}
			}
		}
		return 0
	}
	require.Eventually(t, func() bool {
		return workers(policyEndpointProgrammerName) != 0 && workers(clusterPolicyEndpointProgrammerName) != 0
	}, 30*time.Second, 100*time.Millisecond, "the programming controllers start")
	require.Equal(t, 1.0, workers(policyEndpointProgrammerName))
	require.Equal(t, 1.0, workers(clusterPolicyEndpointProgrammerName))

	web := utils.GetPodIdentifier("web-aaa", envtestNamespace)
	ingressCIDRs := func(id string) []string {
		ingress, _, _, _, _ := bpf.Snapshot(id)
		cidrs := cidrsOf(ingress)
		slices.Sort(cidrs)
		return cidrs
	}
	clusterRules := func(id string) []string {
		_, _, clusterIngress, _, _ := bpf.Snapshot(id)
		return actionCIDRsOf(clusterIngress)
	}
	podState := func(id string, key int) (int, bool) {
		_, _, _, _, states := bpf.Snapshot(id)
		state, ok := states[key]
		return state, ok
	}

	require.Eventually(t, func() bool {
		_, programmed := podState(early, ebpf.POD_STATE_MAP_KEY)
		_, clusterProgrammed := podState(early, ebpf.CLUSTER_POLICY_POD_STATE_MAP_KEY)
		return programmed && clusterProgrammed
	}, envtestWait, 50*time.Millisecond, "an identifier queued before start is programmed once the workers run")

	require.NoError(t, direct.Create(context.Background(), envtestPE("np-1-aaaaa", "np-1", "web-aaa", "192.168.90.1/32", "10.1.1.1")))
	require.Eventually(t, func() bool {
		return slices.Equal(ingressCIDRs(web), []string{"192.168.90.1/32"})
	}, envtestWait, 50*time.Millisecond, "a new policy is programmed through both stages")

	require.NoError(t, direct.Create(context.Background(), envtestPE("np-2-aaaaa", "np-2", "web-aaa", "192.168.90.2/32", "10.1.1.1")))
	require.Eventually(t, func() bool {
		return slices.Equal(ingressCIDRs(web), []string{"192.168.90.1/32", "192.168.90.2/32"})
	}, envtestWait, 50*time.Millisecond, "a second policy selecting the same pod is unioned in")

	require.NoError(t, direct.Create(context.Background(), envtestCPE("cnp-1-aaaaa", "cnp-1", "web-aaa", "192.168.91.1/32", "10.1.1.1")))
	require.Eventually(t, func() bool {
		return slices.Equal(clusterRules(web), []string{"Deny 192.168.91.1/32"})
	}, envtestWait, 50*time.Millisecond, "a cluster policy is programmed through its own stages")

	require.NoError(t, direct.Delete(context.Background(), envtestPE("np-1-aaaaa", "np-1", "", "", "")))
	require.NoError(t, direct.Delete(context.Background(), envtestPE("np-2-aaaaa", "np-2", "", "", "")))
	require.Eventually(t, func() bool {
		state, ok := podState(web, ebpf.POD_STATE_MAP_KEY)
		return len(ingressCIDRs(web)) == 0 && ok && state == DEFAULT_ALLOW
	}, envtestWait, 50*time.Millisecond, "deleting both policies returns the pod to its baseline")
	require.Equal(t, []string{"Deny 192.168.91.1/32"}, clusterRules(web), "the cluster policy is untouched")

	require.NoError(t, direct.Delete(context.Background(), &policyk8sawsv1.ClusterPolicyEndpoint{ObjectMeta: envtestCPE("cnp-1-aaaaa", "", "", "", "").ObjectMeta}))
	require.Eventually(t, func() bool {
		state, ok := podState(web, ebpf.CLUSTER_POLICY_POD_STATE_MAP_KEY)
		return len(clusterRules(web)) == 0 && ok && state == ebpf.DEFAULT_ALLOW
	}, envtestWait, 50*time.Millisecond, "deleting the cluster policy clears its rules")
}

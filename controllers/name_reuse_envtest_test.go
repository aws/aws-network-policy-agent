package controllers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// These tests run the controllers against a real API server. Delete-and-recreate tests hold the
// worker so both parents are queued before either runs; they arrive as a delete and a create. The
// in-place parent change tests send a real update, which is what exercises UpdateFunc.

const (
	envtestNamespace = "np-target"
	// Two policies sharing a 58-character prefix: GenerateName gives their slices identical names
	reuseBase   = "payments-api-allow-ingress-from-frontend-and-monitoring-xy"
	reuseAlpha  = reuseBase + "-alpha"
	reuseBeta   = reuseBase + "-beta"
	gatePolicy  = "gate-policy"
	gateSlice   = "gate-policy-gate1"
	envtestWait = 30 * time.Second
)

func minimalCRD(plural, kind string, scope apiextensionsv1.ResourceScope) *apiextensionsv1.CustomResourceDefinition {
	preserve := true
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: plural + "." + policyk8sawsv1.GroupVersion.Group},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: policyk8sawsv1.GroupVersion.Group,
			Names: apiextensionsv1.CustomResourceDefinitionNames{Plural: plural, Kind: kind, ListKind: kind + "List"},
			Scope: scope,
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{{
				Name: policyk8sawsv1.GroupVersion.Version, Served: true, Storage: true,
				Schema: &apiextensionsv1.CustomResourceValidation{OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
					Type: "object", XPreserveUnknownFields: &preserve}},
			}},
		},
	}
}

// startAPIServer starts an API server with the policy endpoint CRDs and the test namespace
func startAPIServer(t *testing.T) (*rest.Config, client.Client, *runtime.Scheme) {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		// CI must run these: a skip there hides a broken setup-envtest behind a green build
		if os.Getenv("CI") != "" {
			t.Fatal("KUBEBUILDER_ASSETS not set in CI; make test must provide envtest assets")
		}
		t.Skip("KUBEBUILDER_ASSETS not set; run with make test")
	}
	env := &envtest.Environment{CRDs: []*apiextensionsv1.CustomResourceDefinition{
		minimalCRD("policyendpoints", "PolicyEndpoint", apiextensionsv1.NamespaceScoped),
		minimalCRD("clusterpolicyendpoints", "ClusterPolicyEndpoint", apiextensionsv1.ClusterScoped),
	}}
	cfg, err := env.Start()
	require.NoError(t, err)
	t.Cleanup(func() { _ = env.Stop() })

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, policyk8sawsv1.AddToScheme(scheme))
	direct, err := client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(t, err)
	require.NoError(t, direct.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: envtestNamespace}}))
	return cfg, direct, scheme
}

// gatedReconciler blocks the reconcile of the gate slice until released, holding the worker. It
// runs before on the worker goroutine ahead of each reconcile, and records every result.
type gatedReconciler struct {
	inner    reconcile.TypedReconciler[EndpointRequest]
	before   func(EndpointRequest)
	entered  chan struct{}
	release  chan struct{}
	gateOnce sync.Once

	mu      sync.Mutex
	results []reconcileResult
}

type reconcileResult struct {
	req EndpointRequest
	err error
}

func (g *gatedReconciler) Reconcile(ctx context.Context, req EndpointRequest) (ctrl.Result, error) {
	if req.Endpoint.Name == gateSlice {
		g.gateOnce.Do(func() {
			close(g.entered)
			<-g.release
		})
	}
	if g.before != nil {
		g.before(req)
	}
	res, err := g.inner.Reconcile(ctx, req)
	g.mu.Lock()
	g.results = append(g.results, reconcileResult{req: req, err: err})
	g.mu.Unlock()
	return res, err
}

func (g *gatedReconciler) log() []reconcileResult {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.results)
}

// succeeded reports whether req's latest reconcile succeeded
func (g *gatedReconciler) succeeded(req EndpointRequest) bool { return g.succeededSince(0, req) }

// succeededSince reports whether req's latest reconcile at or after log index n succeeded
func (g *gatedReconciler) succeededSince(n int, req EndpointRequest) bool {
	log := g.log()
	for i := len(log) - 1; i >= n; i-- {
		if log[i].req == req {
			return log[i].err == nil
		}
	}
	return false
}

type agentRun struct {
	t     *testing.T
	cache client.Client // the manager's cache-backed client
	gate  *gatedReconciler
	stop  func()
}

// startAgent runs the controller setup builds, around the reconciler newInner builds, in a
// manager, as one run of the agent
func startAgent(t *testing.T, cfg *rest.Config, scheme *runtime.Scheme,
	setup func(ctrl.Manager, reconcile.TypedReconciler[EndpointRequest], controller.TypedOptions[EndpointRequest]) error,
	newInner func(client.Client) reconcile.TypedReconciler[EndpointRequest], before func(EndpointRequest)) *agentRun {
	t.Helper()
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{Scheme: scheme, Metrics: metricsserver.Options{BindAddress: "0"}})
	require.NoError(t, err)
	gate := &gatedReconciler{inner: newInner(mgr.GetClient()), before: before,
		entered: make(chan struct{}), release: make(chan struct{})}
	skip := true
	require.NoError(t, setup(mgr, gate, controller.TypedOptions[EndpointRequest]{SkipNameValidation: &skip}))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = mgr.Start(ctx)
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			select {
			case <-gate.entered:
			default:
				close(gate.entered)
			}
			select {
			case <-gate.release:
			default:
				close(gate.release)
			}
			cancel()
			<-done
		})
	}
	t.Cleanup(stop)
	require.True(t, mgr.GetCache().WaitForCacheSync(ctx))
	return &agentRun{t: t, cache: mgr.GetClient(), gate: gate, stop: stop}
}

func setupPEController(mgr ctrl.Manager, r reconcile.TypedReconciler[EndpointRequest], o controller.TypedOptions[EndpointRequest]) error {
	return setupEndpointController(mgr, "policyendpoint", &policyk8sawsv1.PolicyEndpoint{}, policyEndpointParent, r, o)
}

func setupCPEController(mgr ctrl.Manager, r reconcile.TypedReconciler[EndpointRequest], o controller.TypedOptions[EndpointRequest]) error {
	return setupEndpointController(mgr, "clusterpolicyendpoint", &policyk8sawsv1.ClusterPolicyEndpoint{}, clusterPolicyEndpointParent, r, o)
}

// holdWorker creates the gate slice and waits until its reconcile holds the worker
func (a *agentRun) holdWorker(c client.Client, gate client.Object) {
	a.t.Helper()
	require.NoError(a.t, c.Create(context.Background(), gate))
	select {
	case <-a.gate.entered:
	case <-time.After(envtestWait):
		a.t.Fatal("gate reconcile never started")
	}
}

func (a *agentRun) releaseWorker() { close(a.gate.release) }

// eventually polls cond, which must only read concurrency-safe state while the manager runs
func eventually(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	require.Eventually(t, cond, envtestWait, 50*time.Millisecond, msg)
}

func envtestPE(name, parent string, pod, cidr string, podIP string) *policyk8sawsv1.PolicyEndpoint {
	pe := &policyk8sawsv1.PolicyEndpoint{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: envtestNamespace}}
	pe.Spec.PolicyRef = policyk8sawsv1.PolicyReference{Name: parent, Namespace: envtestNamespace}
	pe.Spec.PodIsolation = []networking.PolicyType{networking.PolicyTypeIngress}
	if pod != "" {
		pe.Spec.PodSelectorEndpoints = []policyk8sawsv1.PodEndpoint{{HostIP: fixtureNodeIP, PodIP: policyk8sawsv1.NetworkAddress(podIP), Name: pod, Namespace: envtestNamespace}}
	}
	if cidr != "" {
		pe.Spec.Ingress = []policyk8sawsv1.EndpointInfo{{CIDR: policyk8sawsv1.NetworkAddress(cidr)}}
	}
	return pe
}

func envtestCPE(name, parent string, pod, cidr string, podIP string) *policyk8sawsv1.ClusterPolicyEndpoint {
	cpe := &policyk8sawsv1.ClusterPolicyEndpoint{ObjectMeta: metav1.ObjectMeta{Name: name}}
	cpe.Spec.PolicyRef = policyk8sawsv1.ClusterPolicyReference{Name: parent}
	cpe.Spec.Tier = policyk8sawsv1.AdminTier
	cpe.Spec.Priority = 10
	if pod != "" {
		cpe.Spec.PodSelectorEndpoints = []policyk8sawsv1.PodEndpoint{{HostIP: fixtureNodeIP, PodIP: policyk8sawsv1.NetworkAddress(podIP), Name: pod, Namespace: envtestNamespace}}
	}
	if cidr != "" {
		cpe.Spec.Ingress = []policyk8sawsv1.ClusterEndpointInfo{{CIDR: policyk8sawsv1.NetworkAddress(cidr), Action: policyk8sawsv1.ClusterNetworkPolicyRuleActionDeny}}
	}
	return cpe
}

// reuseInCache waits until the agent's cache holds obj's name under parent
func reuseInCache[T client.Object](t *testing.T, cache client.Client, obj T, parent string, parentOf func(T) string) {
	t.Helper()
	eventually(t, func() bool {
		got := obj.DeepCopyObject().(T)
		return cache.Get(context.Background(), client.ObjectKeyFromObject(obj), got) == nil && parentOf(got) == parent
	}, "cache holds "+obj.GetName()+" under "+parent)
}

func TestPolicyEndpointNameReuse_Envtest(t *testing.T) {
	x := generatedSliceName(reuseAlpha, "aaaaa")
	require.Equal(t, x, generatedSliceName(reuseBeta, "aaaaa"), "both policies must generate this slice name")
	key := types.NamespacedName{Name: x, Namespace: envtestNamespace}
	alphaReq, betaReq := EndpointRequest{Endpoint: key, Parent: reuseAlpha}, EndpointRequest{Endpoint: key, Parent: reuseBeta}
	oldPod, newPod := utils.GetPodIdentifier("old-aaa", envtestNamespace), utils.GetPodIdentifier("new-aaa", envtestNamespace)
	gate := func() *policyk8sawsv1.PolicyEndpoint { return envtestPE(gateSlice, gatePolicy, "", "", "") }

	start := func(t *testing.T, bpf *ebpf.MockBpfClient, before func(EndpointRequest)) (*agentRun, client.Client, *PolicyEndpointsReconciler) {
		cfg, direct, scheme := startAPIServer(t)
		var r *PolicyEndpointsReconciler
		run := startAgent(t, cfg, scheme, setupPEController, func(c client.Client) reconcile.TypedReconciler[EndpointRequest] {
			r = NewPolicyEndpointsReconciler(c, fixtureNodeIP, bpf, false)
			return r
		}, before)
		return run, direct, r
	}
	// moveToBeta reuses x under beta while the worker is held, so both parents are queued before either runs
	moveToBeta := func(t *testing.T, run *agentRun, direct client.Client) {
		run.holdWorker(direct, gate())
		require.NoError(t, direct.Delete(context.Background(), envtestPE(x, reuseAlpha, "", "", "")))
		require.NoError(t, direct.Create(context.Background(), envtestPE(x, reuseBeta, "new-aaa", "192.168.90.2/32", "10.1.1.2")))
		reuseInCache(t, run.cache, envtestPE(x, "", "", "", ""), reuseBeta, policyEndpointParent)
		run.releaseWorker()
	}
	assertMoved := func(t *testing.T, bpf *ebpf.MockBpfClient, r *PolicyEndpointsReconciler) {
		assert.Empty(t, bpf.IngressByIdentifier[oldPod], "the old pod's rules must be cleared")
		assert.Equal(t, ebpf.DEFAULT_ALLOW, bpf.PodStateByIdentifier[ebpf.PodStateKey{PodIdentifier: oldPod, MapKey: ebpf.POD_STATE_MAP_KEY}])
		assert.Equal(t, []string{"192.168.90.2/32"}, cidrsOf(bpf.IngressByIdentifier[newPod]))
		assert.Equal(t, ebpf.POLICIES_APPLIED, bpf.PodStateByIdentifier[ebpf.PodStateKey{PodIdentifier: newPod, MapKey: ebpf.POD_STATE_MAP_KEY}])
		got, _ := r.podIdentifierToPolicyEndpointMap.Load(newPod)
		assert.Equal(t, refsOf(reuseBeta, x), got)
		_, tracked := r.podIdentifierToPolicyEndpointMap.Load(oldPod)
		assert.False(t, tracked, "the old pod must not stay tracked")
		_, tracked = r.policyEndpointSelectorMap.Load(alphaReq)
		assert.False(t, tracked, "nothing may stay recorded under the old parent")
		_, tracked = r.networkPolicyToPodIdentifierMap.Load(utils.GetNetworkPolicyIdentifier(reuseAlpha, envtestNamespace))
		assert.False(t, tracked, "the old parent's snapshot must be dropped")
	}

	t.Run("delete and recreate under another parent while the worker is busy reconciles both parents", func(t *testing.T) {
		bpf := &ebpf.MockBpfClient{}
		run, direct, r := start(t, bpf, nil)
		require.NoError(t, direct.Create(context.Background(), envtestPE(x, reuseAlpha, "old-aaa", "192.168.90.1/32", "10.1.1.1")))
		eventually(t, func() bool { return run.gate.succeeded(alphaReq) }, "alpha programmed")

		moveToBeta(t, run, direct)
		eventually(t, func() bool { return run.gate.succeeded(alphaReq) && run.gate.succeeded(betaReq) }, "both parents reconciled")
		run.stop()
		assertMoved(t, bpf, r)
	})

	t.Run("an update that changes the parent reconciles both parents", func(t *testing.T) {
		bpf := &ebpf.MockBpfClient{}
		run, direct, r := start(t, bpf, nil)
		require.NoError(t, direct.Create(context.Background(), envtestPE(x, reuseAlpha, "old-aaa", "192.168.90.1/32", "10.1.1.1")))
		eventually(t, func() bool { return run.gate.succeeded(alphaReq) }, "alpha programmed")
		n := len(run.gate.log())

		// The same object moves to beta, so the informer delivers an update carrying both parents
		pe := &policyk8sawsv1.PolicyEndpoint{}
		require.NoError(t, direct.Get(context.Background(), key, pe))
		moved := envtestPE(x, reuseBeta, "new-aaa", "192.168.90.2/32", "10.1.1.2")
		pe.Spec = moved.Spec
		require.NoError(t, direct.Update(context.Background(), pe))
		eventually(t, func() bool { return run.gate.succeededSince(n, alphaReq) && run.gate.succeededSince(n, betaReq) },
			"both parents reconciled after the update")
		run.stop()
		assertMoved(t, bpf, r)
	})

	t.Run("a failing old-parent cleanup retries without touching the new parent", func(t *testing.T) {
		bpf := &ebpf.MockBpfClient{}
		writeFailed := errors.New("injected map write failure")
		moved, alphaFailures, betaDone := false, 0, false
		// Runs on the worker goroutine: fail the cleanup until it has failed once and the new
		// parent has been programmed, so its retry runs after the new parent's reconcile
		before := func(req EndpointRequest) {
			bpf.UpdateEbpfMapsErrFor = nil
			if moved && req == alphaReq && (alphaFailures == 0 || !betaDone) {
				alphaFailures++
				bpf.UpdateEbpfMapsErrFor = map[string]error{oldPod: writeFailed}
			}
			if req == betaReq {
				betaDone = true
			}
		}
		run, direct, r := start(t, bpf, before)
		require.NoError(t, direct.Create(context.Background(), envtestPE(x, reuseAlpha, "old-aaa", "192.168.90.1/32", "10.1.1.1")))
		eventually(t, func() bool { return run.gate.succeeded(alphaReq) }, "alpha programmed")

		run.holdWorker(direct, gate())
		moved = true // read by the worker only after the release below
		require.NoError(t, direct.Delete(context.Background(), envtestPE(x, reuseAlpha, "", "", "")))
		require.NoError(t, direct.Create(context.Background(), envtestPE(x, reuseBeta, "new-aaa", "192.168.90.2/32", "10.1.1.2")))
		reuseInCache(t, run.cache, envtestPE(x, "", "", "", ""), reuseBeta, policyEndpointParent)
		run.releaseWorker()
		eventually(t, func() bool { return run.gate.succeeded(alphaReq) && run.gate.succeeded(betaReq) }, "both parents reconciled")
		run.stop()

		label := map[EndpointRequest]string{alphaReq: "alpha", betaReq: "beta"}
		var order []string
		for _, res := range run.gate.log() {
			if l, ok := label[res.req]; ok {
				order = append(order, fmt.Sprintf("%s ok=%v", l, res.err == nil))
			}
		}
		// After alpha is first programmed, its cleanup fails at least once and succeeds only
		// after beta is programmed
		order = order[1:]
		require.GreaterOrEqual(t, len(order), 3, "%v", order)
		assert.Contains(t, order, "alpha ok=false", "%v", order)
		assert.Equal(t, "alpha ok=true", order[len(order)-1], "%v", order)
		assert.Less(t, slices.Index(order, "beta ok=true"), len(order)-1, "%v", order)
		assertMoved(t, bpf, r)
	})

	t.Run("a name that moves away and back ends up programmed under its parent", func(t *testing.T) {
		bpf := &ebpf.MockBpfClient{}
		run, direct, r := start(t, bpf, nil)
		require.NoError(t, direct.Create(context.Background(), envtestPE(x, reuseAlpha, "old-aaa", "192.168.90.1/32", "10.1.1.1")))
		eventually(t, func() bool { return run.gate.succeeded(alphaReq) }, "alpha programmed")

		run.holdWorker(direct, gate())
		require.NoError(t, direct.Delete(context.Background(), envtestPE(x, reuseAlpha, "", "", "")))
		require.NoError(t, direct.Create(context.Background(), envtestPE(x, reuseBeta, "new-aaa", "192.168.90.2/32", "10.1.1.2")))
		reuseInCache(t, run.cache, envtestPE(x, "", "", "", ""), reuseBeta, policyEndpointParent)
		require.NoError(t, direct.Delete(context.Background(), envtestPE(x, reuseBeta, "", "", "")))
		require.NoError(t, direct.Create(context.Background(), envtestPE(x, reuseAlpha, "new-aaa", "192.168.90.3/32", "10.1.1.2")))
		reuseInCache(t, run.cache, envtestPE(x, "", "", "", ""), reuseAlpha, policyEndpointParent)
		run.releaseWorker()
		eventually(t, func() bool { return run.gate.succeeded(alphaReq) && run.gate.succeeded(betaReq) }, "both parents reconciled")
		run.stop()

		assert.Empty(t, bpf.IngressByIdentifier[oldPod], "the deselected pod's rules must be cleared")
		assert.Equal(t, []string{"192.168.90.3/32"}, cidrsOf(bpf.IngressByIdentifier[newPod]))
		got, _ := r.podIdentifierToPolicyEndpointMap.Load(newPod)
		assert.Equal(t, refsOf(reuseAlpha, x), got, "nothing may stay recorded under beta")
		_, tracked := r.policyEndpointSelectorMap.Load(betaReq)
		assert.False(t, tracked)
	})
}

func TestClusterPolicyEndpointNameReuse_Envtest(t *testing.T) {
	x := generatedSliceName(reuseAlpha, "aaaaa")
	alphaReq, betaReq := cpeRequest(x, reuseAlpha), cpeRequest(x, reuseBeta)
	oldPod, newPod := utils.GetPodIdentifier("old-aaa", envtestNamespace), utils.GetPodIdentifier("new-aaa", envtestNamespace)
	sibling := generatedSliceName(reuseBeta, "bbbbb")
	sibPod := utils.GetPodIdentifier("sib-aaa", envtestNamespace)

	t.Run("delete and recreate under another parent while the worker is busy reconciles both parents", func(t *testing.T) {
		cfg, direct, scheme := startAPIServer(t)
		bpf := &ebpf.MockBpfClient{}
		var r *ClusterPolicyEndpointsReconciler
		run := startAgent(t, cfg, scheme, setupCPEController, func(c client.Client) reconcile.TypedReconciler[EndpointRequest] {
			r = NewClusterPolicyEndpointsReconciler(c, fixtureNodeIP, bpf)
			return r
		}, nil)
		require.NoError(t, direct.Create(context.Background(), envtestCPE(x, reuseAlpha, "old-aaa", "192.168.90.1/32", "10.1.1.1")))
		require.NoError(t, direct.Create(context.Background(), envtestCPE(sibling, reuseBeta, "sib-aaa", "192.168.90.3/32", "10.1.1.3")))
		eventually(t, func() bool { return run.gate.succeeded(alphaReq) && run.gate.succeeded(cpeRequest(sibling, reuseBeta)) }, "both programmed")

		run.holdWorker(direct, envtestCPE(gateSlice, gatePolicy, "", "", ""))
		require.NoError(t, direct.Delete(context.Background(), envtestCPE(x, reuseAlpha, "", "", "")))
		require.NoError(t, direct.Create(context.Background(), envtestCPE(x, reuseBeta, "new-aaa", "192.168.90.2/32", "10.1.1.2")))
		reuseInCache(t, run.cache, envtestCPE(x, "", "", "", ""), reuseBeta, clusterPolicyEndpointParent)
		run.releaseWorker()
		eventually(t, func() bool { return run.gate.succeeded(alphaReq) && run.gate.succeeded(betaReq) }, "both parents reconciled")
		run.stop()

		assert.Empty(t, bpf.ClusterPolicyIngressByIdentifier[oldPod], "the old pod's Deny must be cleared")
		assert.Equal(t, ebpf.DEFAULT_ALLOW, bpf.PodStateByIdentifier[ebpf.PodStateKey{PodIdentifier: oldPod, MapKey: ebpf.CLUSTER_POLICY_POD_STATE_MAP_KEY}])
		for _, id := range []string{newPod, sibPod} {
			assert.ElementsMatch(t, []string{"Deny 192.168.90.2/32", "Deny 192.168.90.3/32"}, actionCIDRsOf(bpf.ClusterPolicyIngressByIdentifier[id]), id)
		}
		_, tracked := r.ClusterPolicyEndpointSelectorMap.Load(alphaReq)
		assert.False(t, tracked, "nothing may stay recorded under the old parent")
		_, tracked = r.clusterNetworkPolicyToPodIdentifierMap.Load(reuseAlpha)
		assert.False(t, tracked, "the old parent's snapshot must be dropped")
	})
	t.Run("an update that changes the parent reconciles both parents", func(t *testing.T) {
		cfg, direct, scheme := startAPIServer(t)
		bpf := &ebpf.MockBpfClient{}
		var r *ClusterPolicyEndpointsReconciler
		run := startAgent(t, cfg, scheme, setupCPEController, func(c client.Client) reconcile.TypedReconciler[EndpointRequest] {
			r = NewClusterPolicyEndpointsReconciler(c, fixtureNodeIP, bpf)
			return r
		}, nil)
		require.NoError(t, direct.Create(context.Background(), envtestCPE(x, reuseAlpha, "old-aaa", "192.168.90.1/32", "10.1.1.1")))
		eventually(t, func() bool { return run.gate.succeeded(alphaReq) }, "alpha programmed")
		n := len(run.gate.log())

		// The same object moves to beta, so the informer delivers an update carrying both parents
		cpe := &policyk8sawsv1.ClusterPolicyEndpoint{}
		require.NoError(t, direct.Get(context.Background(), types.NamespacedName{Name: x}, cpe))
		cpe.Spec = envtestCPE(x, reuseBeta, "new-aaa", "192.168.90.2/32", "10.1.1.2").Spec
		require.NoError(t, direct.Update(context.Background(), cpe))
		eventually(t, func() bool { return run.gate.succeededSince(n, alphaReq) && run.gate.succeededSince(n, betaReq) },
			"both parents reconciled after the update")
		run.stop()

		assert.Empty(t, bpf.ClusterPolicyIngressByIdentifier[oldPod], "the old pod's Deny must be cleared")
		assert.Equal(t, ebpf.DEFAULT_ALLOW, bpf.PodStateByIdentifier[ebpf.PodStateKey{PodIdentifier: oldPod, MapKey: ebpf.CLUSTER_POLICY_POD_STATE_MAP_KEY}])
		assert.Equal(t, []string{"Deny 192.168.90.2/32"}, actionCIDRsOf(bpf.ClusterPolicyIngressByIdentifier[newPod]))
		_, tracked := r.ClusterPolicyEndpointSelectorMap.Load(alphaReq)
		assert.False(t, tracked, "nothing may stay recorded under the old parent")
		_, tracked = r.clusterNetworkPolicyToPodIdentifierMap.Load(reuseAlpha)
		assert.False(t, tracked, "the old parent's snapshot must be dropped")
	})
}

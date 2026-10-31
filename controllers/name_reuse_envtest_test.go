package controllers

import (
	"context"
	"os"
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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// These tests run the reconcilers against a real API server so a slice deleted and recreated
// under another policy reaches the agent as one reconcile, as it does when the agent falls
// behind. A gate holds the single worker inside a reconcile while the test changes slices, then
// releases it once the cache holds the changes.

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

// gatedReconciler blocks the reconcile of the gate slice until released, holding the worker
type gatedReconciler struct {
	inner    reconcile.Reconciler
	entered  chan struct{}
	release  chan struct{}
	gateOnce sync.Once
}

func (g *gatedReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if req.Name == gateSlice {
		g.gateOnce.Do(func() {
			close(g.entered)
			<-g.release
		})
	}
	return g.inner.Reconcile(ctx, req)
}

type reuseEnv struct {
	t      *testing.T
	client client.Client // direct API client
	cache  client.Client // the manager's cache-backed client
	gate   *gatedReconciler
	stop   func()
}

// startReuseEnv starts an API server and a manager running inner on obj's kind
func startReuseEnv(t *testing.T, obj client.Object, inner func(client.Client) reconcile.Reconciler) *reuseEnv {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
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

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{Scheme: scheme, Metrics: metricsserver.Options{BindAddress: "0"}})
	require.NoError(t, err)
	gate := &gatedReconciler{inner: inner(mgr.GetClient()), entered: make(chan struct{}), release: make(chan struct{})}
	skip := true
	require.NoError(t, ctrl.NewControllerManagedBy(mgr).For(obj).
		WithOptions(controller.Options{SkipNameValidation: &skip}).Complete(gate))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = mgr.Start(ctx)
	}()
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			cancel()
			<-done
		}
	}
	t.Cleanup(stop)
	require.True(t, mgr.GetCache().WaitForCacheSync(ctx))
	return &reuseEnv{t: t, client: direct, cache: mgr.GetClient(), gate: gate, stop: stop}
}

// holdWorker creates the gate slice and waits until its reconcile holds the worker
func (e *reuseEnv) holdWorker(gate client.Object) {
	e.t.Helper()
	require.NoError(e.t, e.client.Create(context.Background(), gate))
	select {
	case <-e.gate.entered:
	case <-time.After(envtestWait):
		e.t.Fatal("gate reconcile never started")
	}
}

func (e *reuseEnv) releaseWorker() { close(e.gate.release) }

// eventually polls cond, which must only read concurrency-safe state while the manager runs
func (e *reuseEnv) eventually(cond func() bool, msg string) {
	e.t.Helper()
	require.Eventually(e.t, cond, envtestWait, 50*time.Millisecond, msg)
}

func (e *reuseEnv) recreate(old, replacement client.Object) {
	e.t.Helper()
	require.NoError(e.t, e.client.Delete(context.Background(), old))
	require.NoError(e.t, e.client.Create(context.Background(), replacement))
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

func peSnapshot(r *PolicyEndpointsReconciler, parent string) ([]string, bool) {
	v, ok := r.networkPolicyToPodIdentifierMap.Load(utils.GetNetworkPolicyIdentifier(parent, envtestNamespace))
	if !ok {
		return nil, false
	}
	return v.([]string), true
}

func peRecord(r *PolicyEndpointsReconciler, name string) string {
	v, _ := r.policyEndpointToParentNPMap.Load(types.NamespacedName{Name: name, Namespace: envtestNamespace})
	s, _ := v.(string)
	return s
}

func peTransitionsPending(r *PolicyEndpointsReconciler) int {
	r.parentTransitionsMutex.Lock()
	defer r.parentTransitionsMutex.Unlock()
	return len(r.parentTransitions)
}

func newEnvtestPEReconciler(bpf *ebpf.MockBpfClient, r **PolicyEndpointsReconciler) func(client.Client) reconcile.Reconciler {
	return func(c client.Client) reconcile.Reconciler {
		*r = NewPolicyEndpointsReconciler(c, fixtureNodeIP, bpf, false)
		return *r
	}
}

func TestPolicyEndpointNameReuse_Envtest(t *testing.T) {
	x := generatedSliceName(reuseAlpha, "aaaaa")
	require.Equal(t, x, generatedSliceName(reuseBeta, "aaaaa"), "both policies must generate this slice name")
	oldPod, newPod := utils.GetPodIdentifier("old-aaa", envtestNamespace), utils.GetPodIdentifier("new-aaa", envtestNamespace)

	t.Run("delete and recreate under another policy, seen as one reconcile", func(t *testing.T) {
		bpf := &ebpf.MockBpfClient{}
		var r *PolicyEndpointsReconciler
		e := startReuseEnv(t, &policyk8sawsv1.PolicyEndpoint{}, newEnvtestPEReconciler(bpf, &r))
		old := envtestPE(x, reuseAlpha, "old-aaa", "192.168.90.1/32", "10.1.1.1")
		require.NoError(t, e.client.Create(context.Background(), old))
		e.eventually(func() bool { _, ok := peSnapshot(r, reuseAlpha); return ok && peRecord(r, x) == reuseAlpha }, "alpha programmed")

		e.holdWorker(envtestPE(gateSlice, gatePolicy, "", "", ""))
		e.recreate(old, envtestPE(x, reuseBeta, "new-aaa", "192.168.90.2/32", "10.1.1.2"))
		e.eventually(func() bool {
			got := &policyk8sawsv1.PolicyEndpoint{}
			return e.cache.Get(context.Background(), client.ObjectKeyFromObject(old), got) == nil && got.Spec.PolicyRef.Name == reuseBeta
		}, "cache holds the recreated slice")
		e.releaseWorker()

		e.eventually(func() bool {
			_, alpha := peSnapshot(r, reuseAlpha)
			beta, ok := peSnapshot(r, reuseBeta)
			return !alpha && ok && len(beta) == 1 && beta[0] == newPod && peRecord(r, x) == reuseBeta && peTransitionsPending(r) == 0
		}, "the old policy is cleaned up and the new one programmed")
		e.stop()
		assert.Empty(t, bpf.IngressByIdentifier[oldPod], "the old pod's rules must be cleared")
		assert.Equal(t, []string{"192.168.90.2/32"}, cidrsOf(bpf.IngressByIdentifier[newPod]))
	})

	t.Run("a sibling of the new policy reconciles first", func(t *testing.T) {
		bpf := &ebpf.MockBpfClient{}
		var r *PolicyEndpointsReconciler
		e := startReuseEnv(t, &policyk8sawsv1.PolicyEndpoint{}, newEnvtestPEReconciler(bpf, &r))
		sibling := generatedSliceName(reuseBeta, "bbbbb")
		old := envtestPE(x, reuseAlpha, "old-aaa", "192.168.90.1/32", "10.1.1.1")
		require.NoError(t, e.client.Create(context.Background(), old))
		require.NoError(t, e.client.Create(context.Background(), envtestPE(sibling, reuseBeta, "sib-aaa", "192.168.90.3/32", "10.1.1.3")))
		e.eventually(func() bool { return peRecord(r, x) == reuseAlpha && peRecord(r, sibling) == reuseBeta }, "both programmed")

		e.holdWorker(envtestPE(gateSlice, gatePolicy, "", "", ""))
		// The sibling's update queues ahead of the reused name
		current := &policyk8sawsv1.PolicyEndpoint{}
		require.NoError(t, e.client.Get(context.Background(), types.NamespacedName{Name: sibling, Namespace: envtestNamespace}, current))
		current.Spec.Ingress = []policyk8sawsv1.EndpointInfo{{CIDR: "192.168.90.4/32"}}
		require.NoError(t, e.client.Update(context.Background(), current))
		e.recreate(old, envtestPE(x, reuseBeta, "new-aaa", "192.168.90.2/32", "10.1.1.2"))
		e.eventually(func() bool {
			got := &policyk8sawsv1.PolicyEndpoint{}
			return e.cache.Get(context.Background(), client.ObjectKeyFromObject(old), got) == nil && got.Spec.PolicyRef.Name == reuseBeta
		}, "cache holds the recreated slice")
		e.releaseWorker()

		e.eventually(func() bool {
			_, alpha := peSnapshot(r, reuseAlpha)
			beta, ok := peSnapshot(r, reuseBeta)
			return !alpha && ok && len(beta) == 2 && peRecord(r, x) == reuseBeta && peTransitionsPending(r) == 0
		}, "the old policy is cleaned up and the new one programmed")
		e.stop()
		assert.Empty(t, bpf.IngressByIdentifier[oldPod], "the old pod's rules must be cleared")
		assert.ElementsMatch(t, []string{"192.168.90.2/32", "192.168.90.4/32"}, cidrsOf(bpf.IngressByIdentifier[newPod]))
	})

	t.Run("two slices swap policies, seen as one reconcile each", func(t *testing.T) {
		bpf := &ebpf.MockBpfClient{}
		var r *PolicyEndpointsReconciler
		e := startReuseEnv(t, &policyk8sawsv1.PolicyEndpoint{}, newEnvtestPEReconciler(bpf, &r))
		y := generatedSliceName(reuseBeta, "bbbbb")
		oldX := envtestPE(x, reuseAlpha, "xa-aaa", "192.168.90.1/32", "10.1.1.1")
		oldY := envtestPE(y, reuseBeta, "yb-aaa", "192.168.90.2/32", "10.1.1.2")
		require.NoError(t, e.client.Create(context.Background(), oldX))
		require.NoError(t, e.client.Create(context.Background(), oldY))
		e.eventually(func() bool { return peRecord(r, x) == reuseAlpha && peRecord(r, y) == reuseBeta }, "both programmed")

		e.holdWorker(envtestPE(gateSlice, gatePolicy, "", "", ""))
		e.recreate(oldX, envtestPE(x, reuseBeta, "xb-aaa", "192.168.90.3/32", "10.1.1.3"))
		e.recreate(oldY, envtestPE(y, reuseAlpha, "ya-aaa", "192.168.90.4/32", "10.1.1.4"))
		e.eventually(func() bool {
			gx, gy := &policyk8sawsv1.PolicyEndpoint{}, &policyk8sawsv1.PolicyEndpoint{}
			return e.cache.Get(context.Background(), client.ObjectKeyFromObject(oldX), gx) == nil && gx.Spec.PolicyRef.Name == reuseBeta &&
				e.cache.Get(context.Background(), client.ObjectKeyFromObject(oldY), gy) == nil && gy.Spec.PolicyRef.Name == reuseAlpha
		}, "cache holds both recreated slices")
		e.releaseWorker()

		ya, xb := utils.GetPodIdentifier("ya-aaa", envtestNamespace), utils.GetPodIdentifier("xb-aaa", envtestNamespace)
		e.eventually(func() bool {
			alpha, okA := peSnapshot(r, reuseAlpha)
			beta, okB := peSnapshot(r, reuseBeta)
			return okA && okB && len(alpha) == 1 && alpha[0] == ya && len(beta) == 1 && beta[0] == xb &&
				peRecord(r, x) == reuseBeta && peRecord(r, y) == reuseAlpha && peTransitionsPending(r) == 0
		}, "both policies settle")
		e.stop()
		assert.Empty(t, bpf.IngressByIdentifier[utils.GetPodIdentifier("xa-aaa", envtestNamespace)])
		assert.Empty(t, bpf.IngressByIdentifier[utils.GetPodIdentifier("yb-aaa", envtestNamespace)])
		assert.Equal(t, []string{"192.168.90.4/32"}, cidrsOf(bpf.IngressByIdentifier[ya]))
		assert.Equal(t, []string{"192.168.90.3/32"}, cidrsOf(bpf.IngressByIdentifier[xb]))
	})
}

func cpeSnapshot(r *ClusterPolicyEndpointsReconciler, parent string) ([]string, bool) {
	v, ok := r.clusterNetworkPolicyToPodIdentifierMap.Load(parent)
	if !ok {
		return nil, false
	}
	return v.([]string), true
}

func cpeRecord(r *ClusterPolicyEndpointsReconciler, name string) string {
	v, _ := r.clusterPolicyEndpointToParentCNPMap.Load(name)
	s, _ := v.(string)
	return s
}

func cpeTransitionsPending(r *ClusterPolicyEndpointsReconciler) int {
	r.parentTransitionsMutex.Lock()
	defer r.parentTransitionsMutex.Unlock()
	return len(r.parentTransitions)
}

func TestClusterPolicyEndpointNameReuse_Envtest(t *testing.T) {
	x, y := generatedSliceName(reuseAlpha, "aaaaa"), generatedSliceName(reuseBeta, "bbbbb")
	newReconciler := func(bpf *ebpf.MockBpfClient, r **ClusterPolicyEndpointsReconciler) func(client.Client) reconcile.Reconciler {
		return func(c client.Client) reconcile.Reconciler {
			*r = NewClusterPolicyEndpointsReconciler(c, fixtureNodeIP, bpf)
			return *r
		}
	}

	t.Run("delete and recreate under another policy, seen as one reconcile", func(t *testing.T) {
		bpf := &ebpf.MockBpfClient{}
		var r *ClusterPolicyEndpointsReconciler
		e := startReuseEnv(t, &policyk8sawsv1.ClusterPolicyEndpoint{}, newReconciler(bpf, &r))
		old := envtestCPE(x, reuseAlpha, "old-aaa", "192.168.90.1/32", "10.1.1.1")
		require.NoError(t, e.client.Create(context.Background(), old))
		e.eventually(func() bool { _, ok := cpeSnapshot(r, reuseAlpha); return ok && cpeRecord(r, x) == reuseAlpha }, "alpha programmed")

		e.holdWorker(envtestCPE(gateSlice, gatePolicy, "", "", ""))
		e.recreate(old, envtestCPE(x, reuseBeta, "new-aaa", "192.168.90.2/32", "10.1.1.2"))
		e.eventually(func() bool {
			got := &policyk8sawsv1.ClusterPolicyEndpoint{}
			return e.cache.Get(context.Background(), client.ObjectKeyFromObject(old), got) == nil && got.Spec.PolicyRef.Name == reuseBeta
		}, "cache holds the recreated slice")
		e.releaseWorker()

		newPod := utils.GetPodIdentifier("new-aaa", envtestNamespace)
		e.eventually(func() bool {
			_, alpha := cpeSnapshot(r, reuseAlpha)
			beta, ok := cpeSnapshot(r, reuseBeta)
			return !alpha && ok && len(beta) == 1 && beta[0] == newPod && cpeRecord(r, x) == reuseBeta && cpeTransitionsPending(r) == 0
		}, "the old policy is cleaned up and the new one programmed")
		e.stop()
		assert.Empty(t, bpf.ClusterPolicyIngressByIdentifier[utils.GetPodIdentifier("old-aaa", envtestNamespace)])
		assert.Equal(t, []string{"Deny 192.168.90.2/32"}, actionCIDRsOf(bpf.ClusterPolicyIngressByIdentifier[newPod]))
	})

	t.Run("two slices swap policies, seen as one reconcile each", func(t *testing.T) {
		bpf := &ebpf.MockBpfClient{}
		var r *ClusterPolicyEndpointsReconciler
		e := startReuseEnv(t, &policyk8sawsv1.ClusterPolicyEndpoint{}, newReconciler(bpf, &r))
		oldX := envtestCPE(x, reuseAlpha, "xa-aaa", "192.168.90.1/32", "10.1.1.1")
		oldY := envtestCPE(y, reuseBeta, "yb-aaa", "192.168.90.2/32", "10.1.1.2")
		require.NoError(t, e.client.Create(context.Background(), oldX))
		require.NoError(t, e.client.Create(context.Background(), oldY))
		e.eventually(func() bool { return cpeRecord(r, x) == reuseAlpha && cpeRecord(r, y) == reuseBeta }, "both programmed")

		e.holdWorker(envtestCPE(gateSlice, gatePolicy, "", "", ""))
		e.recreate(oldX, envtestCPE(x, reuseBeta, "xb-aaa", "192.168.90.3/32", "10.1.1.3"))
		e.recreate(oldY, envtestCPE(y, reuseAlpha, "ya-aaa", "192.168.90.4/32", "10.1.1.4"))
		e.eventually(func() bool {
			gx, gy := &policyk8sawsv1.ClusterPolicyEndpoint{}, &policyk8sawsv1.ClusterPolicyEndpoint{}
			return e.cache.Get(context.Background(), client.ObjectKeyFromObject(oldX), gx) == nil && gx.Spec.PolicyRef.Name == reuseBeta &&
				e.cache.Get(context.Background(), client.ObjectKeyFromObject(oldY), gy) == nil && gy.Spec.PolicyRef.Name == reuseAlpha
		}, "cache holds both recreated slices")
		e.releaseWorker()

		ya, xb := utils.GetPodIdentifier("ya-aaa", envtestNamespace), utils.GetPodIdentifier("xb-aaa", envtestNamespace)
		e.eventually(func() bool {
			alpha, okA := cpeSnapshot(r, reuseAlpha)
			beta, okB := cpeSnapshot(r, reuseBeta)
			return okA && okB && len(alpha) == 1 && alpha[0] == ya && len(beta) == 1 && beta[0] == xb &&
				cpeRecord(r, x) == reuseBeta && cpeRecord(r, y) == reuseAlpha && cpeTransitionsPending(r) == 0
		}, "both policies settle")
		e.stop()
		assert.Empty(t, bpf.ClusterPolicyIngressByIdentifier[utils.GetPodIdentifier("xa-aaa", envtestNamespace)])
		assert.Empty(t, bpf.ClusterPolicyIngressByIdentifier[utils.GetPodIdentifier("yb-aaa", envtestNamespace)])
		assert.Equal(t, []string{"Deny 192.168.90.4/32"}, actionCIDRsOf(bpf.ClusterPolicyIngressByIdentifier[ya]))
		assert.Equal(t, []string{"Deny 192.168.90.3/32"}, actionCIDRsOf(bpf.ClusterPolicyIngressByIdentifier[xb]))
	})
}

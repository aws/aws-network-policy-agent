package controllers

import (
	"context"
	"testing"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	mock_client "github.com/aws/aws-network-policy-agent/mocks/controller-runtime/client"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	controllerruntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Shared fixtures for the multi-slice suites. A PolicyEndpoint / ClusterPolicyEndpoint
// is one "slice" of its parent policy: the controller bin-packs pods, ingress rules and
// egress rules across as many slices as the endpoint chunk size requires, so a single
// parent policy routinely produces several, and one podIdentifier can be named by
// slices of several different parents.
//
// Tests declare the slices that exist in the API server, reconcile to reach steady
// state, then mutate the slices and reconcile again. Driving the maps through real
// reconciles rather than seeding them by hand keeps the fixtures honest about the
// reconciler's own bookkeeping.

const (
	fixtureNodeIP    = "192.168.70.108"
	fixtureRemoteIP  = "192.168.70.200"
	fixtureNamespace = "np-target"
)

// podRef is one entry of a slice's PodSelectorEndpoints. An empty node means the
// fixture's own node, so tests only name a node when they need the pod to be remote.
type podRef struct {
	name string
	ip   string
	node string
}

func localPod(name, ip string) podRef  { return podRef{name: name, ip: ip} }
func remotePod(name, ip string) podRef { return podRef{name: name, ip: ip, node: fixtureRemoteIP} }

// ruleRef is one ingress or egress entry. Action applies to cluster policies only;
// namespaced NetworkPolicy rules are allow-only.
type ruleRef struct {
	cidr   string
	action string
}

func allow(cidr string) ruleRef { return ruleRef{cidr: cidr, action: "Accept"} }
func deny(cidr string) ruleRef  { return ruleRef{cidr: cidr, action: "Deny"} }

// sliceSpec declares one PolicyEndpoint or ClusterPolicyEndpoint.
type sliceSpec struct {
	name     string
	parent   string
	pods     []podRef
	ingress  []ruleRef
	egress   []ruleRef
	tier     policyk8sawsv1.Tier
	priority int32
}

func (s sliceSpec) tierOrDefault() policyk8sawsv1.Tier {
	if s.tier == "" {
		return policyk8sawsv1.AdminTier
	}
	return s.tier
}

func (s sliceSpec) podEndpoints() []policyk8sawsv1.PodEndpoint {
	eps := make([]policyk8sawsv1.PodEndpoint, 0, len(s.pods))
	for _, p := range s.pods {
		host := p.node
		if host == "" {
			host = fixtureNodeIP
		}
		eps = append(eps, policyk8sawsv1.PodEndpoint{
			Name:      p.name,
			Namespace: fixtureNamespace,
			PodIP:     policyk8sawsv1.NetworkAddress(p.ip),
			HostIP:    policyk8sawsv1.NetworkAddress(host),
		})
	}
	return eps
}

func identifierOf(podName string) string {
	return utils.GetPodIdentifier(podName, fixtureNamespace)
}

func cidrsOf(rules []fwrp.EbpfFirewallRules) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, string(r.IPCidr))
	}
	return out
}

// ---------------------------------------------------------------------------
// ClusterPolicyEndpoint fixture
// ---------------------------------------------------------------------------

type cpeFixture struct {
	t     *testing.T
	r     *ClusterPolicyEndpointsReconciler
	bpf   *ebpf.MockBpfClient
	store map[string]policyk8sawsv1.ClusterPolicyEndpoint
}

func newCPEFixture(t *testing.T) *cpeFixture {
	t.Helper()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockClient := mock_client.NewMockClient(ctrl)
	fx := &cpeFixture{
		t:     t,
		bpf:   &ebpf.MockBpfClient{},
		store: map[string]policyk8sawsv1.ClusterPolicyEndpoint{},
	}
	fx.r = NewClusterPolicyEndpointsReconciler(mockClient, fixtureNodeIP, fx.bpf)

	mockClient.EXPECT().
		List(gomock.Any(), gomock.AssignableToTypeOf(&policyk8sawsv1.ClusterPolicyEndpointList{}), gomock.Any()).
		DoAndReturn(func(_ context.Context, list *policyk8sawsv1.ClusterPolicyEndpointList, _ ...client.ListOption) error {
			list.Items = nil
			for _, cpe := range fx.store {
				list.Items = append(list.Items, cpe)
			}
			return nil
		}).AnyTimes()

	mockClient.EXPECT().
		Get(gomock.Any(), gomock.Any(), gomock.AssignableToTypeOf(&policyk8sawsv1.ClusterPolicyEndpoint{}), gomock.Any()).
		DoAndReturn(func(_ context.Context, key types.NamespacedName, obj *policyk8sawsv1.ClusterPolicyEndpoint, _ ...client.GetOption) error {
			cpe, ok := fx.store[key.Name]
			if !ok {
				return apierrors.NewNotFound(schema.GroupResource{Resource: "clusterpolicyendpoints"}, key.Name)
			}
			*obj = cpe
			return nil
		}).AnyTimes()

	return fx
}

// setSlices replaces the set of ClusterPolicyEndpoints the API server holds.
func (fx *cpeFixture) setSlices(specs ...sliceSpec) {
	fx.store = map[string]policyk8sawsv1.ClusterPolicyEndpoint{}
	for _, s := range specs {
		ingress := make([]policyk8sawsv1.ClusterEndpointInfo, 0, len(s.ingress))
		for _, r := range s.ingress {
			ingress = append(ingress, policyk8sawsv1.ClusterEndpointInfo{
				CIDR:   policyk8sawsv1.NetworkAddress(r.cidr),
				Action: policyk8sawsv1.ClusterNetworkPolicyRuleAction(r.action),
			})
		}
		egress := make([]policyk8sawsv1.ClusterEndpointInfo, 0, len(s.egress))
		for _, r := range s.egress {
			egress = append(egress, policyk8sawsv1.ClusterEndpointInfo{
				CIDR:   policyk8sawsv1.NetworkAddress(r.cidr),
				Action: policyk8sawsv1.ClusterNetworkPolicyRuleAction(r.action),
			})
		}
		fx.store[s.name] = policyk8sawsv1.ClusterPolicyEndpoint{
			ObjectMeta: metav1.ObjectMeta{Name: s.name},
			Spec: policyk8sawsv1.ClusterPolicyEndpointSpec{
				PolicyRef:            policyk8sawsv1.ClusterPolicyReference{Name: s.parent},
				Tier:                 s.tierOrDefault(),
				Priority:             s.priority,
				PodSelectorEndpoints: s.podEndpoints(),
				Ingress:              ingress,
				Egress:               egress,
			},
		}
	}
}

// deleteSlice removes one slice from the API server without reconciling, so the caller
// can drive the delete flow explicitly via reconcileDeleted.
func (fx *cpeFixture) deleteSlice(name string) {
	delete(fx.store, name)
}

// reconcileAll reconciles every slice currently present, which is how the agent reaches
// steady state after a restart or a policy create.
func (fx *cpeFixture) reconcileAll() {
	fx.t.Helper()
	for name := range fx.store {
		require.NoError(fx.t, fx.reconcile(name), "steady-state reconcile of %s", name)
	}
}

func (fx *cpeFixture) reconcile(name string) error {
	cpe := fx.store[name]
	return fx.r.reconcileClusterPolicyEndpoint(context.TODO(), &cpe)
}

// reconcileDeleted drives the cleanup path the agent takes when a slice is gone from the
// API server.
func (fx *cpeFixture) reconcileDeleted(name string) error {
	return fx.r.cleanUpClusterPolicyEndpoint(context.TODO(), controllerruntime.Request{
		NamespacedName: types.NamespacedName{Name: name},
	})
}

// detachContext models the identifier's last local pod leaving the node: DeleteBPFProbes
// tears the probes down once the program FD is no longer shared, so later map writes for
// that identifier have no context to write to.
func (fx *cpeFixture) detachContext(podIdentifiers ...string) {
	if fx.bpf.PodIdentifiersWithoutBPFContext == nil {
		fx.bpf.PodIdentifiersWithoutBPFContext = map[string]bool{}
	}
	for _, id := range podIdentifiers {
		fx.bpf.PodIdentifiersWithoutBPFContext[id] = true
	}
}

func (fx *cpeFixture) reset() { fx.bpf.Reset() }

func (fx *cpeFixture) clusterPolicyCIDRs(podIdentifier string) []string {
	return cidrsOf(fx.bpf.ClusterPolicyIngressByIdentifier[podIdentifier])
}

func (fx *cpeFixture) clusterPolicyEgressCIDRs(podIdentifier string) []string {
	return cidrsOf(fx.bpf.ClusterPolicyEgressByIdentifier[podIdentifier])
}

func (fx *cpeFixture) clusterPolicyState(podIdentifier string) (int, bool) {
	state, ok := fx.bpf.PodStateByIdentifier[ebpf.PodStateKey{
		PodIdentifier: podIdentifier,
		MapKey:        ebpf.CLUSTER_POLICY_POD_STATE_MAP_KEY,
	}]
	return state, ok
}

// assertNoContextErrors is the generic detector for this bug class: a reconcile that
// tried to write eBPF maps for an identifier whose probes are already detached fails
// with "no bpf context registered", and the agent surfaces that as a reconcile error.
func (fx *cpeFixture) assertNoContextErrors(err error) {
	fx.t.Helper()
	assert.NoError(fx.t, err, "reconcile must not fail on an identifier with no eBPF context")
}

func (fx *cpeFixture) assertIdentifierAbsent(podIdentifier string) {
	fx.t.Helper()
	_, ok := fx.r.podIdentifierToClusterPolicyEndpointMap.Load(podIdentifier)
	assert.False(fx.t, ok, "podIdentifierToClusterPolicyEndpointMap must not retain %s", podIdentifier)
}

// ---------------------------------------------------------------------------
// PolicyEndpoint fixture
// ---------------------------------------------------------------------------

type peFixture struct {
	t     *testing.T
	r     *PolicyEndpointsReconciler
	bpf   *ebpf.MockBpfClient
	store map[string]policyk8sawsv1.PolicyEndpoint
}

func newPEFixture(t *testing.T) *peFixture {
	t.Helper()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockClient := mock_client.NewMockClient(ctrl)
	fx := &peFixture{
		t:     t,
		bpf:   &ebpf.MockBpfClient{},
		store: map[string]policyk8sawsv1.PolicyEndpoint{},
	}
	fx.r = NewPolicyEndpointsReconciler(mockClient, fixtureNodeIP, fx.bpf, false)

	mockClient.EXPECT().
		List(gomock.Any(), gomock.AssignableToTypeOf(&policyk8sawsv1.PolicyEndpointList{}), gomock.Any()).
		DoAndReturn(func(_ context.Context, list *policyk8sawsv1.PolicyEndpointList, _ ...client.ListOption) error {
			list.Items = nil
			for _, pe := range fx.store {
				list.Items = append(list.Items, pe)
			}
			return nil
		}).AnyTimes()

	mockClient.EXPECT().
		Get(gomock.Any(), gomock.Any(), gomock.AssignableToTypeOf(&policyk8sawsv1.PolicyEndpoint{}), gomock.Any()).
		DoAndReturn(func(_ context.Context, key types.NamespacedName, obj *policyk8sawsv1.PolicyEndpoint, _ ...client.GetOption) error {
			pe, ok := fx.store[key.Name]
			if !ok {
				return apierrors.NewNotFound(schema.GroupResource{Resource: "policyendpoints"}, key.Name)
			}
			*obj = pe
			return nil
		}).AnyTimes()

	return fx
}

func (fx *peFixture) setSlices(specs ...sliceSpec) {
	fx.store = map[string]policyk8sawsv1.PolicyEndpoint{}
	for _, s := range specs {
		ingress := make([]policyk8sawsv1.EndpointInfo, 0, len(s.ingress))
		for _, r := range s.ingress {
			ingress = append(ingress, policyk8sawsv1.EndpointInfo{CIDR: policyk8sawsv1.NetworkAddress(r.cidr)})
		}
		egress := make([]policyk8sawsv1.EndpointInfo, 0, len(s.egress))
		for _, r := range s.egress {
			egress = append(egress, policyk8sawsv1.EndpointInfo{CIDR: policyk8sawsv1.NetworkAddress(r.cidr)})
		}
		fx.store[s.name] = policyk8sawsv1.PolicyEndpoint{
			ObjectMeta: metav1.ObjectMeta{Name: s.name, Namespace: fixtureNamespace},
			Spec: policyk8sawsv1.PolicyEndpointSpec{
				PolicyRef:            policyk8sawsv1.PolicyReference{Name: s.parent, Namespace: fixtureNamespace},
				PodSelectorEndpoints: s.podEndpoints(),
				Ingress:              ingress,
				Egress:               egress,
			},
		}
	}
}

func (fx *peFixture) deleteSlice(name string) {
	delete(fx.store, name)
}

func (fx *peFixture) reconcileAll() {
	fx.t.Helper()
	for name := range fx.store {
		require.NoError(fx.t, fx.reconcile(name), "steady-state reconcile of %s", name)
	}
}

func (fx *peFixture) reconcile(name string) error {
	pe := fx.store[name]
	return fx.r.reconcilePolicyEndpoint(context.TODO(), &pe)
}

func (fx *peFixture) reconcileDeleted(name string) error {
	return fx.r.cleanUpPolicyEndpoint(context.TODO(), controllerruntime.Request{
		NamespacedName: types.NamespacedName{Name: name, Namespace: fixtureNamespace},
	})
}

func (fx *peFixture) detachContext(podIdentifiers ...string) {
	if fx.bpf.PodIdentifiersWithoutBPFContext == nil {
		fx.bpf.PodIdentifiersWithoutBPFContext = map[string]bool{}
	}
	for _, id := range podIdentifiers {
		fx.bpf.PodIdentifiersWithoutBPFContext[id] = true
	}
}

func (fx *peFixture) reset() { fx.bpf.Reset() }

func (fx *peFixture) ingressCIDRs(podIdentifier string) []string {
	return cidrsOf(fx.bpf.IngressByIdentifier[podIdentifier])
}

func (fx *peFixture) egressCIDRs(podIdentifier string) []string {
	return cidrsOf(fx.bpf.EgressByIdentifier[podIdentifier])
}

func (fx *peFixture) podState(podIdentifier string) (int, bool) {
	state, ok := fx.bpf.PodStateByIdentifier[ebpf.PodStateKey{
		PodIdentifier: podIdentifier,
		MapKey:        ebpf.POD_STATE_MAP_KEY,
	}]
	return state, ok
}

func (fx *peFixture) assertIdentifierAbsent(podIdentifier string) {
	fx.t.Helper()
	_, ok := fx.r.podIdentifierToPolicyEndpointMap.Load(podIdentifier)
	assert.False(fx.t, ok, "podIdentifierToPolicyEndpointMap must not retain %s", podIdentifier)
}

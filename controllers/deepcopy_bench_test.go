package controllers

import (
	"context"
	"fmt"
	"testing"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// cacheReader mimics the controller-runtime cache reader: objects are deep copied on
// read unless the caller passes client.UnsafeDisableDeepCopy, in which case the caller
// gets a shallow copy that shares slices with the stored ("cached") object.
// forceDeepCopy ignores UnsafeDisableDeepCopy to reproduce the pre-change behavior.
type cacheReader struct {
	client.Client
	pes           map[types.NamespacedName]*policyk8sawsv1.PolicyEndpoint
	cpes          map[string]*policyk8sawsv1.ClusterPolicyEndpoint
	forceDeepCopy bool
}

func (c *cacheReader) unsafe(opts []client.GetOption) bool {
	for _, o := range opts {
		if o == client.UnsafeDisableDeepCopy {
			return !c.forceDeepCopy
		}
	}
	return false
}

func (c *cacheReader) unsafeList(opts []client.ListOption) bool {
	for _, o := range opts {
		if o == client.UnsafeDisableDeepCopy {
			return !c.forceDeepCopy
		}
	}
	return false
}

func (c *cacheReader) Get(_ context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	unsafe := c.unsafe(opts)
	switch out := obj.(type) {
	case *policyk8sawsv1.PolicyEndpoint:
		pe, ok := c.pes[key]
		if !ok {
			return apierrors.NewNotFound(schema.GroupResource{Resource: "policyendpoints"}, key.Name)
		}
		if unsafe {
			*out = *pe
		} else {
			*out = *pe.DeepCopy()
		}
	case *policyk8sawsv1.ClusterPolicyEndpoint:
		cpe, ok := c.cpes[key.Name]
		if !ok {
			return apierrors.NewNotFound(schema.GroupResource{Resource: "clusterpolicyendpoints"}, key.Name)
		}
		if unsafe {
			*out = *cpe
		} else {
			*out = *cpe.DeepCopy()
		}
	default:
		return fmt.Errorf("cacheReader: unsupported type %T", obj)
	}
	return nil
}

func (c *cacheReader) List(_ context.Context, list client.ObjectList, opts ...client.ListOption) error {
	lo := &client.ListOptions{}
	lo.ApplyOptions(opts)
	unsafe := c.unsafeList(opts)
	switch out := list.(type) {
	case *policyk8sawsv1.PolicyEndpointList:
		out.Items = out.Items[:0]
		for _, pe := range c.pes {
			if lo.Namespace != "" && pe.Namespace != lo.Namespace {
				continue
			}
			if unsafe {
				out.Items = append(out.Items, *pe)
			} else {
				out.Items = append(out.Items, *pe.DeepCopy())
			}
		}
	case *policyk8sawsv1.ClusterPolicyEndpointList:
		out.Items = out.Items[:0]
		for _, cpe := range c.cpes {
			if unsafe {
				out.Items = append(out.Items, *cpe)
			} else {
				out.Items = append(out.Items, *cpe.DeepCopy())
			}
		}
	default:
		return fmt.Errorf("cacheReader: unsupported type %T", list)
	}
	return nil
}

const benchNodeIP = "192.168.0.1"

// buildPEs creates numPEs PolicyEndpoints of one parent NP, each with endpointsPerPE ingress
// and egress CIDRs and podsPerPE selected pods, the first of which is local to the node.
func buildPEs(namespace string, numPEs, endpointsPerPE, podsPerPE int) map[types.NamespacedName]*policyk8sawsv1.PolicyEndpoint {
	tcp := corev1.ProtocolTCP
	port := int32(8080)
	pes := make(map[types.NamespacedName]*policyk8sawsv1.PolicyEndpoint, numPEs)
	for i := 0; i < numPEs; i++ {
		pe := &policyk8sawsv1.PolicyEndpoint{}
		pe.Name = fmt.Sprintf("np-%d", i)
		pe.Namespace = namespace
		pe.Spec.PolicyRef = policyk8sawsv1.PolicyReference{Name: "np", Namespace: namespace}
		for j := 0; j < endpointsPerPE; j++ {
			ep := policyk8sawsv1.EndpointInfo{
				CIDR:  policyk8sawsv1.NetworkAddress(fmt.Sprintf("10.%d.%d.%d", i%256, j/256, j%256)),
				Ports: []policyk8sawsv1.Port{{Protocol: &tcp, Port: &port}},
			}
			pe.Spec.Ingress = append(pe.Spec.Ingress, ep)
			pe.Spec.Egress = append(pe.Spec.Egress, ep)
		}
		for j := 0; j < podsPerPE; j++ {
			hostIP := "192.168.0.2"
			if j == 0 {
				hostIP = benchNodeIP
			}
			pe.Spec.PodSelectorEndpoints = append(pe.Spec.PodSelectorEndpoints, policyk8sawsv1.PodEndpoint{
				HostIP:    policyk8sawsv1.NetworkAddress(hostIP),
				PodIP:     policyk8sawsv1.NetworkAddress(fmt.Sprintf("172.16.%d.%d", i%256, j%256)),
				Name:      fmt.Sprintf("pod-%d-%d", i, j),
				Namespace: namespace,
			})
		}
		pes[types.NamespacedName{Namespace: namespace, Name: pe.Name}] = pe
	}
	return pes
}

// BenchmarkPEReconcileReads measures allocations of the PolicyEndpoint read paths: listing
// and fetching sibling PEs (deriveTargetPodsForParentNP) and deriving firewall rules for a
// local pod (deriveIngressAndEgressFirewallRules).
//
//	go test ./controllers/ -run '^$' -bench BenchmarkPEReconcileReads -benchmem
func BenchmarkPEReconcileReads(b *testing.B) {
	for _, size := range []struct{ pes, endpoints, pods int }{
		{10, 100, 100},
		{100, 1000, 100},
	} {
		for _, mode := range []struct {
			name          string
			forceDeepCopy bool
		}{{"deepcopy", true}, {"nodeepcopy", false}} {
			name := fmt.Sprintf("pes=%d/endpoints=%d/pods=%d/%s", size.pes, size.endpoints, size.pods, mode.name)
			b.Run(name, func(b *testing.B) {
				reader := &cacheReader{pes: buildPEs("ns", size.pes, size.endpoints, size.pods), forceDeepCopy: mode.forceDeepCopy}
				r := NewPolicyEndpointsReconciler(reader, benchNodeIP, nil, false)
				ctx := context.Background()
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, podIdentifiers, _, _, _, err := r.deriveTargetPodsForParentNP(ctx, "np", "ns", "np-0")
					if err != nil {
						b.Fatal(err)
					}
					for podIdentifier := range podIdentifiers {
						if _, _, _, _, err := r.deriveIngressAndEgressFirewallRules(ctx, podIdentifier, "ns", "np-0", false); err != nil {
							b.Fatal(err)
						}
					}
				}
			})
		}
	}
}

// TestDeriveFirewallRules_DoesNotWriteIntoCachedSlices guards the UnsafeDisableDeepCopy read
// in deriveIngressAndEgressFirewallRules: the rule processor appends to L4Info and Except,
// which must not write into spare capacity of the Ports/Except slices owned by the informer
// cache.
func TestDeriveFirewallRules_DoesNotWriteIntoCachedSlices(t *testing.T) {
	for _, direction := range []string{"ingress", "egress"} {
		t.Run(direction, func(t *testing.T) {
			tcp := corev1.ProtocolTCP
			port80, port443 := int32(80), int32(443)
			// Spare capacity, as left behind by JSON decoding into the cache.
			cachedPorts := make([]policyk8sawsv1.Port, 1, 4)
			cachedPorts[0] = policyk8sawsv1.Port{Protocol: &tcp, Port: &port80}
			cachedExcept := make([]policyk8sawsv1.NetworkAddress, 1, 4)
			cachedExcept[0] = "10.0.0.128/26"

			endpoints := []policyk8sawsv1.EndpointInfo{
				{CIDR: "10.0.0.0/24", Except: []policyk8sawsv1.NetworkAddress{"10.0.0.192/26"}, Ports: []policyk8sawsv1.Port{{Protocol: &tcp, Port: &port443}}},
				// Same CIDR again: the rule processor merges by appending the earlier rule's
				// L4Info and Except onto this one.
				{CIDR: "10.0.0.0/24", Except: cachedExcept, Ports: cachedPorts},
			}
			pe := &policyk8sawsv1.PolicyEndpoint{}
			pe.Name, pe.Namespace = "np-abcd", "ns"
			pe.Spec.PolicyRef = policyk8sawsv1.PolicyReference{Name: "np", Namespace: "ns"}
			if direction == "ingress" {
				pe.Spec.Ingress = endpoints
			} else {
				pe.Spec.Egress = endpoints
			}
			pe.Spec.PodSelectorEndpoints = []policyk8sawsv1.PodEndpoint{{HostIP: benchNodeIP, PodIP: "172.16.0.1", Name: "pod", Namespace: "ns"}}

			reader := &cacheReader{pes: map[types.NamespacedName]*policyk8sawsv1.PolicyEndpoint{{Namespace: "ns", Name: pe.Name}: pe}}
			r := NewPolicyEndpointsReconciler(reader, benchNodeIP, nil, false)
			ctx := context.Background()

			_, podIdentifiers, _, _, _, err := r.deriveTargetPodsForParentNP(ctx, "np", "ns", pe.Name)
			assert.NoError(t, err)
			assert.Len(t, podIdentifiers, 1)
			for podIdentifier := range podIdentifiers {
				ingressRules, egressRules, _, _, err := r.deriveIngressAndEgressFirewallRules(ctx, podIdentifier, "ns", pe.Name, false)
				assert.NoError(t, err)
				rules := ingressRules
				if direction == "egress" {
					rules = egressRules
				}
				assert.Len(t, rules, 2)
				_, err = fwrp.NewFirewallRuleProcessor(benchNodeIP, "/32", false).ComputeMapEntriesFromEndpointRules(rules)
				assert.NoError(t, err)
			}

			assert.Len(t, endpoints[1].Ports, 1)
			assert.Len(t, endpoints[1].Except, 1)
			for i, p := range cachedPorts[:cap(cachedPorts)][1:] {
				assert.Equal(t, policyk8sawsv1.Port{}, p, "cached Ports backing array overwritten at index %d", i+1)
			}
			for i, e := range cachedExcept[:cap(cachedExcept)][1:] {
				assert.Equal(t, policyk8sawsv1.NetworkAddress(""), e, "cached Except backing array overwritten at index %d", i+1)
			}
		})
	}
}

// cachedPorts returns Ports with spare capacity, as left behind by JSON decoding into the
// cache, whose Protocol/Port/EndPort pointers are owned by the cached object.
func cachedPorts(protocol corev1.Protocol, port, endPort int32) []policyk8sawsv1.Port {
	ports := make([]policyk8sawsv1.Port, 1, 4)
	ports[0] = policyk8sawsv1.Port{Protocol: &protocol, Port: &port}
	if endPort != 0 {
		ports[0].EndPort = &endPort
	}
	return ports
}

// TestFirewallRuleDerivation_LeavesCachedObjectsUnchanged guards the UnsafeDisableDeepCopy reads
// as a whole: everything reachable from a cached PE/CPE -- slice elements and the pointers
// inside each Port included -- must be byte-for-byte unchanged after deriving and computing
// firewall rules from it. The rules use the same CIDR twice and nested CIDRs so the rule
// processor's merge and L4 inheritance paths run, across two sibling slices.
func TestFirewallRuleDerivation_LeavesCachedObjectsUnchanged(t *testing.T) {
	localPod := policyk8sawsv1.PodEndpoint{HostIP: benchNodeIP, PodIP: "172.16.0.1", Name: "pod", Namespace: "ns"}

	t.Run("PolicyEndpoint", func(t *testing.T) {
		endpoints := func() []policyk8sawsv1.EndpointInfo {
			return []policyk8sawsv1.EndpointInfo{
				{CIDR: "10.0.0.0/16", Except: append(make([]policyk8sawsv1.NetworkAddress, 0, 4), "10.0.255.0/24"), Ports: cachedPorts(corev1.ProtocolTCP, 80, 90)},
				{CIDR: "10.0.0.0/24", Except: append(make([]policyk8sawsv1.NetworkAddress, 0, 4), "10.0.0.128/26"), Ports: cachedPorts(corev1.ProtocolUDP, 53, 0)},
				{CIDR: "10.0.0.0/24", Ports: cachedPorts(corev1.ProtocolTCP, 443, 0)},
				{CIDR: "10.0.0.7"},
			}
		}
		pes := map[types.NamespacedName]*policyk8sawsv1.PolicyEndpoint{}
		for _, name := range []string{"np-aaaa", "np-bbbb"} {
			pe := &policyk8sawsv1.PolicyEndpoint{}
			pe.Name, pe.Namespace = name, "ns"
			pe.Spec.PolicyRef = policyk8sawsv1.PolicyReference{Name: "np", Namespace: "ns"}
			pe.Spec.Ingress, pe.Spec.Egress = endpoints(), endpoints()
			pe.Spec.PodSelectorEndpoints = []policyk8sawsv1.PodEndpoint{localPod}
			pes[types.NamespacedName{Namespace: "ns", Name: name}] = pe
		}
		snapshots := map[types.NamespacedName]*policyk8sawsv1.PolicyEndpoint{}
		for k, pe := range pes {
			snapshots[k] = pe.DeepCopy()
		}

		r := NewPolicyEndpointsReconciler(&cacheReader{pes: pes}, benchNodeIP, nil, false)
		ctx := context.Background()
		_, podIdentifiers, _, _, _, err := r.deriveTargetPodsForParentNP(ctx, "np", "ns", "np-aaaa")
		assert.NoError(t, err)
		assert.Len(t, podIdentifiers, 1)
		processor := fwrp.NewFirewallRuleProcessor(benchNodeIP, "/32", false)
		for podIdentifier := range podIdentifiers {
			// Reconcile path.
			ingressRules, egressRules, _, _, err := r.deriveIngressAndEgressFirewallRules(ctx, podIdentifier, "ns", "np-aaaa", false)
			assert.NoError(t, err)
			assert.NotEmpty(t, ingressRules)
			for _, rules := range [][]fwrp.EbpfFirewallRules{ingressRules, egressRules} {
				_, err = processor.ComputeMapEntriesFromEndpointRules(rules)
				assert.NoError(t, err)
			}
			// CNI RPC path.
			ingressRules, egressRules, err = r.DeriveFireWallRulesPerPodIdentifier(podIdentifier, "ns")
			assert.NoError(t, err)
			for _, rules := range [][]fwrp.EbpfFirewallRules{ingressRules, egressRules} {
				_, err = processor.ComputeMapEntriesFromEndpointRules(rules)
				assert.NoError(t, err)
			}
		}

		for k, pe := range pes {
			assert.Equal(t, snapshots[k], pe, "cached PolicyEndpoint %s modified", k)
		}
	})

	t.Run("ClusterPolicyEndpoint", func(t *testing.T) {
		endpoints := func() []policyk8sawsv1.ClusterEndpointInfo {
			return []policyk8sawsv1.ClusterEndpointInfo{
				{CIDR: "10.0.0.0/16", Action: policyk8sawsv1.ClusterNetworkPolicyRuleActionAccept, Ports: cachedPorts(corev1.ProtocolTCP, 80, 90)},
				{CIDR: "10.0.0.0/24", Action: policyk8sawsv1.ClusterNetworkPolicyRuleActionDeny, Ports: cachedPorts(corev1.ProtocolUDP, 53, 0)},
				{CIDR: "10.0.0.0/24", Action: policyk8sawsv1.ClusterNetworkPolicyRuleActionPass, Ports: cachedPorts(corev1.ProtocolTCP, 443, 0)},
				{CIDR: "10.0.0.7", Action: policyk8sawsv1.ClusterNetworkPolicyRuleActionDeny},
			}
		}
		cpes := map[string]*policyk8sawsv1.ClusterPolicyEndpoint{}
		for i, name := range []string{"cnp-aaaa", "cnp-bbbb"} {
			cpe := &policyk8sawsv1.ClusterPolicyEndpoint{}
			cpe.Name = name
			cpe.Spec.PolicyRef = policyk8sawsv1.ClusterPolicyReference{Name: "cnp"}
			cpe.Spec.Tier = policyk8sawsv1.AdminTier
			if i == 1 {
				cpe.Spec.Tier = policyk8sawsv1.BaselineTier
			}
			cpe.Spec.Priority = int32(10 + i)
			cpe.Spec.Ingress, cpe.Spec.Egress = endpoints(), endpoints()
			cpe.Spec.PodSelectorEndpoints = []policyk8sawsv1.PodEndpoint{localPod}
			cpes[name] = cpe
		}
		snapshots := map[string]*policyk8sawsv1.ClusterPolicyEndpoint{}
		for k, cpe := range cpes {
			snapshots[k] = cpe.DeepCopy()
		}

		r := NewClusterPolicyEndpointsReconciler(&cacheReader{cpes: cpes}, benchNodeIP, nil)
		ctx := context.Background()
		_, podIdentifiers, _, _, _, err := r.deriveTargetPodsForParentCNP(ctx, "cnp", "cnp-aaaa")
		assert.NoError(t, err)
		assert.Len(t, podIdentifiers, 1)
		processor := fwrp.NewFirewallRuleProcessor(benchNodeIP, "/32", false)
		for podIdentifier := range podIdentifiers {
			ingressRules, egressRules, err := r.DeriveClusterPolicyFireWallRulesPerPodIdentifier(ctx, podIdentifier)
			assert.NoError(t, err)
			assert.NotEmpty(t, ingressRules)
			for _, rules := range [][]fwrp.EbpfFirewallRules{ingressRules, egressRules} {
				_, err = processor.ComputeClusterPolicyMapEntriesFromEndpointRules(rules)
				assert.NoError(t, err)
			}
		}

		for k, cpe := range cpes {
			assert.Equal(t, snapshots[k], cpe, "cached ClusterPolicyEndpoint %s modified", k)
		}
	})
}

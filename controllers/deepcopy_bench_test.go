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
	pe, ok := c.pes[key]
	if !ok {
		return apierrors.NewNotFound(schema.GroupResource{Resource: "policyendpoints"}, key.Name)
	}
	if c.unsafe(opts) {
		*obj.(*policyk8sawsv1.PolicyEndpoint) = *pe
	} else {
		*obj.(*policyk8sawsv1.PolicyEndpoint) = *pe.DeepCopy()
	}
	return nil
}

func (c *cacheReader) List(_ context.Context, list client.ObjectList, opts ...client.ListOption) error {
	lo := &client.ListOptions{}
	lo.ApplyOptions(opts)
	unsafe := c.unsafeList(opts)
	out := list.(*policyk8sawsv1.PolicyEndpointList)
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
// in deriveIngressAndEgressFirewallRules: the rule processor appends to L4Info, which must
// not write into spare capacity of the Ports slice owned by the informer cache.
func TestDeriveFirewallRules_DoesNotWriteIntoCachedSlices(t *testing.T) {
	tcp := corev1.ProtocolTCP
	port80, port443 := int32(80), int32(443)
	// Spare capacity, as left behind by JSON decoding into the cache.
	cachedPorts := make([]policyk8sawsv1.Port, 1, 4)
	cachedPorts[0] = policyk8sawsv1.Port{Protocol: &tcp, Port: &port80}

	pe := &policyk8sawsv1.PolicyEndpoint{}
	pe.Name, pe.Namespace = "np-abcd", "ns"
	pe.Spec.PolicyRef = policyk8sawsv1.PolicyReference{Name: "np", Namespace: "ns"}
	pe.Spec.Ingress = []policyk8sawsv1.EndpointInfo{
		{CIDR: "10.0.0.1", Ports: []policyk8sawsv1.Port{{Protocol: &tcp, Port: &port443}}},
		// Same CIDR again: the rule processor merges by appending the earlier rule's L4Info onto this one.
		{CIDR: "10.0.0.1", Ports: cachedPorts},
	}
	pe.Spec.PodSelectorEndpoints = []policyk8sawsv1.PodEndpoint{{HostIP: benchNodeIP, PodIP: "172.16.0.1", Name: "pod", Namespace: "ns"}}

	reader := &cacheReader{pes: map[types.NamespacedName]*policyk8sawsv1.PolicyEndpoint{{Namespace: "ns", Name: pe.Name}: pe}}
	r := NewPolicyEndpointsReconciler(reader, benchNodeIP, nil, false)
	ctx := context.Background()

	_, podIdentifiers, _, _, _, err := r.deriveTargetPodsForParentNP(ctx, "np", "ns", pe.Name)
	assert.NoError(t, err)
	assert.Len(t, podIdentifiers, 1)
	for podIdentifier := range podIdentifiers {
		ingressRules, _, _, _, err := r.deriveIngressAndEgressFirewallRules(ctx, podIdentifier, "ns", pe.Name, false)
		assert.NoError(t, err)
		_, err = fwrp.NewFirewallRuleProcessor(benchNodeIP, "/32", false).ComputeMapEntriesFromEndpointRules(ingressRules)
		assert.NoError(t, err)
	}

	assert.Len(t, pe.Spec.Ingress[1].Ports, 1)
	for i, p := range cachedPorts[:cap(cachedPorts)][1:] {
		assert.Equal(t, policyk8sawsv1.Port{}, p, "cached Ports backing array overwritten at index %d", i+1)
	}
}

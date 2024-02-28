package manifest

import (
	network "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type NetworkPolicyBuilder struct {
	namespace    string
	name         string
	podSelector  map[string]string
	egressRules  []network.NetworkPolicyEgressRule
	ingressRules []network.NetworkPolicyIngressRule
}

func (n *NetworkPolicyBuilder) Build() *network.NetworkPolicy {

	netpol := &network.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      n.name,
			Namespace: n.namespace,
		},
		Spec: network.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: n.podSelector,
			},
		},
	}

	if len(n.ingressRules) > 0 {
		netpol.Spec.PolicyTypes = append(netpol.Spec.PolicyTypes, network.PolicyTypeIngress)
		netpol.Spec.Ingress = n.ingressRules
	}

	if len(n.egressRules) > 0 {
		netpol.Spec.PolicyTypes = append(netpol.Spec.PolicyTypes, network.PolicyTypeEgress)
		netpol.Spec.Egress = n.egressRules
	}

	return netpol
}

func NewNetworkPolicyBuilder() *NetworkPolicyBuilder {
	return &NetworkPolicyBuilder{
		namespace:    "default",
		name:         "default-network-policy",
		podSelector:  map[string]string{},
		egressRules:  []network.NetworkPolicyEgressRule{},
		ingressRules: []network.NetworkPolicyIngressRule{},
	}
}

func (n *NetworkPolicyBuilder) Name(name string) *NetworkPolicyBuilder {
	n.name = name
	return n
}

func (n *NetworkPolicyBuilder) Namespace(namespace string) *NetworkPolicyBuilder {
	n.namespace = namespace
	return n
}

func (n *NetworkPolicyBuilder) PodSelector(labelKey string, labelValue string) *NetworkPolicyBuilder {
	n.podSelector[labelKey] = labelValue
	return n
}

func (n *NetworkPolicyBuilder) AddEgressRule(egressRule network.NetworkPolicyEgressRule) *NetworkPolicyBuilder {
	n.egressRules = append(n.egressRules, egressRule)
	return n
}

func (n *NetworkPolicyBuilder) AddIngressRule(ingressRule network.NetworkPolicyIngressRule) *NetworkPolicyBuilder {
	n.ingressRules = append(n.ingressRules, ingressRule)
	return n
}

package manifest

import (
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type IngressRuleBuilder struct {
	From []network.NetworkPolicyPeer
	Port []network.NetworkPolicyPort
}

type EgressRuleBuilder struct {
	To   []network.NetworkPolicyPeer
	Port []network.NetworkPolicyPort
}

func NewIngressRuleBuilder() *IngressRuleBuilder {
	return &IngressRuleBuilder{
		From: []network.NetworkPolicyPeer{},
		Port: []network.NetworkPolicyPort{},
	}
}

func (ir *IngressRuleBuilder) Build() network.NetworkPolicyIngressRule {
	obj := network.NetworkPolicyIngressRule{}
	if len(ir.From) > 0 {
		obj.From = ir.From
	}
	if len(ir.Port) > 0 {
		obj.Ports = ir.Port
	}
	return obj
}

func (ir *IngressRuleBuilder) AddPeer(nsSelector map[string]string, podSelector map[string]string, acceptCIDR string) *IngressRuleBuilder {
	peerObj := network.NetworkPolicyPeer{}

	if podSelector != nil {
		peerObj.PodSelector = &metav1.LabelSelector{
			MatchLabels: podSelector,
		}
	}

	if nsSelector != nil {
		peerObj.NamespaceSelector = &metav1.LabelSelector{
			MatchLabels: nsSelector,
		}
	}

	if acceptCIDR != "" {
		peerObj.IPBlock = &network.IPBlock{
			CIDR: acceptCIDR,
		}
	}
	ir.From = append(ir.From, peerObj)
	return ir
}

func (ir *IngressRuleBuilder) AddPort(port int, protocol v1.Protocol) *IngressRuleBuilder {
	portObj := network.NetworkPolicyPort{
		Protocol: &protocol,
	}

	if port != -1 {
		val := intstr.FromInt(port)
		portObj.Port = &val
	}

	ir.Port = append(ir.Port, portObj)
	return ir
}

func NewEgressRuleBuilder() *EgressRuleBuilder {
	return &EgressRuleBuilder{
		To:   []network.NetworkPolicyPeer{},
		Port: []network.NetworkPolicyPort{},
	}
}

func (er *EgressRuleBuilder) Build() network.NetworkPolicyEgressRule {
	obj := network.NetworkPolicyEgressRule{}
	if len(er.To) > 0 {
		obj.To = er.To
	}
	if len(er.Port) > 0 {
		obj.Ports = er.Port
	}
	return obj
}

func (er *EgressRuleBuilder) AddPeer(nsSelector map[string]string, podSelector map[string]string, acceptCIDR string) *EgressRuleBuilder {
	peerObj := network.NetworkPolicyPeer{}
	if podSelector != nil {
		peerObj.PodSelector = &metav1.LabelSelector{
			MatchLabels: podSelector,
		}
	}
	if nsSelector != nil {
		peerObj.NamespaceSelector = &metav1.LabelSelector{
			MatchLabels: nsSelector,
		}
	}

	if acceptCIDR != "" {
		peerObj.IPBlock = &network.IPBlock{
			CIDR: acceptCIDR,
		}
	}

	er.To = append(er.To, peerObj)
	return er
}

func (er *EgressRuleBuilder) AddPort(port int, protocol v1.Protocol) *EgressRuleBuilder {
	portObj := network.NetworkPolicyPort{
		Protocol: &protocol,
	}

	if port != -1 {
		val := intstr.FromInt(port)
		portObj.Port = &val
	}

	er.Port = append(er.Port, portObj)
	return er
}

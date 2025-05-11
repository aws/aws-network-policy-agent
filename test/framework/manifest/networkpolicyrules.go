package manifest

import (
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// IPBlock holds one CIDR plus its except list.
type IPBlock struct {
	CIDR   string
	Except []string
}

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

// AddIPBlocks appends one or more IPBlock-based peers.
func (ir *IngressRuleBuilder) AddIPBlocks(nsSelector map[string]string, podSelector map[string]string, blocks ...IPBlock) *IngressRuleBuilder {
	for _, blk := range blocks {
		peer := network.NetworkPolicyPeer{}
		if podSelector != nil {
			peer.PodSelector = &metav1.LabelSelector{MatchLabels: podSelector}
		}
		if nsSelector != nil {
			peer.NamespaceSelector = &metav1.LabelSelector{MatchLabels: nsSelector}
		}
		if blk.CIDR != "" {
			peer.IPBlock = &network.IPBlock{
				CIDR:   blk.CIDR,
				Except: blk.Except,
			}
		}
		ir.From = append(ir.From, peer)
	}
	return ir
}

// AddPeer creates a single IPBlock peer from cidr and optional except lists.
func (ir *IngressRuleBuilder) AddPeer(nsSelector map[string]string, podSelector map[string]string, cidr string, except ...string) *IngressRuleBuilder {
	blk := IPBlock{CIDR: cidr, Except: except}
	return ir.AddIPBlocks(nsSelector, podSelector, blk)
}

func (ir *IngressRuleBuilder) AddPort(port int, protocol v1.Protocol) *IngressRuleBuilder {
	portObj := network.NetworkPolicyPort{}

	if string(protocol) != "" {
		portObj.Protocol = &protocol
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

// AddPeer creates a single IPBlock peer from cidr and optional except lists.
func (er *EgressRuleBuilder) AddPeer(nsSelector map[string]string, podSelector map[string]string, cidr string, except ...string) *EgressRuleBuilder {
	blk := IPBlock{CIDR: cidr, Except: except}
	return er.AddIPBlocks(nsSelector, podSelector, blk)
}

func (er *EgressRuleBuilder) AddPort(port int, protocol v1.Protocol) *EgressRuleBuilder {
	portObj := network.NetworkPolicyPort{}

	if string(protocol) != "" {
		portObj.Protocol = &protocol
	}

	if port != -1 {
		val := intstr.FromInt(port)
		portObj.Port = &val
	}

	er.Port = append(er.Port, portObj)
	return er
}

// AddIPBlocks appends one or more IPBlock-based peers.
func (er *EgressRuleBuilder) AddIPBlocks(nsSelector map[string]string, podSelector map[string]string, blocks ...IPBlock) *EgressRuleBuilder {
	for _, blk := range blocks {
		peer := network.NetworkPolicyPeer{}
		if podSelector != nil {
			peer.PodSelector = &metav1.LabelSelector{MatchLabels: podSelector}
		}
		if nsSelector != nil {
			peer.NamespaceSelector = &metav1.LabelSelector{MatchLabels: nsSelector}
		}
		if blk.CIDR != "" {
			peer.IPBlock = &network.IPBlock{
				CIDR:   blk.CIDR,
				Except: blk.Except,
			}
		}
		er.To = append(er.To, peer)
	}
	return er
}

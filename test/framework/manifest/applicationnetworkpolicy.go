package manifest

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type ApplicationNetworkPolicyBuilder struct {
	namespace    string
	name         string
	podSelector  map[string]string
	ingressRules []map[string]interface{}
	egressRules  []map[string]interface{}
	policyTypes  []string
}

func NewApplicationNetworkPolicyBuilder() *ApplicationNetworkPolicyBuilder {
	return &ApplicationNetworkPolicyBuilder{
		namespace:    "default",
		name:         "default-app-policy",
		podSelector:  map[string]string{},
		ingressRules: []map[string]interface{}{},
		egressRules:  []map[string]interface{}{},
		policyTypes:  []string{},
	}
}

func (a *ApplicationNetworkPolicyBuilder) Name(name string) *ApplicationNetworkPolicyBuilder {
	a.name = name
	return a
}

func (a *ApplicationNetworkPolicyBuilder) Namespace(namespace string) *ApplicationNetworkPolicyBuilder {
	a.namespace = namespace
	return a
}

func (a *ApplicationNetworkPolicyBuilder) PodSelector(labelKey string, labelValue string) *ApplicationNetworkPolicyBuilder {
	a.podSelector[labelKey] = labelValue
	return a
}

func (a *ApplicationNetworkPolicyBuilder) AddIngressRule(rule map[string]interface{}) *ApplicationNetworkPolicyBuilder {
	a.ingressRules = append(a.ingressRules, rule)
	return a
}

func (a *ApplicationNetworkPolicyBuilder) AddEgressRule(rule map[string]interface{}) *ApplicationNetworkPolicyBuilder {
	a.egressRules = append(a.egressRules, rule)
	return a
}

func (a *ApplicationNetworkPolicyBuilder) SetPolicyTypes(policyTypes []string) *ApplicationNetworkPolicyBuilder {
	a.policyTypes = policyTypes
	return a
}

func (a *ApplicationNetworkPolicyBuilder) Build() *unstructured.Unstructured {
	anp := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.k8s.aws/v1alpha1",
			"kind":       "ApplicationNetworkPolicy",
			"metadata": map[string]interface{}{
				"name":      a.name,
				"namespace": a.namespace,
			},
			"spec": map[string]interface{}{
				"podSelector": map[string]interface{}{
					"matchLabels": a.podSelector,
				},
			},
		},
	}

	spec := anp.Object["spec"].(map[string]interface{})

	if len(a.policyTypes) > 0 {
		spec["policyTypes"] = a.policyTypes
	}

	if len(a.ingressRules) > 0 {
		spec["ingress"] = a.ingressRules
	}

	if len(a.egressRules) > 0 {
		spec["egress"] = a.egressRules
	}

	return anp
}

// Helper builders for ApplicationNetworkPolicy egress rules
type ApplicationNetworkPolicyEgressRuleBuilder struct {
	ports []map[string]interface{}
}

func NewApplicationEgressRuleBuilder() *ApplicationNetworkPolicyEgressRuleBuilder {
	return &ApplicationNetworkPolicyEgressRuleBuilder{
		ports: []map[string]interface{}{},
	}
}

func (r *ApplicationNetworkPolicyEgressRuleBuilder) AddPort(port int32, protocol string) *ApplicationNetworkPolicyEgressRuleBuilder {
	r.ports = append(r.ports, map[string]interface{}{
		"port":     port,
		"protocol": protocol,
	})
	return r
}

func (r *ApplicationNetworkPolicyEgressRuleBuilder) BuildEgressRule(to []map[string]interface{}) map[string]interface{} {
	rule := map[string]interface{}{
		"to": to,
	}

	if len(r.ports) > 0 {
		rule["ports"] = r.ports
	}

	return rule
}

// Helper functions for ApplicationNetworkPolicy peer builders
func NewApplicationPodsPeer(namespaceSelector, podSelector map[string]string) map[string]interface{} {
	peer := map[string]interface{}{}

	if len(namespaceSelector) > 0 {
		peer["namespaceSelector"] = map[string]interface{}{
			"matchLabels": namespaceSelector,
		}
	}

	if len(podSelector) > 0 {
		peer["podSelector"] = map[string]interface{}{
			"matchLabels": podSelector,
		}
	}

	return peer
}

func NewApplicationIPBlockPeer(cidr string, except []string) map[string]interface{} {
	ipBlock := map[string]interface{}{
		"cidr": cidr,
	}

	if len(except) > 0 {
		ipBlock["except"] = except
	}

	return map[string]interface{}{
		"ipBlock": ipBlock,
	}
}

func NewApplicationDomainNamesPeer(domains []string) map[string]interface{} {
	return map[string]interface{}{
		"domainNames": domains,
	}
}

package manifest

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type ClusterNetworkPolicyBuilder struct {
	name         string
	priority     int32
	tier         string
	subject      map[string]interface{}
	ingressRules []map[string]interface{}
	egressRules  []map[string]interface{}
}

func NewClusterNetworkPolicyBuilder() *ClusterNetworkPolicyBuilder {
	return &ClusterNetworkPolicyBuilder{
		name:         "default-cluster-policy",
		priority:     100,
		tier:         "Admin",
		ingressRules: []map[string]interface{}{},
		egressRules:  []map[string]interface{}{},
	}
}

func (c *ClusterNetworkPolicyBuilder) Name(name string) *ClusterNetworkPolicyBuilder {
	c.name = name
	return c
}

func (c *ClusterNetworkPolicyBuilder) Priority(priority int32) *ClusterNetworkPolicyBuilder {
	c.priority = priority
	return c
}

func (c *ClusterNetworkPolicyBuilder) Tier(tier string) *ClusterNetworkPolicyBuilder {
	c.tier = tier
	return c
}

func (c *ClusterNetworkPolicyBuilder) SubjectPods(namespaceSelector, podSelector map[string]string) *ClusterNetworkPolicyBuilder {
	c.subject = map[string]interface{}{
		"pods": map[string]interface{}{
			"namespaceSelector": map[string]interface{}{
				"matchLabels": namespaceSelector,
			},
			"podSelector": map[string]interface{}{
				"matchLabels": podSelector,
			},
		},
	}
	return c
}

func (c *ClusterNetworkPolicyBuilder) SubjectNamespaces(namespaceSelector map[string]string) *ClusterNetworkPolicyBuilder {
	c.subject = map[string]interface{}{
		"namespaces": map[string]interface{}{
			"matchLabels": namespaceSelector,
		},
	}
	return c
}

func (c *ClusterNetworkPolicyBuilder) AddIngressRule(rule map[string]interface{}) *ClusterNetworkPolicyBuilder {
	c.ingressRules = append(c.ingressRules, rule)
	return c
}

func (c *ClusterNetworkPolicyBuilder) AddEgressRule(rule map[string]interface{}) *ClusterNetworkPolicyBuilder {
	c.egressRules = append(c.egressRules, rule)
	return c
}

func (c *ClusterNetworkPolicyBuilder) Build() *unstructured.Unstructured {
	cnp := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.k8s.aws/v1alpha1",
			"kind":       "ClusterNetworkPolicy",
			"metadata": map[string]interface{}{
				"name": c.name,
			},
			"spec": map[string]interface{}{
				"priority": c.priority,
				"tier":     c.tier,
				"subject":  c.subject,
			},
		},
	}

	spec := cnp.Object["spec"].(map[string]interface{})

	if len(c.ingressRules) > 0 {
		spec["ingress"] = c.ingressRules
	}

	if len(c.egressRules) > 0 {
		spec["egress"] = c.egressRules
	}

	return cnp
}

// Helper builders for rules
type ClusterNetworkPolicyRuleBuilder struct {
	name   string
	action string
	ports  []map[string]interface{}
}

func NewClusterIngressRuleBuilder() *ClusterNetworkPolicyRuleBuilder {
	return &ClusterNetworkPolicyRuleBuilder{
		action: "Accept",
		ports:  []map[string]interface{}{},
	}
}

func NewClusterEgressRuleBuilder() *ClusterNetworkPolicyRuleBuilder {
	return &ClusterNetworkPolicyRuleBuilder{
		action: "Accept",
		ports:  []map[string]interface{}{},
	}
}

func (r *ClusterNetworkPolicyRuleBuilder) Name(name string) *ClusterNetworkPolicyRuleBuilder {
	r.name = name
	return r
}

func (r *ClusterNetworkPolicyRuleBuilder) Action(action string) *ClusterNetworkPolicyRuleBuilder {
	r.action = action
	return r
}

func (r *ClusterNetworkPolicyRuleBuilder) AddPort(port int32, protocol string) *ClusterNetworkPolicyRuleBuilder {
	r.ports = append(r.ports, map[string]interface{}{
		"portNumber": map[string]interface{}{
			"port":     port,
			"protocol": protocol,
		},
	})
	return r
}

func (r *ClusterNetworkPolicyRuleBuilder) AddPortRange(start, end int32, protocol string) *ClusterNetworkPolicyRuleBuilder {
	r.ports = append(r.ports, map[string]interface{}{
		"portRange": map[string]interface{}{
			"start":    start,
			"end":      end,
			"protocol": protocol,
		},
	})
	return r
}

func (r *ClusterNetworkPolicyRuleBuilder) BuildIngressRule(from []map[string]interface{}) map[string]interface{} {
	rule := map[string]interface{}{
		"action": r.action,
		"from":   from,
	}

	if r.name != "" {
		rule["name"] = r.name
	}

	if len(r.ports) > 0 {
		rule["ports"] = r.ports
	}

	return rule
}

func (r *ClusterNetworkPolicyRuleBuilder) BuildEgressRule(to []map[string]interface{}) map[string]interface{} {
	rule := map[string]interface{}{
		"action": r.action,
		"to":     to,
	}

	if r.name != "" {
		rule["name"] = r.name
	}

	if len(r.ports) > 0 {
		rule["ports"] = r.ports
	}

	return rule
}

// Helper functions for peer builders
func NewPodsPeer(namespaceSelector, podSelector map[string]string) map[string]interface{} {
	return map[string]interface{}{
		"pods": map[string]interface{}{
			"namespaceSelector": map[string]interface{}{
				"matchLabels": namespaceSelector,
			},
			"podSelector": map[string]interface{}{
				"matchLabels": podSelector,
			},
		},
	}
}

func NewNamespacesPeer(namespaceSelector map[string]string) map[string]interface{} {
	return map[string]interface{}{
		"namespaces": map[string]interface{}{
			"matchLabels": namespaceSelector,
		},
	}
}

func NewNetworksPeer(cidrs []string) map[string]interface{} {
	return map[string]interface{}{
		"networks": cidrs,
	}
}

func NewDomainNamesPeer(domains []string) map[string]interface{} {
	return map[string]interface{}{
		"domainNames": domains,
	}
}

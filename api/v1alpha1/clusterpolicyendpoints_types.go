/*
Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Tier defines the tier of the admin policy
// +kubebuilder:validation:Enum={"Admin", "Baseline"}
type Tier string

const (
	// AdminTier
	AdminTier Tier = "Admin"
	// BaselineTier
	BaselineTier Tier = "Baseline"
)

// ClusterPolicyAction defines the action to be applied by the admin policy
// +kubebuilder:validation:Enum={"Accept", "Deny", "Pass"}

type ClusterNetworkPolicyRuleAction string

const (
	ClusterNetworkPolicyRuleActionAccept ClusterNetworkPolicyRuleAction = "Accept"
	ClusterNetworkPolicyRuleActionDeny   ClusterNetworkPolicyRuleAction = "Deny"
	ClusterNetworkPolicyRuleActionPass   ClusterNetworkPolicyRuleAction = "Pass"
)

// ClusterPolicyReference is the reference to the admin network policy resource
type ClusterPolicyReference struct {
	// Name is the name of the ClusterNetworkPolicy
	Name string `json:"name"`
}

// EndpointInfo defines the network endpoint information for the policy ingress/egress
type ClusterEndpointInfo struct {

	// CIDR is the network address(s) of the endpoint
	CIDR NetworkAddress `json:"cidr,omitempty"`

	// Ports is the list of ports
	Ports []Port `json:"ports,omitempty"`

	// DomainName is the FQDN for the endpoint (egress-only)
	DomainName DomainName `json:"domainName,omitempty"`

	// Action from the CNP rule
	Action ClusterNetworkPolicyRuleAction `json:"action"`
}

// ClusterPolicyEndpointSpec defines the desired state of ClusterPolicyEndpoint
type ClusterPolicyEndpointSpec struct {

	// PolicyRef is a reference to the Kubernetes AdminNetworkPolicy resource.
	PolicyRef ClusterPolicyReference `json:"policyRef"`

	// Tier defines the type of admin policy
	Tier Tier `json:"tier"`

	// Priority is the priority of the admin policy endpoint
	Priority int32 `json:"priority"`

	// PodSelectorEndpoints contains information about the pods
	// matching the podSelector
	PodSelectorEndpoints []PodEndpoint `json:"podSelectorEndpoints,omitempty"`

	// Ingress is the list of ingress rules containing resolved network addresses
	Ingress []ClusterEndpointInfo `json:"ingress,omitempty"`

	// Egress is the list of egress rules containing resolved network addresses
	Egress []ClusterEndpointInfo `json:"egress,omitempty"`
}

// ClusterPolicyEndpointStatus defines the observed state of ClusterPolicyEndpoint
type ClusterPolicyEndpointStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Cluster

// ClusterPolicyEndpoint is the Schema for the ClusterPolicyendpoints API
type ClusterPolicyEndpoint struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterPolicyEndpointSpec   `json:"spec,omitempty"`
	Status ClusterPolicyEndpointStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ClusterPolicyEndpointList contains a list of ClusterPolicyEndpoint
type ClusterPolicyEndpointList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterPolicyEndpoint `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterPolicyEndpoint{}, &ClusterPolicyEndpointList{})
}

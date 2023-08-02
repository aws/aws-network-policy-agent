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
	corev1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PolicyReference is the reference to the network policy resource
type PolicyReference struct {
	// Name is the name of the Policy
	Name string `json:"name"`

	// Namespace is the namespace of the Policy
	Namespace string `json:"namespace"`
}

type NetworkAddress string

// Port contains information about the transport port/protocol
type Port struct {
	// Protocol specifies the transport protocol, default TCP
	Protocol *corev1.Protocol `json:"protocol,omitempty"`

	// Port specifies the numerical port for the protocol. If empty applies to all ports
	Port *int32 `json:"port,omitempty"`

	// Endport specifies the port range port to endPort
	// port must be defined and an integer, endPort > port
	EndPort *int32 `json:"endPort,omitempty"`
}

// EndpointInfo defines the network endpoint information for the policy ingress/egress
type EndpointInfo struct {
	// CIDR is the network address(s) of the endpoint
	CIDR NetworkAddress `json:"cidr"`

	// Except is the exceptions to the CIDR ranges mentioned above.
	Except []NetworkAddress `json:"except,omitempty"`

	// Ports is the list of ports
	Ports []Port `json:"ports,omitempty"`
}

// PodEndpoint defines the summary information for the pods
type PodEndpoint struct {
	// HostIP is the IP address of the host the pod is currently running on
	HostIP NetworkAddress `json:"hostIP"`
	// PodIP is the IP address of the pod
	PodIP NetworkAddress `json:"podIP"`
	// Name is the pod name
	Name string `json:"name"`
	// Namespace is the pod namespace
	Namespace string `json:"namespace"`
}

// PolicyEndpointSpec defines the desired state of PolicyEndpoint
type PolicyEndpointSpec struct {
	// PodSelector is the podSelector from the policy resource
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`

	// PolicyRef is a reference to the Kubernetes NetworkPolicy resource.
	PolicyRef PolicyReference `json:"policyRef"`

	// PodIsolation specifies whether the pod needs to be isolated for a
	// particular traffic direction Ingress or Egress, or both. If default isolation is not
	// specified, and there are no ingress/egress rules, then the pod is not isolated
	// from the point of view of this policy. This follows the NetworkPolicy spec.PolicyTypes.
	PodIsolation []networking.PolicyType `json:"podIsolation,omitempty"`

	// PodSelectorEndpoints contains information about the pods
	// matching the podSelector
	PodSelectorEndpoints []PodEndpoint `json:"podSelectorEndpoints,omitempty"`

	// Ingress is the list of ingress rules containing resolved network addresses
	Ingress []EndpointInfo `json:"ingress,omitempty"`

	// Egress is the list of egress rules containing resolved network addresses
	Egress []EndpointInfo `json:"egress,omitempty"`
}

// PolicyEndpointStatus defines the observed state of PolicyEndpoint
type PolicyEndpointStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// PolicyEndpoint is the Schema for the policyendpoints API
type PolicyEndpoint struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PolicyEndpointSpec   `json:"spec,omitempty"`
	Status PolicyEndpointStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// PolicyEndpointList contains a list of PolicyEndpoint
type PolicyEndpointList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PolicyEndpoint `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PolicyEndpoint{}, &PolicyEndpointList{})
}

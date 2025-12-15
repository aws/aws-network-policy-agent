package clusternetworkpolicy

import (
	"context"

	"github.com/aws/aws-network-policy-agent/test/framework/utils"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var ClusterNetworkPolicyGVK = schema.GroupVersionKind{
	Group:   "networking.k8s.aws",
	Version: "v1alpha1",
	Kind:    "ClusterNetworkPolicy",
}

type Manager interface {
	CreateClusterNetworkPolicy(ctx context.Context, cnp *unstructured.Unstructured) error
	DeleteClusterNetworkPolicy(ctx context.Context, cnp *unstructured.Unstructured) error
	GetClusterNetworkPolicy(ctx context.Context, name string) (*unstructured.Unstructured, error)
}

func NewManager(k8sClient client.Client) Manager {
	return &defaultManager{k8sClient: k8sClient}
}

type defaultManager struct {
	k8sClient client.Client
}

func (m *defaultManager) CreateClusterNetworkPolicy(ctx context.Context, cnp *unstructured.Unstructured) error {
	cnp.SetGroupVersionKind(ClusterNetworkPolicyGVK)
	return m.k8sClient.Create(ctx, cnp)
}

func (m *defaultManager) DeleteClusterNetworkPolicy(ctx context.Context, cnp *unstructured.Unstructured) error {
	err := m.k8sClient.Delete(ctx, cnp)
	if err != nil {
		return client.IgnoreNotFound(err)
	}

	policy := &unstructured.Unstructured{}
	policy.SetGroupVersionKind(ClusterNetworkPolicyGVK)
	return wait.PollUntilContextCancel(ctx, utils.PollIntervalShort, true, func(context.Context) (done bool, err error) {
		if err := m.k8sClient.Get(ctx, client.ObjectKey{Name: cnp.GetName()}, policy); err != nil {
			if errors.IsNotFound(err) {
				return true, nil
			}
			return false, err
		}
		return false, nil
	})
}

func (m *defaultManager) GetClusterNetworkPolicy(ctx context.Context, name string) (*unstructured.Unstructured, error) {
	cnp := &unstructured.Unstructured{}
	cnp.SetGroupVersionKind(ClusterNetworkPolicyGVK)
	err := m.k8sClient.Get(ctx, client.ObjectKey{Name: name}, cnp)
	return cnp, err
}

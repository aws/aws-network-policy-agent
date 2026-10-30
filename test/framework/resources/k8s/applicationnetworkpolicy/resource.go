package applicationnetworkpolicy

import (
	"context"

	"github.com/aws/aws-network-policy-agent/test/framework/utils"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var ApplicationNetworkPolicyGVK = schema.GroupVersionKind{
	Group:   "networking.k8s.aws",
	Version: "v1alpha1",
	Kind:    "ApplicationNetworkPolicy",
}

type Manager interface {
	CreateApplicationNetworkPolicy(ctx context.Context, anp *unstructured.Unstructured) error
	DeleteApplicationNetworkPolicy(ctx context.Context, anp *unstructured.Unstructured) error
	GetApplicationNetworkPolicy(ctx context.Context, namespace, name string) (*unstructured.Unstructured, error)
}

func NewManager(k8sClient client.Client) Manager {
	return &defaultManager{k8sClient: k8sClient}
}

type defaultManager struct {
	k8sClient client.Client
}

func (m *defaultManager) CreateApplicationNetworkPolicy(ctx context.Context, anp *unstructured.Unstructured) error {
	anp.SetGroupVersionKind(ApplicationNetworkPolicyGVK)
	return m.k8sClient.Create(ctx, anp)
}

func (m *defaultManager) DeleteApplicationNetworkPolicy(ctx context.Context, anp *unstructured.Unstructured) error {
	err := m.k8sClient.Delete(ctx, anp)
	if err != nil {
		return client.IgnoreNotFound(err)
	}

	policy := &unstructured.Unstructured{}
	policy.SetGroupVersionKind(ApplicationNetworkPolicyGVK)
	return wait.PollUntilContextCancel(ctx, utils.PollIntervalShort, true, func(context.Context) (done bool, err error) {
		if err := m.k8sClient.Get(ctx, client.ObjectKey{
			Namespace: anp.GetNamespace(),
			Name:      anp.GetName(),
		}, policy); err != nil {
			if errors.IsNotFound(err) {
				return true, nil
			}
			return false, err
		}
		return false, nil
	})
}

func (m *defaultManager) GetApplicationNetworkPolicy(ctx context.Context, namespace, name string) (*unstructured.Unstructured, error) {
	anp := &unstructured.Unstructured{}
	anp.SetGroupVersionKind(ApplicationNetworkPolicyGVK)
	err := m.k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, anp)
	return anp, err
}

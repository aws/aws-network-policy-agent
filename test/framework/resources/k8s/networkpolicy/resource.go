package networkpolicy

import (
	"context"

	"github.com/aws/aws-network-policy-agent/test/framework/utils"
	network "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Manager interface {
	CreateNetworkPolicy(ctx context.Context, networkpolicy *network.NetworkPolicy) error
	DeleteNetworkPolicy(ctx context.Context, networkpolicy *network.NetworkPolicy) error
}

func NewManager(k8sClient client.Client) Manager {
	return &defaultManager{k8sClient: k8sClient}
}

type defaultManager struct {
	k8sClient client.Client
}

func (m *defaultManager) CreateNetworkPolicy(ctx context.Context, networkpolicy *network.NetworkPolicy) error {
	return m.k8sClient.Create(ctx, networkpolicy)
}

func (m *defaultManager) DeleteNetworkPolicy(ctx context.Context, networkpolicy *network.NetworkPolicy) error {

	err := m.k8sClient.Delete(ctx, networkpolicy)
	if err != nil {
		return client.IgnoreNotFound(err)
	}

	netpol := &network.NetworkPolicy{}
	return wait.PollUntilContextCancel(ctx, utils.PollIntervalShort, true, func(context.Context) (done bool, err error) {
		if err := m.k8sClient.Get(ctx, utils.NamespacedName(networkpolicy), netpol); err != nil {
			return false, err
		}
		if errors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	})
}

package namespace

import (
	"context"

	"github.com/aws/aws-network-policy-agent/test/framework/utils"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"

	v1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Manager interface {
	CreateNamespace(ctx context.Context, namespace string) error
	DeleteAndWaitTillNamespaceDeleted(ctx context.Context, namespace string) error
}

func NewManager(k8sClient client.Client) Manager {
	return &defaultManager{k8sClient: k8sClient}
}

type defaultManager struct {
	k8sClient client.Client
}

func (m *defaultManager) CreateNamespace(ctx context.Context, namespace string) error {
	return m.k8sClient.Create(ctx, &v1.Namespace{ObjectMeta: metaV1.ObjectMeta{Name: namespace}})
}

func (m *defaultManager) DeleteAndWaitTillNamespaceDeleted(ctx context.Context, namespace string) error {

	namespaceObj := &v1.Namespace{ObjectMeta: metaV1.ObjectMeta{Name: namespace}}
	err := m.k8sClient.Delete(ctx, namespaceObj)
	if err != nil {
		return client.IgnoreNotFound(err)
	}

	observedNamespace := &v1.Namespace{}
	return wait.PollUntilContextCancel(ctx, utils.PollIntervalShort, true, func(context.Context) (done bool, err error) {
		err = m.k8sClient.Get(ctx, utils.NamespacedName(namespaceObj), observedNamespace)
		if errors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	})
}

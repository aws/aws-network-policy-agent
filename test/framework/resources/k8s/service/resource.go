package service

import (
	"context"

	"github.com/aws/aws-network-policy-agent/test/framework/utils"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Manager interface {
	GetService(ctx context.Context, namespace string, name string) (*v1.Service, error)
	CreateService(ctx context.Context, service *v1.Service) (*v1.Service, error)
	DeleteService(ctx context.Context, service *v1.Service) error
}

type defaultManager struct {
	k8sClient client.Client
}

func NewManager(k8sClient client.Client) Manager {
	return &defaultManager{k8sClient: k8sClient}
}

func (s *defaultManager) GetService(ctx context.Context, namespace string,
	name string) (*v1.Service, error) {

	service := &v1.Service{}
	err := s.k8sClient.Get(ctx, types.NamespacedName{
		Namespace: namespace,
		Name:      name,
	}, service)

	return service, err
}

func (s *defaultManager) CreateService(ctx context.Context, service *v1.Service) (*v1.Service, error) {
	err := s.k8sClient.Create(ctx, service)
	if err != nil {
		return nil, err
	}

	observedService := &v1.Service{}
	return observedService, wait.PollUntil(utils.PollIntervalShort, func() (bool, error) {
		if err := s.k8sClient.Get(ctx, utils.NamespacedName(service), observedService); err != nil {
			return false, err
		}
		return true, nil
	}, ctx.Done())
}

func (s *defaultManager) DeleteService(ctx context.Context, service *v1.Service) error {
	err := s.k8sClient.Delete(ctx, service)
	if err != nil {
		return err
	}

	return nil
}

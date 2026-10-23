package proxymanager

import (
	"context"

	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"k8s.io/apimachinery/pkg/types"
)

type ProxyManagerMock struct {
}

func (p *ProxyManagerMock) Start(ctx context.Context) error {
	return nil
}

func (p *ProxyManagerMock) AddDNSRedirectionRulesForPod(pod npatypes.Pod, podIdentifier string) error {
	return nil
}

func (p *ProxyManagerMock) RemoveDNSRedirectionRulesForPod(pod types.NamespacedName, podIdentifier string) error {
	return nil
}

func (p *ProxyManagerMock) ForceRemoveDNSRedirectionRulesForPod(pod types.NamespacedName, podIdentifier string) error {
	return nil
}

func (p *ProxyManagerMock) HealthCheckDNSProxy() error {
	return nil
}

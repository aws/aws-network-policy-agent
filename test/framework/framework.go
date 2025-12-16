package framework

import (
	"github.com/aws/aws-network-policy-agent/test/framework/resources/k8s/clusternetworkpolicy"
	"github.com/aws/aws-network-policy-agent/test/framework/resources/k8s/deployment"
	"github.com/aws/aws-network-policy-agent/test/framework/resources/k8s/namespace"
	"github.com/aws/aws-network-policy-agent/test/framework/resources/k8s/networkpolicy"
	"github.com/aws/aws-network-policy-agent/test/framework/resources/k8s/pod"
	"github.com/aws/aws-network-policy-agent/test/framework/resources/k8s/service"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Framework struct {
	Options                     Options
	K8sClient                   client.Client
	DeploymentManager           deployment.Manager
	NamespaceManager            namespace.Manager
	ServiceManager              service.Manager
	PodManager                  pod.Manager
	NetworkPolicyManager        networkpolicy.Manager
	ClusterNetworkPolicyManager clusternetworkpolicy.Manager
}

func New(options Options) *Framework {
	err := options.Validate()
	Expect(err).NotTo(HaveOccurred())

	config, err := clientcmd.BuildConfigFromFlags("", options.KubeConfig)
	Expect(err).NotTo(HaveOccurred())

	clientset, err := kubernetes.NewForConfig(config)
	Expect(err).NotTo(HaveOccurred())

	k8sSchema := runtime.NewScheme()
	clientgoscheme.AddToScheme(k8sSchema)

	k8sClient, err := client.New(config, client.Options{Scheme: k8sSchema})
	Expect(err).NotTo(HaveOccurred())

	return &Framework{
		K8sClient:                   k8sClient,
		DeploymentManager:           deployment.NewManager(k8sClient),
		NamespaceManager:            namespace.NewManager(k8sClient),
		PodManager:                  pod.NewManager(k8sClient, clientset, config),
		NetworkPolicyManager:        networkpolicy.NewManager(k8sClient),
		ClusterNetworkPolicyManager: clusternetworkpolicy.NewManager(k8sClient),
		ServiceManager:              service.NewManager(k8sClient),
		Options:                     options,
	}
}

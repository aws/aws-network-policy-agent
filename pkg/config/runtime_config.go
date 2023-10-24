package config

import (
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/spf13/pflag"
)

const (
	flagKubeconfig          = "kubeconfig"
	flagMetricsBindAddr     = "metrics-bind-addr"
	flagHealthProbeBindAddr = "health-probe-bind-addr"

	defaultKubeconfig             = ""
	defaultWatchNamespace         = corev1.NamespaceAll
	defaultMetricsAddr            = ":8162"
	defaultHealthProbeBindAddress = ":8163"
	defaultQPS                    = 20
	defaultBurst                  = 100
)

// RuntimeConfig stores the configuration for the controller-runtime
type RuntimeConfig struct {
	APIServer              string
	KubeConfig             string
	MetricsBindAddress     string
	HealthProbeBindAddress string
	SyncPeriod             time.Duration
}

func (c *RuntimeConfig) BindFlags(fs *pflag.FlagSet) {
	fs.StringVar(&c.KubeConfig, flagKubeconfig, defaultKubeconfig,
		"Path to the kubeconfig file containing authorization and API server information.")
	fs.StringVar(&c.MetricsBindAddress, flagMetricsBindAddr, defaultMetricsAddr,
		"The address the metric endpoint binds to.")
	fs.StringVar(&c.HealthProbeBindAddress, flagHealthProbeBindAddr, defaultHealthProbeBindAddress,
		"The address the health probes binds to.")
}

// BuildRestConfig builds the REST config for the controller runtime
func BuildRestConfig(rtCfg RuntimeConfig) (*rest.Config, error) {
	var restCFG *rest.Config
	var err error
	if rtCfg.KubeConfig == "" {
		restCFG, err = rest.InClusterConfig()
	} else {
		restCFG, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{ExplicitPath: rtCfg.KubeConfig}, &clientcmd.ConfigOverrides{}).ClientConfig()
	}
	if err != nil {
		return nil, err
	}
	restCFG.QPS = defaultQPS
	restCFG.Burst = defaultBurst
	return restCFG, nil
}

// BuildRuntimeOptions builds the options for the controller runtime based on config
func BuildRuntimeOptions(rtCfg RuntimeConfig, scheme *runtime.Scheme) ctrl.Options {
	return ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: rtCfg.MetricsBindAddress},
		HealthProbeBindAddress: rtCfg.HealthProbeBindAddress,
	}
}

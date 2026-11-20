package config

import (
	"path/filepath"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func TestRuntimeConfigBindFlags(t *testing.T) {
	tests := []struct {
		name              string
		args              []string
		expectedAPIServer string
	}{
		{
			name: "API server is empty by default",
		},
		{
			name:              "API server can be configured",
			args:              []string{"--apiserver", "https://api.example.com"},
			expectedAPIServer: "https://api.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg RuntimeConfig
			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
			cfg.BindFlags(flags)

			require.NoError(t, flags.Parse(tt.args))
			assert.Equal(t, tt.expectedAPIServer, cfg.APIServer)
		})
	}
}

func TestBuildRestConfig(t *testing.T) {
	const (
		kubeconfigAPIServer = "https://kubernetes-service.example.com"
		directAPIServer     = "https://direct-api.example.com"
		bearerToken         = "service-account-token"
		certificateData     = "cluster-ca"
	)

	kubeconfigPath := filepath.Join(t.TempDir(), "kubeconfig")
	kubeconfig := clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{
			"test": {
				Server:                   kubeconfigAPIServer,
				TLSServerName:            "kubernetes-service.example.com",
				CertificateAuthorityData: []byte(certificateData),
			},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"test": {
				Token: bearerToken,
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			"test": {
				Cluster:  "test",
				AuthInfo: "test",
			},
		},
		CurrentContext: "test",
	}
	require.NoError(t, clientcmd.WriteToFile(kubeconfig, kubeconfigPath))

	tests := []struct {
		name              string
		apiServer         string
		expectedAPIServer string
	}{
		{
			name:              "uses API server from kubeconfig by default",
			expectedAPIServer: kubeconfigAPIServer,
		},
		{
			name:              "overrides API server while preserving authentication",
			apiServer:         directAPIServer,
			expectedAPIServer: directAPIServer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restConfig, err := BuildRestConfig(RuntimeConfig{
				APIServer:  tt.apiServer,
				KubeConfig: kubeconfigPath,
			})

			require.NoError(t, err)
			assert.Equal(t, tt.expectedAPIServer, restConfig.Host)
			assert.Equal(t, bearerToken, restConfig.BearerToken)
			assert.Equal(t, []byte(certificateData), restConfig.CAData)
			if tt.apiServer == "" {
				assert.Equal(t, "kubernetes-service.example.com", restConfig.TLSClientConfig.ServerName)
			} else {
				assert.Empty(t, restConfig.TLSClientConfig.ServerName)
			}
			assert.Equal(t, float32(defaultQPS), restConfig.QPS)
			assert.Equal(t, defaultBurst, restConfig.Burst)
		})
	}
}

func TestBuildRestConfigRejectsInvalidAPIServer(t *testing.T) {
	kubeconfigPath := filepath.Join(t.TempDir(), "kubeconfig")
	kubeconfig := clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{
			"test": {Server: "https://kubernetes-service.example.com"},
		},
		Contexts: map[string]*clientcmdapi.Context{
			"test": {Cluster: "test"},
		},
		CurrentContext: "test",
	}
	require.NoError(t, clientcmd.WriteToFile(kubeconfig, kubeconfigPath))

	tests := []struct {
		name      string
		apiServer string
	}{
		{name: "rejects HTTP", apiServer: "http://api.example.com"},
		{name: "rejects unsupported scheme", apiServer: "tcp://api.example.com:443"},
		{name: "rejects missing scheme", apiServer: "api.example.com"},
		{name: "rejects path", apiServer: "https://api.example.com/proxy"},
		{name: "rejects query", apiServer: "https://api.example.com?proxy=true"},
		{name: "rejects user info", apiServer: "https://user@api.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := BuildRestConfig(RuntimeConfig{
				APIServer:  tt.apiServer,
				KubeConfig: kubeconfigPath,
			})

			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid Kubernetes API server URL")
		})
	}
}

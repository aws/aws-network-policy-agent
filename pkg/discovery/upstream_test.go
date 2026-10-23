package discovery

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetKubeDNSServiceIP(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantIP  string
		wantErr string
	}{
		{
			name:   "kube-dns Service IP",
			env:    map[string]string{"KUBE_DNS_SERVICE_HOST": "10.100.0.10"},
			wantIP: "10.100.0.10",
		},
		{
			name:    "variable not set",
			env:     map[string]string{},
			wantErr: "KUBE_DNS_SERVICE_HOST is not set",
		},
		{
			name:    "not an IP",
			env:     map[string]string{"KUBE_DNS_SERVICE_HOST": "kube-dns"},
			wantErr: `KUBE_DNS_SERVICE_HOST="kube-dns" is not an IPv4 address`,
		},
		{
			name:    "IPv6 address",
			env:     map[string]string{"KUBE_DNS_SERVICE_HOST": "fd00::a"},
			wantErr: `KUBE_DNS_SERVICE_HOST="fd00::a" is not an IPv4 address`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, err := getKubeDNSServiceIP(func(key string) string { return tt.env[key] })
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				assert.Nil(t, ip)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.wantIP, ip.String())
		})
	}
}

// A node that cannot run DNS policy must keep the agent alive, because the CNI plugin needs its
// socket to set up every new pod. Only the domainName rules are given up.
func TestResolveDNSPolicyUpstream(t *testing.T) {
	tests := []struct {
		name        string
		enableIPv6  bool
		kubeDNSHost string
		wantIP      string
		wantAvail   bool
		wantReason  string
	}{
		{
			name:        "kube-dns Service IP found",
			kubeDNSHost: "10.100.0.10",
			wantIP:      "10.100.0.10",
			wantAvail:   true,
		},
		{
			name:       "no kube-dns Service IP",
			wantReason: "the upstream DNS server could not be discovered: KUBE_DNS_SERVICE_HOST is not set",
		},
		{
			name:        "IPv6 cluster",
			enableIPv6:  true,
			kubeDNSHost: "10.100.0.10",
			wantReason:  "DNS policy is not supported on IPv6 clusters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("KUBE_DNS_SERVICE_HOST", tt.kubeDNSHost)

			ip, available, reason := ResolveDNSPolicyUpstream(tt.enableIPv6)

			assert.Equal(t, tt.wantAvail, available)
			if !tt.wantAvail {
				assert.Nil(t, ip)
				assert.Contains(t, reason, tt.wantReason)
				return
			}
			assert.Equal(t, tt.wantIP, ip.String())
			assert.Empty(t, reason)
		})
	}
}

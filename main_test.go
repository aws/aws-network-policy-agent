package main

import (
	"testing"

	cnirpc "github.com/aws/amazon-vpc-cni-k8s/rpc"
	"github.com/stretchr/testify/assert"
)

func TestSelectNodeIP(t *testing.T) {
	tests := []struct {
		name       string
		reply      *cnirpc.NetworkPolicyAgentConfigReply
		enableIPv6 bool
		wantIP     string
		wantErr    string
	}{
		{
			name:       "IPv4 mode returns NodeIPv4",
			reply:      &cnirpc.NetworkPolicyAgentConfigReply{NodeIPv4: "192.168.1.10", NodeIPv6: "2600::1"},
			enableIPv6: false,
			wantIP:     "192.168.1.10",
		},
		{
			name:       "IPv6 mode returns NodeIPv6",
			reply:      &cnirpc.NetworkPolicyAgentConfigReply{NodeIPv4: "192.168.1.10", NodeIPv6: "2600::1"},
			enableIPv6: true,
			wantIP:     "2600::1",
		},
		{
			name:       "IPv4 mode with missing NodeIPv4 errors",
			reply:      &cnirpc.NetworkPolicyAgentConfigReply{NodeIPv6: "2600::1"},
			enableIPv6: false,
			wantErr:    "ipamd did not provide a node IP (EnableIPv6=false)",
		},
		{
			name:       "IPv6 mode with missing NodeIPv6 errors",
			reply:      &cnirpc.NetworkPolicyAgentConfigReply{NodeIPv4: "192.168.1.10"},
			enableIPv6: true,
			wantErr:    "ipamd did not provide a node IP (EnableIPv6=true)",
		},
		{
			name:       "empty reply errors",
			reply:      &cnirpc.NetworkPolicyAgentConfigReply{},
			enableIPv6: false,
			wantErr:    "ipamd did not provide a node IP (EnableIPv6=false)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIP, err := selectNodeIP(tt.reply, tt.enableIPv6)
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				assert.Empty(t, gotIP)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.wantIP, gotIP)
		})
	}
}

package ebpf

import (
	"net"
	"testing"

	"github.com/achevuru/aws-network-policy-agent/api/v1alpha1"
	"github.com/achevuru/aws-network-policy-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	ctrl "sigs.k8s.io/controller-runtime"
	// "unsafe"
)

func TestBpfClient_computeMapEntriesFromEndpointRules(t *testing.T) {
	test_bpfClientLogger := ctrl.Log.WithName("ebpf-client")
	protocolTCP := v1alpha1.ProtocolTCP
	//protocolUDP := v1alpha1.ProtocolUDP
	//protocolSCTP := v1alpha1.ProtocolSCTP

	var testIP v1alpha1.NetworkAddress
	var gotKeys []string

	nodeIP := "10.1.1.1"
	_, nodeIPCIDR, _ := net.ParseCIDR(nodeIP + "/32")
	nodeIPKey := utils.ComputeTrieKey(*nodeIPCIDR)
	// nodeIPValue := utils.ComputeTrieValue([]v1alpha1.Port{}, test_bpfClientLogger, true, false)

	var testPort int32
	testPort = 80
	testIP = "10.1.1.2/32"
	_, testIPCIDR, _ := net.ParseCIDR(string(testIP))
	/*
	   testL4Info := []v1alpha1.Port{
	           {
	                   Protocol: &protocolTCP,
	                   Port:     &testPort,
	           },
	   }
	*/
	testIPKey := utils.ComputeTrieKey(*testIPCIDR)
	//      cidrWithPPValue := utils.ComputeTrieValue(testL4Info, test_bpfClientLogger, false, false)
	type args struct {
		firewallRules []EbpfFirewallRules
	}

	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr error
	}{
		{
			name: "CIDR with Port and Protocol",
			args: args{
				[]EbpfFirewallRules{
					{
						IPCidr: "10.1.1.2/32",
						L4Info: []v1alpha1.Port{
							{
								Protocol: &protocolTCP,
								Port:     &testPort,
							},
						},
					},
				},
			},
			want: []string{string(nodeIPKey), string(testIPKey)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			test_bpfClient := &bpfClient{
				nodeIP: "10.1.1.1",
				logger: test_bpfClientLogger,
			}
			got, err := test_bpfClient.computeMapEntriesFromEndpointRules(tt.args.firewallRules)
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				for key, _ := range got {
					gotKeys = append(gotKeys, key)
				}
				assert.Equal(t, tt.want, gotKeys)
			}
		})
	}
}

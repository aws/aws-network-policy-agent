package fwruleprocessor

import (
	"testing"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

func benchInt32(v int32) *int32 { return &v }

func benchPorts(n int) []v1alpha1.Port {
	tcp := corev1.ProtocolTCP
	udp := corev1.ProtocolUDP
	ports := make([]v1alpha1.Port, 0, n)
	for i := 0; i < n; i++ {
		p := int32(i % 100)
		proto := &tcp
		if i%2 == 0 {
			proto = &udp
		}
		ports = append(ports, v1alpha1.Port{Protocol: proto, Port: benchInt32(p), EndPort: benchInt32(p)})
	}
	return ports
}

func BenchmarkMergeDuplicateL4Info(b *testing.B) {
	ports := benchPorts(500)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mergeDuplicateL4Info(ports)
	}
}

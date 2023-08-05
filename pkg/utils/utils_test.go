package utils

import (
	"net"
	"testing"

	"github.com/achevuru/aws-network-policy-agent/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
)

func TestComputeTrieKey(t *testing.T) {

	_, hostCIDR, _ := net.ParseCIDR("10.1.1.2/32")
	_, nonHostCIDR, _ := net.ParseCIDR("10.1.1.0/24")

	type args struct {
		IPNet net.IPNet
	}

	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "Host CIDR",
			args: args{
				IPNet: *hostCIDR,
			},
			want: []byte{0x20, 0x00, 0x00, 0x00, 0x0a, 0x01, 0x01, 0x02},
		},

		{
			name: "Non-Host CIDR",
			args: args{
				IPNet: *nonHostCIDR,
			},
			want: []byte{0x18, 0x00, 0x00, 0x00, 0x0a, 0x01, 0x01, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeTrieKey(tt.args.IPNet, false)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestComputeTrieValue(t *testing.T) {
	test_utilsLogger := ctrl.Log.WithName("ebpf-client")
	protocolTCP := corev1.ProtocolTCP
	protocolUDP := corev1.ProtocolUDP
	protocolSCTP := corev1.ProtocolSCTP

	var testPort80, testPort81 int32
	testPort80 = 80
	testPort81 = 81

	type args struct {
		Ports    []v1alpha1.Port
		allowAll bool
		denyAll  bool
	}

	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "TCP on Port 80",
			args: args{
				Ports: []v1alpha1.Port{
					{
						Protocol: &protocolTCP,
						Port:     &testPort80,
					},
				},
			},
			want: []byte{0x06, 0x00, 0x00, 0x00, 0x50, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00},
		},

		{
			name: "UDP on Port 80",
			args: args{
				Ports: []v1alpha1.Port{
					{
						Protocol: &protocolUDP,
						Port:     &testPort80,
					},
				},
			},
			want: []byte{0x11, 0x00, 0x00, 0x00, 0x50, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00},
		},

		{
			name: "SCTP on Port 80",
			args: args{
				Ports: []v1alpha1.Port{
					{
						Protocol: &protocolSCTP,
						Port:     &testPort80,
					},
				},
			},
			want: []byte{0x84, 0x00, 0x00, 0x00, 0x50, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "TCP on Port 80 and UDP on Port 81",
			args: args{
				Ports: []v1alpha1.Port{
					{
						Protocol: &protocolTCP,
						Port:     &testPort80,
					},
					{
						Protocol: &protocolUDP,
						Port:     &testPort81,
					},
				},
			},
			want: []byte{0x06, 0x00, 0x00, 0x00, 0x50, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x11, 0x00, 0x00, 0x00, 0x51, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "TCP on Port 80, UDP on Port 81 and SCTP on Port 80",
			args: args{
				Ports: []v1alpha1.Port{
					{
						Protocol: &protocolTCP,
						Port:     &testPort80,
					},
					{
						Protocol: &protocolUDP,
						Port:     &testPort81,
					},
					{
						Protocol: &protocolSCTP,
						Port:     &testPort80,
					},
				},
			},
			want: []byte{0x06, 0x00, 0x00, 0x00, 0x50, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x11, 0x00, 0x00, 0x00, 0x51, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x84, 0x00, 0x00, 0x00, 0x50, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00},
		},

		{
			name: "Allow All scenario",
			args: args{
				Ports:    []v1alpha1.Port{},
				allowAll: true,
				denyAll:  false,
			},
			want: []byte{0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "Except CIDR scenario",
			args: args{
				Ports:    []v1alpha1.Port{},
				allowAll: false,
				denyAll:  true,
			},
			want: []byte{0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeTrieValue(tt.args.Ports, test_utilsLogger, tt.args.allowAll, tt.args.denyAll)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetPodNamespacedName(t *testing.T) {
	type args struct {
		podName      string
		podNamespace string
	}

	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Valid pod name and namespace",
			args: args{
				podName:      "testPod",
				podNamespace: "testNamespace",
			},
			want: "testPodtestNamespace",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetPodNamespacedName(tt.args.podName, tt.args.podNamespace)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetPodIdentifier(t *testing.T) {
	type args struct {
		podName      string
		podNamespace string
	}

	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Valid pod name and namespace",
			args: args{
				podName:      "hello-udp-748dc8d996-fb8b2",
				podNamespace: "default",
			},
			want: "hello-udp-748dc8d996-default",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetPodIdentifier(tt.args.podName, tt.args.podNamespace)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetPodIdentifierFromBPFPinPath(t *testing.T) {
	type args struct {
		pinPath string
	}

	tests := []struct {
		name string
		args args
		want [2]string
	}{
		{
			name: "Ingress Pinpath",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/programs/hello-udp-748dc8d996-default_handle_ingress",
			},
			want: [2]string{"hello-udp-748dc8d996-default", "ingress"},
		},
		{
			name: "Egress Pinpath",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/programs/hello-udp-748dc8d996-default_handle_egress",
			},
			want: [2]string{"hello-udp-748dc8d996-default", "egress"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got1, got2 := GetPodIdentifierFromBPFPinPath(tt.args.pinPath)
			assert.Equal(t, tt.want[0], got1)
			assert.Equal(t, tt.want[1], got2)
		})
	}
}

func TestGetBPFPinPathFromPodIdentifier(t *testing.T) {
	type args struct {
		podIdentifier string
		direction     string
	}

	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Sample Ingress PodIdentifier",
			args: args{
				podIdentifier: "hello-udp-748dc8d996-default",
				direction:     "ingress",
			},
			want: "/sys/fs/bpf/globals/aws/programs/hello-udp-748dc8d996-default_handle_ingress",
		},
		{
			name: "Sample Egress PodIdentifier",
			args: args{
				podIdentifier: "hello-udp-748dc8d996-default",
				direction:     "egress",
			},
			want: "/sys/fs/bpf/globals/aws/programs/hello-udp-748dc8d996-default_handle_egress",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetBPFPinPathFromPodIdentifier(tt.args.podIdentifier, tt.args.direction)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetBPFMapPinPathFromPodIdentifier(t *testing.T) {
	type args struct {
		podIdentifier string
		direction     string
	}

	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Sample Ingress PodIdentifier",
			args: args{
				podIdentifier: "hello-udp-748dc8d996-default",
				direction:     "ingress",
			},
			want: "/sys/fs/bpf/globals/aws/maps/hello-udp-748dc8d996-default_ingress_map",
		},
		{
			name: "Sample Egress PodIdentifier",
			args: args{
				podIdentifier: "hello-udp-748dc8d996-default",
				direction:     "egress",
			},
			want: "/sys/fs/bpf/globals/aws/maps/hello-udp-748dc8d996-default_egress_map",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetBPFMapPinPathFromPodIdentifier(tt.args.podIdentifier, tt.args.direction)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetPolicyEndpointIdentifier(t *testing.T) {
	type args struct {
		policyName      string
		policyNamespace string
	}

	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Sample PolicyEndpoint resource",
			args: args{
				policyName:      "testPolicy",
				policyNamespace: "testPolicyNamespace",
			},
			want: "testPolicytestPolicyNamespace",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetPolicyEndpointIdentifier(tt.args.policyName, tt.args.policyNamespace)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsCatchAllIPEntry(t *testing.T) {
	type args struct {
		ipAddr string
	}

	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "IPv4 Catch All IP Entry",
			args: args{
				ipAddr: "0.0.0.0/0",
			},
			want: true,
		},
		{
			name: "IPv4 Host IP Entry",
			args: args{
				ipAddr: "1.1.1.1/32",
			},
			want: false,
		},
		{
			name: "Random /m IPv4 CIDR",
			args: args{
				ipAddr: "1.1.1.2/24",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsCatchAllIPEntry(tt.args.ipAddr)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsNonHostCIDR(t *testing.T) {
	type args struct {
		ipAddr string
	}

	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "IPv4 Catch All IP Entry",
			args: args{
				ipAddr: "0.0.0.0/0",
			},
			want: false,
		},
		{
			name: "IPv4 Host IP Entry",
			args: args{
				ipAddr: "1.1.1.1/32",
			},
			want: false,
		},
		{
			name: "IPv6 Host IP Entry",
			args: args{
				ipAddr: "2000::/128",
			},
			want: false,
		},
		{
			name: "Random /m IPv4 CIDR",
			args: args{
				ipAddr: "1.1.1.2/24",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsNonHostCIDR(tt.args.ipAddr)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetHostVethName(t *testing.T) {
	type args struct {
		podName      string
		podNamespace string
	}

	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Sample Pod",
			args: args{
				podName:      "foo",
				podNamespace: "bar",
			},
			want: "eni9cfdfc6963c",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetHostVethName(tt.args.podName, tt.args.podNamespace)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsFileExistsError(t *testing.T) {
	type args struct {
		error string
	}

	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "file exists error string",
			args: args{
				error: "while loading egress program handle egress on fd 15: file exists",
			},
			want: true,
		},
		{
			name: "Link Not Found error string",
			args: args{
				error: "while loading egress program handle ingress on fd 15: link not found",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsFileExistsError(tt.args.error)
			assert.Equal(t, tt.want, got)
		})
	}
}

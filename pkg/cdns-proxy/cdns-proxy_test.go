package cdnsproxy_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-network-policy-agent/api/v1alpha1"
	cdnsproxy "github.com/aws/aws-network-policy-agent/pkg/cdns-proxy"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/filter"
	fwrp "github.com/aws/aws-network-policy-agent/pkg/fwruleprocessor"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestMain(m *testing.M) {
	logger.New(logger.DEFAULT_LOG_LEVEL, "stdout", logger.DEFAULT_LOG_FILE_MAX_SIZE, logger.DEFAULT_LOG_FILE_MAX_BACKUPS)
	m.Run()
}

type Environment struct {
	upstreamDNSServer *dnstest.Server
	proxy             *cdnsproxy.DNSProxy
	mockBpfClient     *ebpf.MockBpfClient
	clientPodID       string
	clientPodIP       string
	controllerId      string
}

func (e *Environment) Start(t *testing.T) {
	s := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		ret := new(dns.Msg)
		ret.SetReply(r)
		ret.Answer = append(ret.Answer, test.A("www.example.org. IN A 1.2.3.4"))
		w.WriteMsg(ret)
	})
	e.upstreamDNSServer = s

	contents := `.:9090 {
		bind 127.0.0.1
		log
		ipfilter
		forward . ` + s.Addr + `
	}`

	dnsProxy := cdnsproxy.NewDNSProxy(logger.Get(), &ebpf.MockBpfClient{}, "", "")
	assert.NotNil(t, dnsProxy)
	err := dnsProxy.Start(context.TODO(), contents)
	assert.Nil(t, err)
	e.proxy = dnsProxy

	e.mockBpfClient = &ebpf.MockBpfClient{}
	filter.BpfClient = e.mockBpfClient

	e.clientPodID = "temp_pod_id"
	e.clientPodIP = "127.0.0.1"

	e.controllerId = "test-controller"
}

func (e *Environment) Stop() {
	e.upstreamDNSServer.Close()
	e.proxy.Stop()
	filter.DeletePolicyEndpointDomains(e.clientPodID)
	filter.DeletePodIPToPodIdEntry(e.clientPodIP)
}

func TestCdnsProxyStartup(t *testing.T) {
	e := &Environment{}
	e.Start(t)
	defer e.Stop()

	filter.SetPodIPToPodId("127.0.0.1", "temp_pod_id")

	client := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion("www.example.org.", dns.TypeA)

	// Send query
	resp, _, err := client.Exchange(m, "127.0.0.1:9090")
	if err != nil {
		t.Fatalf("failed to query proxy: %v", err)
	}

	fmt.Printf("%+v", resp)

	if len(resp.Answer) == 0 {
		t.Fatalf("expected an answer, got none")
	}

	if a, ok := resp.Answer[0].(*dns.A); !ok || a.A.String() != "1.2.3.4" {
		t.Fatalf("expected A record 1.2.3.4, got %v", resp.Answer)
	}

	// as there is no DomainRule filter for "temp_pod_id", proxy will not write anything in ebpf map
	assert.Equal(t, uint32(0), e.mockBpfClient.WriteIPsForPodIdCount.Load())
}

func TestProxy_WhenIPFilter_IsPresent(t *testing.T) {
	e := &Environment{}
	e.Start(t)
	defer e.Stop()

	tcpProtocol := corev1.ProtocolTCP
	port80 := int32(80)

	filter.SetPodIPToPodId("127.0.0.1", "temp_pod_id")
	filter.SetPolicyEndpointDomains("temp_pod_id", []fwrp.EbpfFirewallRules{
		{
			DomainName: "www.example.org.",
			L4Info: []v1alpha1.Port{
				{
					Protocol: &tcpProtocol,
					Port:     &port80,
				},
			},
		},
	})

	client := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion("www.example.org.", dns.TypeA)

	// Send query
	resp, _, err := client.Exchange(m, "127.0.0.1:9090")
	if err != nil {
		t.Fatalf("failed to query proxy: %v", err)
	}

	if len(resp.Answer) == 0 {
		t.Fatalf("expected an answer, got none")
	}

	if a, ok := resp.Answer[0].(*dns.A); !ok || a.A.String() != "1.2.3.4" {
		t.Fatalf("expected A record 1.2.3.4, got %v", resp.Answer)
	}

	// as there is DomainRule filter for "temp_pod_id", proxy will write resolved IP and TTL info in ebpf map
	assert.Equal(t, uint32(1), e.mockBpfClient.WriteIPsForPodIdCount.Load())
}

func TestProxy_WhenNoPodIPToPodIdMappingExists(t *testing.T) {
	e := &Environment{}
	e.Start(t)
	defer e.Stop()

	client := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion("www.example.org.", dns.TypeA)

	// Send query
	resp, _, err := client.Exchange(m, "127.0.0.1:9090")
	if err != nil {
		t.Fatalf("failed to query proxy: %v", err)
	}

	fmt.Printf("%+v", resp)

	if len(resp.Answer) == 0 {
		t.Fatalf("expected an answer, got none")
	}

	if a, ok := resp.Answer[0].(*dns.A); !ok || a.A.String() != "1.2.3.4" {
		t.Fatalf("expected A record 1.2.3.4, got %v", resp.Answer)
	}

	assert.Equal(t, uint32(0), e.mockBpfClient.WriteIPsForPodIdCount.Load())
}

func TestProxy_WhenNoFilterExists(t *testing.T) {
	e := &Environment{}
	e.Start(t)
	defer e.Stop()

	filter.SetPodIPToPodId("127.0.0.1", "temp_pod_id")

	client := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion("www.example.org.", dns.TypeA)

	// Send query
	resp, _, err := client.Exchange(m, "127.0.0.1:9090")
	if err != nil {
		t.Fatalf("failed to query proxy: %v", err)
	}

	fmt.Printf("%+v", resp)

	if len(resp.Answer) == 0 {
		t.Fatalf("expected an answer, got none")
	}

	if a, ok := resp.Answer[0].(*dns.A); !ok || a.A.String() != "1.2.3.4" {
		t.Fatalf("expected A record 1.2.3.4, got %v", resp.Answer)
	}

	assert.Equal(t, uint32(0), e.mockBpfClient.WriteIPsForPodIdCount.Load())
}

func TestProxy_WhenIPFilter_Wildcard(t *testing.T) {
	e := &Environment{}
	e.Start(t)
	defer e.Stop()

	tcpProtocol := corev1.ProtocolTCP
	port80 := int32(80)

	filter.SetPodIPToPodId("127.0.0.1", "temp_pod_id")
	filter.SetPolicyEndpointDomains("temp_pod_id", []fwrp.EbpfFirewallRules{
		{
			DomainName: "*.amazon.com.",
			L4Info: []v1alpha1.Port{
				{
					Protocol: &tcpProtocol,
					Port:     &port80,
				},
			},
		},
	})

	client := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion("api.amazon.com.", dns.TypeA)

	// Send query
	resp, _, err := client.Exchange(m, "127.0.0.1:9090")
	if err != nil {
		t.Fatalf("failed to query proxy: %v", err)
	}

	if len(resp.Answer) == 0 {
		t.Fatalf("expected an answer, got none")
	}

	if a, ok := resp.Answer[0].(*dns.A); !ok || a.A.String() != "1.2.3.4" {
		t.Fatalf("expected A record 1.2.3.4, got %v", resp.Answer)
	}

	// as there is DomainRule filter for "temp_pod_id", proxy will write resolved IP and TTL info in ebpf map
	assert.Equal(t, uint32(1), e.mockBpfClient.WriteIPsForPodIdCount.Load())
}

func TestProxy_WhenIPFilter_NoPortsMeansAllPorts(t *testing.T) {
	e := &Environment{}
	e.Start(t)
	defer e.Stop()

	filter.SetPodIPToPodId("127.0.0.1", "temp_pod_id")
	// DNS rule without any L4Info — should be treated as allow-all-ports
	filter.SetPolicyEndpointDomains("temp_pod_id", []fwrp.EbpfFirewallRules{
		{
			DomainName: "www.example.org.",
			L4Info:     []v1alpha1.Port{},
		},
	})

	client := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion("www.example.org.", dns.TypeA)

	resp, _, err := client.Exchange(m, "127.0.0.1:9090")
	if err != nil {
		t.Fatalf("failed to query proxy: %v", err)
	}
	if len(resp.Answer) == 0 {
		t.Fatalf("expected an answer, got none")
	}
	if a, ok := resp.Answer[0].(*dns.A); !ok || a.A.String() != "1.2.3.4" {
		t.Fatalf("expected A record 1.2.3.4, got %v", resp.Answer)
	}

	// Domain was registered despite empty ports, so resolved IP must be written to ebpf map
	assert.Equal(t, uint32(1), e.mockBpfClient.WriteIPsForPodIdCount.Load())
}

func TestProxy_TCPDNSRequest(t *testing.T) {
	e := &Environment{}
	e.Start(t)
	defer e.Stop()

	tcpProtocol := corev1.ProtocolTCP
	port80 := int32(80)

	filter.SetPodIPToPodId("127.0.0.1", "temp_pod_id")
	filter.SetPolicyEndpointDomains("temp_pod_id", []fwrp.EbpfFirewallRules{
		{
			DomainName: "www.example.org.",
			L4Info: []v1alpha1.Port{
				{
					Protocol: &tcpProtocol,
					Port:     &port80,
				},
			},
		},
	})

	// Create TCP DNS client
	client := new(dns.Client)
	client.Net = "tcp" // Set to use TCP instead of UDP

	m := new(dns.Msg)
	m.SetQuestion("www.example.org.", dns.TypeA)

	// Send TCP DNS query
	resp, _, err := client.Exchange(m, "127.0.0.1:9090")
	if err != nil {
		t.Fatalf("failed to query proxy via TCP: %v", err)
	}

	if len(resp.Answer) == 0 {
		t.Fatalf("expected an answer, got none")
	}

	if a, ok := resp.Answer[0].(*dns.A); !ok || a.A.String() != "1.2.3.4" {
		t.Fatalf("expected A record 1.2.3.4, got %v", resp.Answer)
	}

	// Verify that the response was received over TCP
	assert.True(t, resp.Truncated == false, "TCP response should not be truncated")

	// as there is DomainRule filter for "temp_pod_id", proxy will write resolved IP and TTL info in ebpf map
	assert.Equal(t, uint32(1), e.mockBpfClient.WriteIPsForPodIdCount.Load())
}

func TestProxy_LargeDNSResponse_UDPTruncation_TCPFallback(t *testing.T) {
	// Create a custom upstream server that returns a large response
	s := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		ret := new(dns.Msg)
		ret.SetReply(r)

		// Create a large response by adding many TXT records
		// This will exceed the typical UDP packet size limit (~512 bytes)
		for i := 0; i < 50; i++ {
			txtRecord := &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   "large.example.org.",
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Txt: []string{fmt.Sprintf("This is a very long TXT record number %d with lots of text to make the DNS response large enough to exceed UDP limits and trigger truncation", i)},
			}
			ret.Answer = append(ret.Answer, txtRecord)
		}

		// Check if this is a UDP request and the response is large
		if w.RemoteAddr().Network() == "udp" && ret.Len() > 512 {
			ret.Truncated = true
			// Truncate the response for UDP
			ret.Answer = ret.Answer[:5] // Keep only first 5 records for UDP
		}

		w.WriteMsg(ret)
	})
	defer s.Close()

	// Setup proxy with the custom upstream server
	contents := `.:9091 {
		bind 127.0.0.1
		log
		ipfilter
		forward . ` + s.Addr + `
	}`

	dnsProxy := cdnsproxy.NewDNSProxy(logger.Get(), &ebpf.MockBpfClient{}, "", "")
	assert.NotNil(t, dnsProxy)
	err := dnsProxy.Start(context.TODO(), contents)
	assert.Nil(t, err)
	defer dnsProxy.Stop()

	mockBpfClient := &ebpf.MockBpfClient{}
	filter.BpfClient = mockBpfClient

	tcpProtocol := corev1.ProtocolTCP
	port80 := int32(80)

	filter.SetPodIPToPodId("127.0.0.1", "temp_pod_id")
	filter.SetPolicyEndpointDomains("temp_pod_id", []fwrp.EbpfFirewallRules{
		{
			DomainName: "large.example.org.",
			L4Info: []v1alpha1.Port{
				{
					Protocol: &tcpProtocol,
					Port:     &port80,
				},
			},
		},
	})

	// Test 1: UDP request should get truncated response
	udpClient := new(dns.Client)
	udpClient.Net = "udp"
	udpClient.UDPSize = 512 // Set small UDP buffer size

	m := new(dns.Msg)
	m.SetQuestion("large.example.org.", dns.TypeTXT)

	// Send UDP query
	udpResp, _, err := udpClient.Exchange(m, "127.0.0.1:9091")
	if err != nil {
		t.Fatalf("failed to query proxy via UDP: %v", err)
	}

	fmt.Printf("UDP DNS Response (should be truncated): %+v\n", udpResp)

	// Verify UDP response is truncated
	assert.True(t, udpResp.Truncated, "UDP response should be truncated due to size")
	assert.True(t, len(udpResp.Answer) < 50, "UDP response should have fewer records due to truncation")

	// Test 2: TCP request should get full response
	tcpClient := new(dns.Client)
	tcpClient.Net = "tcp"

	m2 := new(dns.Msg)
	m2.SetQuestion("large.example.org.", dns.TypeTXT)

	// Send TCP query
	tcpResp, _, err := tcpClient.Exchange(m2, "127.0.0.1:9091")
	if err != nil {
		t.Fatalf("failed to query proxy via TCP: %v", err)
	}

	// Verify TCP response is complete
	assert.False(t, tcpResp.Truncated, "TCP response should not be truncated")
	assert.Equal(t, 50, len(tcpResp.Answer), "TCP response should have all 50 TXT records")

	// Verify all records are TXT records
	for i, answer := range tcpResp.Answer {
		if txt, ok := answer.(*dns.TXT); ok {
			assert.Contains(t, txt.Txt[0], fmt.Sprintf("number %d", i), "TXT record should contain expected content")
		} else {
			t.Fatalf("expected TXT record, got %T", answer)
		}
	}
}

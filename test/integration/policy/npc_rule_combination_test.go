package policy

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/manifest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
)

// PolicyEndpoint simplified struct for parsing kubectl output
type PolicyEndpointEgress struct {
	CIDR   string                 `json:"cidr"`
	Except []string               `json:"except"`
	Ports  []map[string]interface{} `json:"ports"`
}

type PolicyEndpointSpec struct {
	Egress []PolicyEndpointEgress `json:"egress"`
}

type PolicyEndpointItem struct {
	Spec PolicyEndpointSpec `json:"spec"`
}

type PolicyEndpointList struct {
	Items []PolicyEndpointItem `json:"items"`
}

// test to validate NPC's combining logic
var _ = Describe("Rules Combining Validation", func() {

	Context("Single NetworkPolicy with 2 rules: same CIDR+exceptions, different ports", func() {
		var (
			np             *network.NetworkPolicy
			testNamespace  = "test-combining"
		)

		BeforeEach(func() {
			By("Creating test namespace")
			err := fw.NamespaceManager.CreateNamespace(ctx, testNamespace)
			Expect(err).ToNot(HaveOccurred())

			By("Creating NetworkPolicy with 2 egress rules (ports 80 and 443)")
			// Rule 1: Port 80 to 10.0.0.0/8 except 10.1.0.0/16
			rule1 := manifest.NewEgressRuleBuilder().
				AddPeer(nil, nil, "10.0.0.0/8", "10.1.0.0/16").
				AddPort(80, v1.ProtocolTCP).
				Build()

			// Rule 2: Port 443 to 10.0.0.0/8 except 10.1.0.0/16
			rule2 := manifest.NewEgressRuleBuilder().
				AddPeer(nil, nil, "10.0.0.0/8", "10.1.0.0/16").
				AddPort(443, v1.ProtocolTCP).
				Build()

			np = manifest.NewNetworkPolicyBuilder().
				Namespace(testNamespace).
				Name("test-combining-policy").
				PodSelector("app", "testpod").
				SetPolicyType(false, true).
				AddEgressRule(rule1).
				AddEgressRule(rule2).
				Build()

			err = fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, np)
			Expect(err).ToNot(HaveOccurred())

			By("Creating test pod to trigger PolicyEndpoint creation")
			container := manifest.NewBusyBoxContainerBuilder().
				ImageRepository(fw.Options.TestImageRegistry).
				Command([]string{"/bin/sh", "-c"}).
				Args([]string{"sleep 3600"}).
				Build()

			pod := manifest.NewDefaultPodBuilder().
				Name("testpod").
				Namespace(testNamespace).
				AddLabel("app", "testpod").
				Container(container).
				Build()

			_, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, pod, 2*time.Minute)
			Expect(err).ToNot(HaveOccurred())
		})

		It("should combine rules with same CIDR+exceptions into single PolicyEndpoint entry", func() {
			By("Waiting for PolicyEndpoints to be created")
			time.Sleep(10 * time.Second)

			By("Getting PolicyEndpoints using kubectl")
			cmd := exec.Command("kubectl", "get", "policyendpoints", "-n", testNamespace, "-o", "json")
			output, err := cmd.CombinedOutput()
			Expect(err).ToNot(HaveOccurred())

			var peList PolicyEndpointList
			err = json.Unmarshal(output, &peList)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(peList.Items)).To(BeNumerically(">", 0))

			By("Searching for target rule with CIDR=10.0.0.0/8 and Exception=10.1.0.0/16")
			var targetPorts []map[string]interface{}
			var foundTargetRule bool
			
			for _, pe := range peList.Items {
				for _, egress := range pe.Spec.Egress {
					if egress.CIDR == "10.0.0.0/8" && len(egress.Except) == 1 && egress.Except[0] == "10.1.0.0/16" {
						foundTargetRule = true
						targetPorts = egress.Ports
						fmt.Printf("\nFound target rule: CIDR=%s, Exceptions=%v, Ports=%d\n", 
							egress.CIDR, egress.Except, len(egress.Ports))
						break
					}
				}
			}
			
			By("Validating both ports 80 and 443 are in the combined entry")
			var foundPort80, foundPort443 bool
			for _, port := range targetPorts {
				if portNum, ok := port["port"].(float64); ok {
					if int(portNum) == 80 {
						foundPort80 = true
					}
					if int(portNum) == 443 {
						foundPort443 = true
					}
				}
			}
			
			Expect(foundTargetRule).To(BeTrue(), "Should find target rule")
			Expect(foundPort80).To(BeTrue(), "Should have port 80")
			Expect(foundPort443).To(BeTrue(), "Should have port 443")
			
			fmt.Printf("Ports: 80=%v, 443=%v\n", foundPort80, foundPort443)
			fmt.Printf("TEST PASSED: Rules combined\n\n")
		})

		AfterEach(func() {
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, np)
			fw.NamespaceManager.DeleteAndWaitTillNamespaceDeleted(ctx, testNamespace)
		})
	})

	Context("NetworkPolicy with all-ports wildcard", func() {
		var (
			np             *network.NetworkPolicy
			testNamespace  = "test-allports"
		)

		BeforeEach(func() {
			By("Creating test namespace")
			err := fw.NamespaceManager.CreateNamespace(ctx, testNamespace)
			Expect(err).ToNot(HaveOccurred())

			By("Creating NetworkPolicy with 2 rules: port-specific + all-ports wildcard")
			// Rule 1: Port 53 to 172.16.0.0/12 except 172.17.0.0/16
			rule1 := manifest.NewEgressRuleBuilder().
				AddPeer(nil, nil, "172.16.0.0/12", "172.17.0.0/16").
				AddPort(53, v1.ProtocolUDP).
				Build()

			// Rule 2: ALL PORTS to 172.16.0.0/12 except 172.17.0.0/16 (no ports = wildcard)
			rule2 := manifest.NewEgressRuleBuilder().
				AddPeer(nil, nil, "172.16.0.0/12", "172.17.0.0/16").
				Build()

			np = manifest.NewNetworkPolicyBuilder().
				Namespace(testNamespace).
				Name("test-allports-policy").
				PodSelector("app", "testpod").
				SetPolicyType(false, true).
				AddEgressRule(rule1).
				AddEgressRule(rule2).
				Build()

			err = fw.NetworkPolicyManager.CreateNetworkPolicy(ctx, np)
			Expect(err).ToNot(HaveOccurred())

			By("Creating test pod to trigger PolicyEndpoint creation")
			container := manifest.NewBusyBoxContainerBuilder().
				ImageRepository(fw.Options.TestImageRegistry).
				Command([]string{"/bin/sh", "-c"}).
				Args([]string{"sleep 3600"}).
				Build()

			pod := manifest.NewDefaultPodBuilder().
				Name("testpod").
				Namespace(testNamespace).
				AddLabel("app", "testpod").
				Container(container).
				Build()

			_, err = fw.PodManager.CreateAndWaitTillPodIsRunning(ctx, pod, 2*time.Minute)
			Expect(err).ToNot(HaveOccurred())
		})

		It("should preserve all-ports rule - empty ports wins over port-specific", func() {
			By("Waiting for PolicyEndpoints to be created")
			time.Sleep(10 * time.Second)

			By("Getting PolicyEndpoints")
			cmd := exec.Command("kubectl", "get", "policyendpoints", "-n", testNamespace, "-o", "json")
			output, err := cmd.CombinedOutput()
			Expect(err).ToNot(HaveOccurred())

			var peList PolicyEndpointList
			err = json.Unmarshal(output, &peList)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(peList.Items)).To(BeNumerically(">", 0))

			By("Searching for target rule with CIDR=172.16.0.0/12 and Exception=172.17.0.0/16")
			var foundTargetWithEmptyPorts bool
			
			for _, pe := range peList.Items {
				for _, egress := range pe.Spec.Egress {
					if egress.CIDR == "172.16.0.0/12" && len(egress.Except) == 1 && egress.Except[0] == "172.17.0.0/16" {
						fmt.Printf("\n✓ Found target rule: CIDR=%s, Exceptions=%v, Ports=%d\n", 
							egress.CIDR, egress.Except, len(egress.Ports))
						
						if len(egress.Ports) == 0 {
							foundTargetWithEmptyPorts = true
							fmt.Printf("  [] - ALL PORTS present\n")
						} else {
							fmt.Printf("  Has %d ports\n", len(egress.Ports))
						}
						break
					}
				}
			}
			
			Expect(foundTargetWithEmptyPorts).To(BeTrue(), "Should find entry with empty ports (all-ports wildcard)")
			
			fmt.Printf(" TEST PASSED: All-ports preserved\n\n")
		})

		AfterEach(func() {
			fw.NetworkPolicyManager.DeleteNetworkPolicy(ctx, np)
			fw.NamespaceManager.DeleteAndWaitTillNamespaceDeleted(ctx, testNamespace)
		})
	})
})

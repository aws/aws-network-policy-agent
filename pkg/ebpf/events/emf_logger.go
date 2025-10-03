package events

import (
	"encoding/json"
	"time"
)

// EMFMetricData represents an EMF (Embedded Metric Format) log entry
// This format allows CloudWatch to automatically extract metrics from logs
type EMFMetricData struct {
	AWS       EMFMetadata     `json:"_aws"`
	Timestamp int64           `json:"timestamp"`
	Event     PolicyEventData `json:"event"`
	Metric    map[string]int  `json:"metric_value"` // For the actual metric value
}

// EMFMetadata contains CloudWatch EMF metadata
type EMFMetadata struct {
	Timestamp         int64                  `json:"Timestamp"`
	CloudWatchMetrics []CloudWatchMetricSpec `json:"CloudWatchMetrics"`
}

// CloudWatchMetricSpec defines the metric specification for EMF
type CloudWatchMetricSpec struct {
	Namespace  string             `json:"Namespace"`
	Dimensions [][]string         `json:"Dimensions"`
	Metrics    []MetricDefinition `json:"Metrics"`
}

// MetricDefinition defines a single metric
type MetricDefinition struct {
	Name string `json:"Name"`
	Unit string `json:"Unit"`
}

// PolicyEventData contains all the event details
type PolicyEventData struct {
	// Common fields
	MetricName string `json:"metric_name"`
	Direction  string `json:"direction"`
	SrcIP      string `json:"src_ip"`
	DstIP      string `json:"dst_ip"`
	SrcPort    int    `json:"src_port"`
	DstPort    int    `json:"dst_port"`
	Protocol   string `json:"protocol"`

	// Pod information
	SrcPodName string `json:"src_pod_name,omitempty"`
	DstPodName string `json:"dst_pod_name,omitempty"`

	// Policy information (only for ACCEPT verdicts)
	PolicyName      string `json:"policy_name,omitempty"`
	PolicyNamespace string `json:"policy_namespace,omitempty"`

	// Additional metadata
	NodeName string `json:"node_name"`
	Verdict  string `json:"verdict"`
}

// CreateEMFLogForIngressAccept creates an EMF log for ingress L4 connections accepted
func CreateEMFLogForIngressAccept(
	nodeName, policyName, policyNamespace, srcIP, dstIP, dstPodName, protocol string,
	srcPort, dstPort int,
) string {
	return createEMFLog(
		"ingress_l4_connections_accepted",
		"ingress",
		"ACCEPT",
		nodeName,
		policyName,
		policyNamespace,
		srcIP,
		dstIP,
		"",
		dstPodName,
		protocol,
		srcPort,
		dstPort,
	)
}

// CreateEMFLogForEgressAccept creates an EMF log for egress L4 connections accepted
func CreateEMFLogForEgressAccept(
	nodeName, policyName, policyNamespace, srcIP, dstIP, srcPodName, protocol string,
	srcPort, dstPort int,
) string {
	return createEMFLog(
		"egress_l4_connections_accepted",
		"egress",
		"ACCEPT",
		nodeName,
		policyName,
		policyNamespace,
		srcIP,
		dstIP,
		srcPodName,
		"",
		protocol,
		srcPort,
		dstPort,
	)
}

// CreateEMFLogForIngressDenied creates an EMF log for ingress L4 connections denied
func CreateEMFLogForIngressDenied(
	nodeName, srcIP, dstIP, dstPodName, protocol string,
	srcPort, dstPort int,
) string {
	return createEMFLog(
		"ingress_l4_connections_denied",
		"ingress",
		"DENY",
		nodeName,
		"",
		"",
		srcIP,
		dstIP,
		"",
		dstPodName,
		protocol,
		srcPort,
		dstPort,
	)
}

// CreateEMFLogForEgressDenied creates an EMF log for egress L4 connections denied
func CreateEMFLogForEgressDenied(
	nodeName, srcIP, dstIP, srcPodName, protocol string,
	srcPort, dstPort int,
) string {
	return createEMFLog(
		"egress_l4_connections_denied",
		"egress",
		"DENY",
		nodeName,
		"",
		"",
		srcIP,
		dstIP,
		srcPodName,
		"",
		protocol,
		srcPort,
		dstPort,
	)
}

// CreateEMFLogForIngressDropped creates an EMF log for ingress L4 connections dropped
func CreateEMFLogForIngressDropped(
	nodeName, srcIP, dstIP, dstPodName, protocol string,
	srcPort, dstPort int,
) string {
	return createEMFLog(
		"ingress_l4_connections_dropped",
		"ingress",
		"DROPPED",
		nodeName,
		"",
		"",
		srcIP,
		dstIP,
		"",
		dstPodName,
		protocol,
		srcPort,
		dstPort,
	)
}

// CreateEMFLogForEgressDropped creates an EMF log for egress L4 connections dropped
func CreateEMFLogForEgressDropped(
	nodeName, srcIP, dstIP, srcPodName, protocol string,
	srcPort, dstPort int,
) string {
	return createEMFLog(
		"egress_l4_connections_dropped",
		"egress",
		"DROPPED",
		nodeName,
		"",
		"",
		srcIP,
		dstIP,
		srcPodName,
		"",
		protocol,
		srcPort,
		dstPort,
	)
}

// createEMFLog is the core function that creates an EMF formatted log entry
func createEMFLog(
	metricName, direction, verdict, nodeName, policyName, policyNamespace,
	srcIP, dstIP, srcPodName, dstPodName, protocol string,
	srcPort, dstPort int,
) string {
	timestamp := time.Now().UnixMilli()

	// Build event data
	eventData := PolicyEventData{
		MetricName: metricName,
		Direction:  direction,
		SrcIP:      srcIP,
		DstIP:      dstIP,
		SrcPort:    srcPort,
		DstPort:    dstPort,
		Protocol:   protocol,
		NodeName:   nodeName,
		Verdict:    verdict,
	}

	// Add optional fields
	if srcPodName != "" {
		eventData.SrcPodName = srcPodName
	}
	if dstPodName != "" {
		eventData.DstPodName = dstPodName
	}
	if policyName != "" {
		eventData.PolicyName = policyName
	}
	if policyNamespace != "" {
		eventData.PolicyNamespace = policyNamespace
	}

	// Define dimensions based on metric type
	dimensions := buildDimensions(metricName, policyNamespace, policyName)

	// Create EMF structure
	emfData := EMFMetricData{
		AWS: EMFMetadata{
			Timestamp: timestamp,
			CloudWatchMetrics: []CloudWatchMetricSpec{
				{
					Namespace:  "AWSNetworkPolicy",
					Dimensions: dimensions,
					Metrics: []MetricDefinition{
						{
							Name: metricName,
							Unit: "Count",
						},
					},
				},
			},
		},
		Timestamp: timestamp,
		Event:     eventData,
		Metric: map[string]int{
			metricName: 1, // Each log entry represents 1 connection
		},
	}

	// Marshal to JSON
	jsonBytes, err := json.Marshal(emfData)
	if err != nil {
		log().Errorf("Failed to marshal EMF data: %v", err)
		return ""
	}

	return string(jsonBytes)
}

// buildDimensions creates dimension sets for CloudWatch metrics based on metric type
func buildDimensions(metricName, policyNamespace, policyName string) [][]string {
	// For accepted connections, include policy dimensions
	if metricName == "ingress_l4_connections_accepted" || metricName == "egress_l4_connections_accepted" {
		return [][]string{
			{"MetricName"},                                  // Dimension set 1: Just the metric
			{"MetricName", "PolicyNamespace"},               // Dimension set 2: Metric + namespace
			{"MetricName", "PolicyNamespace", "PolicyName"}, // Dimension set 3: All policy info
		}
	}

	// For denied and dropped connections, only metric dimension
	return [][]string{
		{"MetricName"},
	}
}

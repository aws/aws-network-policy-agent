// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package rpc

import (
	"context"
	"os"
	"testing"

	"github.com/aws/amazon-vpc-cni-k8s/rpc"
	"github.com/aws/aws-network-policy-agent/controllers"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/stretchr/testify/assert"
)

func TestRunRPCHandler_NoExistingSocket(t *testing.T) {
	testSocketPath := "/tmp/test-rpc-handler.sock"
	defer os.Remove(testSocketPath)

	errCh, err := RunRPCHandler(nil, nil, testSocketPath)
	assert.Nil(t, err)
	assert.NotNil(t, errCh)
}

func TestRunRPCHandler_StaleSocketCleanup(t *testing.T) {
	testSocketPath := "/tmp/temp-rpc-handler.sock"

	// Create a stale socket file
	file, err := os.Create(testSocketPath)
	if err != nil {
		t.Fatalf("Failed to create stale socket file: %v", err)
	}
	file.Close()
	defer os.Remove(testSocketPath)

	errCh, err := RunRPCHandler(nil, nil, testSocketPath)
	assert.Nil(t, err)
	assert.NotNil(t, errCh)
}

func TestEnforceNpToPod_ClearDeletedPodBeforeAttach(t *testing.T) {
	mockBpfClient := &ebpf.MockBpfClient{}
	reconciler := controllers.NewPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient, false)
	clusterReconciler := controllers.NewClusterPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient)

	s := &server{
		policyReconciler:        reconciler,
		clusterPolicyReconciler: clusterReconciler,
	}

	resp, err := s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
		K8S_POD_NAME:        "nginx-abc123",
		K8S_POD_NAMESPACE:   "default",
		NETWORK_POLICY_MODE: "standard",
		InterfaceCount:      1,
	})
	assert.NoError(t, err)
	assert.True(t, resp.Success)

	// ClearDeletedPod must appear before AttacheBPFProbes
	assert.Equal(t, "ClearDeletedPod", mockBpfClient.CallLog[1])
	assert.Equal(t, "AttacheBPFProbes", mockBpfClient.CallLog[2])
}

func TestEnforceNpToPod_NilClusterPolicyReconciler_ReturnsError(t *testing.T) {
	mockBpfClient := &ebpf.MockBpfClient{}
	reconciler := controllers.NewPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient, false)

	s := &server{
		policyReconciler:        reconciler,
		clusterPolicyReconciler: nil,
	}

	resp, err := s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
		K8S_POD_NAME:        "nginx-abc123",
		K8S_POD_NAMESPACE:   "default",
		NETWORK_POLICY_MODE: "standard",
		InterfaceCount:      1,
	})
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Empty(t, mockBpfClient.CallLog)
}

func TestEnforceNpToPod_NilClusterPolicyEBPFClient_ReturnsError(t *testing.T) {
	mockBpfClient := &ebpf.MockBpfClient{}
	reconciler := controllers.NewPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient, false)
	// clusterReconciler with nil eBPF client
	clusterReconciler := controllers.NewClusterPolicyEndpointsReconciler(nil, "10.0.0.1", nil)

	s := &server{
		policyReconciler:        reconciler,
		clusterPolicyReconciler: clusterReconciler,
	}

	resp, err := s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
		K8S_POD_NAME:        "nginx-abc123",
		K8S_POD_NAMESPACE:   "default",
		NETWORK_POLICY_MODE: "standard",
		InterfaceCount:      1,
	})
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Empty(t, mockBpfClient.CallLog)
}

func TestEnforceNpToPod_OneReconcilerReady_ReturnsError(t *testing.T) {
	// Reverse case: clusterPolicyReconciler is ready but policyReconciler is nil
	mockBpfClient := &ebpf.MockBpfClient{}
	clusterReconciler := controllers.NewClusterPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient)

	s := &server{
		policyReconciler:        nil,
		clusterPolicyReconciler: clusterReconciler,
	}

	resp, err := s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
		K8S_POD_NAME:        "nginx-abc123",
		K8S_POD_NAMESPACE:   "default",
		NETWORK_POLICY_MODE: "standard",
		InterfaceCount:      1,
	})
	assert.Error(t, err)
	assert.False(t, resp.Success)
	assert.Contains(t, err.Error(), "One of the policy reconcilers is not ready")
	assert.Empty(t, mockBpfClient.CallLog)
}

func TestEnforceNpToPod_BothReconcilersNil_ReturnsSuccess(t *testing.T) {
	s := &server{
		policyReconciler:        nil,
		clusterPolicyReconciler: nil,
	}

	resp, err := s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
		K8S_POD_NAME:        "nginx-abc123",
		K8S_POD_NAMESPACE:   "default",
		NETWORK_POLICY_MODE: "standard",
		InterfaceCount:      1,
	})
	assert.NoError(t, err)
	assert.True(t, resp.Success)
}

func TestEnforceNpToPod_NoPolicies_UpdatesBothPodStateMaps(t *testing.T) {
	mockBpfClient := &ebpf.MockBpfClient{}
	reconciler := controllers.NewPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient, false)
	clusterReconciler := controllers.NewClusterPolicyEndpointsReconciler(nil, "10.0.0.1", mockBpfClient)

	s := &server{
		policyReconciler:        reconciler,
		clusterPolicyReconciler: clusterReconciler,
	}

	resp, err := s.EnforceNpToPod(context.Background(), &rpc.EnforceNpRequest{
		K8S_POD_NAME:        "nginx-abc123",
		K8S_POD_NAMESPACE:   "default",
		NETWORK_POLICY_MODE: "standard",
		InterfaceCount:      1,
	})
	assert.NoError(t, err)
	assert.True(t, resp.Success)

	// With no policies and IsFirstPodInPodIdentifier returning false,
	// the "no active policies" branch fires and calls UpdatePodStateEbpfMaps twice:
	// once for POD_STATE_MAP_KEY and once for CLUSTER_POLICY_POD_STATE_MAP_KEY
	updateCount := 0
	for _, call := range mockBpfClient.CallLog {
		if call == "UpdatePodStateEbpfMaps" {
			updateCount++
		}
	}
	assert.Equal(t, 2, updateCount, "should update both pod state map and cluster policy pod state map")
}

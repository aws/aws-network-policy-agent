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

	s := &server{
		policyReconciler: reconciler,
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

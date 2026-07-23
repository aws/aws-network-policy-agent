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
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// startTestHealthServer starts a gRPC server with the standard health service
// registered on a Unix socket at socketPath, reporting status for
// grpcHealthServiceName. It returns a stop function to shut the server down.
func startTestHealthServer(t *testing.T, socketPath string, status healthpb.HealthCheckResponse_ServingStatus) func() {
	t.Helper()

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)

	grpcServer := grpc.NewServer()
	healthServer := health.NewServer()
	healthServer.SetServingStatus(grpcHealthServiceName, status)
	healthpb.RegisterHealthServer(grpcServer, healthServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()

	return func() {
		grpcServer.Stop()
		_ = os.Remove(socketPath)
	}
}

func TestGRPCSocketHealthChecker_Serving(t *testing.T) {
	socketPath := "/tmp/test-healthcheck-serving.sock"
	_ = os.Remove(socketPath)
	stop := startTestHealthServer(t, socketPath, healthpb.HealthCheckResponse_SERVING)
	defer stop()

	checker, err := NewGRPCSocketHealthChecker(socketPath)
	require.NoError(t, err)
	defer checker.Close()
	assert.NoError(t, checker.Check(nil))
}

func TestGRPCSocketHealthChecker_NotServing(t *testing.T) {
	socketPath := "/tmp/test-healthcheck-notserving.sock"
	_ = os.Remove(socketPath)
	stop := startTestHealthServer(t, socketPath, healthpb.HealthCheckResponse_NOT_SERVING)
	defer stop()

	checker, err := NewGRPCSocketHealthChecker(socketPath)
	require.NoError(t, err)
	defer checker.Close()
	err = checker.Check(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "non-serving status")
}

func TestGRPCSocketHealthChecker_MissingSocket(t *testing.T) {
	socketPath := "/tmp/test-healthcheck-missing.sock"
	// Ensure nothing is listening at this path.
	_ = os.Remove(socketPath)

	checker, err := NewGRPCSocketHealthChecker(socketPath)
	require.NoError(t, err)
	defer checker.Close()
	err = checker.Check(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "grpc health check failed")
}

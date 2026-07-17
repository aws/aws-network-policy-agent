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
	"fmt"
	"net"
	"net/http"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

const grpcCheckTimeout = 5 * time.Second

// GRPCSocketHealthChecker issues gRPC Health/Check RPCs against the NPA Unix
// socket. It holds a single long-lived gRPC client reused across probe
// invocations rather than rebuilding one per call.
type GRPCSocketHealthChecker struct {
	conn   *grpc.ClientConn
	client healthpb.HealthClient
}

// NewGRPCSocketHealthChecker creates a health checker for the Unix socket at
// socketPath. grpc.NewClient performs no I/O and connects lazily on the first
// Check, so this succeeds even when the server is not yet listening.
func NewGRPCSocketHealthChecker(socketPath string) (*GRPCSocketHealthChecker, error) {
	conn, err := grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("grpc NewClient for %s failed: %w", socketPath, err)
	}
	return &GRPCSocketHealthChecker{
		conn:   conn,
		client: healthpb.NewHealthClient(conn),
	}, nil
}

// Check implements the controller-runtime healthz.Checker signature.
func (c *GRPCSocketHealthChecker) Check(r *http.Request) error {
	baseCtx := context.Background()
	if r != nil {
		baseCtx = r.Context()
	}
	ctx, cancel := context.WithTimeout(baseCtx, grpcCheckTimeout)
	defer cancel()

	resp, err := c.client.Check(ctx, &healthpb.HealthCheckRequest{
		Service: grpcHealthServiceName,
	})
	if err != nil {
		err = fmt.Errorf("grpc health check failed: %w", err)
		log().Errorf("grpc-socket check failed: %v", err)
		return err
	}
	if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		err = fmt.Errorf("grpc health check returned non-serving status: %s", resp.GetStatus())
		log().Errorf("grpc-socket check failed: %v", err)
		return err
	}
	return nil
}

// Close releases the underlying gRPC client connection.
func (c *GRPCSocketHealthChecker) Close() error {
	return c.conn.Close()
}

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

const livenessCheckTimeout = 10 * time.Second

// NewGRPCSocketLivenessCheck returns a health check that issues a gRPC
// Health/Check RPC against the NPA Unix socket at socketPath.
func NewGRPCSocketLivenessCheck(socketPath string) func(_ *http.Request) error {
	return func(_ *http.Request) error {
		ctx, cancel := context.WithTimeout(context.Background(), livenessCheckTimeout)
		defer cancel()

		conn, err := grpc.NewClient(
			"unix://"+socketPath,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			}),
		)
		if err != nil {
			err = fmt.Errorf("grpc NewClient for %s failed: %w", socketPath, err)
			log().Errorf("grpc-socket check failed: %v", err)
			return err
		}
		defer conn.Close()

		client := healthpb.NewHealthClient(conn)
		resp, err := client.Check(ctx, &healthpb.HealthCheckRequest{
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
}

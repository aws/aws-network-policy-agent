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

package rpcclient

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// GRPC is the ipamd client Dial interface
type GRPCClient interface {
	Dial(ctx context.Context, target string, opts ...grpc.DialOption) (*grpc.ClientConn, error)
}

type NPAgentRPC struct{}

// New creates a new cniGRPC
func New() GRPCClient {
	return &NPAgentRPC{}
}

func (n *NPAgentRPC) Dial(ctx context.Context, target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	return grpc.DialContext(ctx, target, opts...)
}

func GetDefaultServiceRetryConfig() grpc.DialOption {

	// The retry policy for the request made to IPAM server. It waits for the IPAM GRPC to be up before initiating retry policy
	config := `{
		"methodConfig": [{
			"name": [{"service": "rpc.ConfigServerBackend"}],
			"waitForReady": true,
			"retryPolicy": {
				"MaxAttempts": 5,
				"InitialBackoff": "0.5s",
				"MaxBackoff": "10s",
				"BackoffMultiplier": 1.1,
				"RetryableStatusCodes": [ "UNAVAILABLE", "ABORTED", "UNKNOWN"]
			}
		}]
	}`
	return grpc.WithDefaultServiceConfig(config)
}

func GetInsecureConnectionType() grpc.DialOption {
	return grpc.WithTransportCredentials(insecure.NewCredentials())
}

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
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// On a new node the agent dials ipamd before ipamd listens. The time between ipamd listening and the agent
// connecting is time in which the CNI is ready but the agent does not serve npa.sock yet.
func TestFastReconnectFindsLateServerQuickly(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "ipamd.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := New().Dial(ctx, "unix://"+sock, GetInsecureConnectionType(), GetFastReconnectParams())
	require.NoError(t, err)
	defer conn.Close()

	// With grpc's default backoff the attempts are at about 0, 1 and 2.6 s, so a server that
	// starts at 1.25 s is found 0.8 s late or more.
	serverUp := make(chan time.Time, 1)
	time.AfterFunc(1250*time.Millisecond, func() {
		l, err := net.Listen("unix", sock)
		if err != nil {
			panic(err)
		}
		s := grpc.NewServer()
		healthpb.RegisterHealthServer(s, health.NewServer())
		serverUp <- time.Now()
		go s.Serve(l)
		t.Cleanup(s.Stop)
	})

	_, err = healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{}, grpc.WaitForReady(true))
	require.NoError(t, err)
	assert.Less(t, time.Since(<-serverUp), 750*time.Millisecond)
}

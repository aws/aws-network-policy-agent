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
	"net"
	"time"

	"github.com/aws/aws-network-policy-agent/controllers"
	"github.com/aws/aws-network-policy-agent/pkg/utils"

	pb "github.com/emilyhuaa/policyLogsEnhancement/pkg/rpc"

	rpc "github.com/aws/amazon-vpc-cni-k8s/rpc"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	npgRPCaddress            = "127.0.0.1:50052"
	grpcHealthServiceName    = "grpc.health.v1.np-agent"
	metadataServiceName      = "aws-k8s-metadata-service"
	metadataServiceNamespace = "default"
)

// server controls RPC service responses.
type server struct {
	policyReconciler *controllers.PolicyEndpointsReconciler
	log              logr.Logger
	cacheClient      pb.CacheServiceClient
}

// EnforceNpToPod processes CNI Enforce NP network request
func (s *server) EnforceNpToPod(ctx context.Context, in *rpc.EnforceNpRequest) (*rpc.EnforceNpReply, error) {
	s.log.Info("Received Enforce Network Policy Request for Pod", "Name", in.K8S_POD_NAME, "Namespace", in.K8S_POD_NAMESPACE)
	var err error

	podIdentifier := utils.GetPodIdentifier(in.K8S_POD_NAME, in.K8S_POD_NAMESPACE, s.log)
	isMapUpdateRequired := s.policyReconciler.GeteBPFClient().IsMapUpdateRequired(podIdentifier)
	err = s.policyReconciler.GeteBPFClient().AttacheBPFProbes(types.NamespacedName{Name: in.K8S_POD_NAME, Namespace: in.K8S_POD_NAMESPACE},
		podIdentifier, true, true)
	if err != nil {
		s.log.Error(err, "Attaching eBPF probe failed for", "pod", in.K8S_POD_NAME, "namespace", in.K8S_POD_NAMESPACE)
		return nil, err
	}

	// We attempt to program eBPF firewall map entries for this pod, if the local agent is aware of the policies
	// configured against it. For example, if this is a new replica of an existing pod/deployment then the local
	// node agent will have the policy information available to it. If not, we will leave the pod in default deny state
	// until the Network Policy controller reconciles existing policies against this pod.

	// Check if there are active policies against the new pod and if there are other pods on the local node that share
	// the eBPF firewall maps with the newly launched pod, if already present we can skip the map update and return
	if s.policyReconciler.ArePoliciesAvailableInLocalCache(podIdentifier) && isMapUpdateRequired {
		// If we're here, then the local agent knows the list of active policies that apply to this pod and
		// this is the first pod of it's type to land on the local node/cluster
		s.log.Info("Active policies present against this pod and this is a new Pod to the local node, configuring firewall rules....")

		//Derive Ingress and Egress Firewall Rules and Update the relevant eBPF maps
		ingressRules, egressRules, _ :=
			s.policyReconciler.DeriveFireWallRulesPerPodIdentifier(podIdentifier, in.K8S_POD_NAMESPACE)

		err = s.policyReconciler.GeteBPFClient().UpdateEbpfMaps(podIdentifier, ingressRules, egressRules)
		if err != nil {
			s.log.Error(err, "Map update(s) failed for, ", "podIdentifier ", podIdentifier)
			return nil, err
		}
	} else {
		s.log.Info("Pod either has no active policies or shares the eBPF firewall maps with other local pods. No Map update required..")
	}

	resp := rpc.EnforceNpReply{
		Success: err == nil,
	}
	return &resp, nil
}

// newCacheClient creates a new gRPC client for the CacheService.
// It takes the address of the gRPC server as input and returns a CacheServiceClient and an error.
func newCacheClient(address string) (pb.CacheServiceClient, error) {
	conn, err := grpc.NewClient(
		address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}
	return pb.NewCacheServiceClient(conn), nil
}

// syncLocalCache is a method of the server struct that continuously syncs the local cache
// with the metadata cache using a gRPC client.
func (s *server) syncLocalCache() {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)

		req := &pb.CacheRequest{}
		res, err := s.cacheClient.GetCache(ctx, req)
		cancel()

		if err != nil {
			// If there was an error fetching the cache data, log the error and sleep for 30 seconds before retrying.
			s.log.Error(err, "Failed to sync local cache with metadata cache")
			time.Sleep(30 * time.Second)
			continue
		}

		newCache := make(map[string]utils.Metadata)
		for _, ipMetadata := range res.Data {
			newCache[ipMetadata.Ip] = utils.Metadata{Name: ipMetadata.Metadata.Name, Namespace: ipMetadata.Metadata.Namespace}
		}
		utils.UpdateLocalCache(newCache)
		s.log.Info("Successfully synced local cache with metadata cache", "local cache", utils.LocalCache)

		time.Sleep(30 * time.Second)
	}
}

// RunRPCHandler handles request from gRPC
func RunRPCHandler(policyReconciler *controllers.PolicyEndpointsReconciler, clientset *kubernetes.Clientset) error {
	rpcLog := ctrl.Log.WithName("rpc-handler")

	rpcLog.Info("Serving RPC Handler", "Address", npgRPCaddress)
	listener, err := net.Listen("tcp", npgRPCaddress)
	if err != nil {
		rpcLog.Error(err, "Failed to listen gRPC port")
		return errors.Wrap(err, "network policy agent: failed to listen to gRPC port")
	}
	grpcServer := grpc.NewServer()

	// Connect to metadata cache service
	serviceIP, _ := utils.GetServiceIP(clientset, metadataServiceName, metadataServiceNamespace)
	cacheClient, err := newCacheClient(serviceIP + ":50051")
	if err != nil {
		rpcLog.Error(err, "unable to connect to aws-k8s-metadata service, continuing without")
		utils.CacheClientConnected = false
	} else {
		utils.CacheClientConnected = true
	}

	s := &server{
		policyReconciler: policyReconciler,
		log:              rpcLog,
		cacheClient:      cacheClient,
	}

	if utils.CacheClientConnected {
		go s.syncLocalCache()
	}

	rpc.RegisterNPBackendServer(grpcServer, s)

	healthServer := health.NewServer()
	// No need to ever change this to HealthCheckResponse_NOT_SERVING since it's a local service only
	healthServer.SetServingStatus(grpcHealthServiceName, healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(grpcServer, healthServer)

	// Register reflection service on gRPC server.
	reflection.Register(grpcServer)
	if err := grpcServer.Serve(listener); err != nil {
		rpcLog.Error(err, "Failed to start server on gRPC port: %v", err)
		return errors.Wrap(err, "network policy agent: failed to start server on gPRC port")
	}
	rpcLog.Info("Done with RPC Handler initialization")
	return nil
}

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
	"sync"

	"github.com/aws/aws-network-policy-agent/controllers"
	"github.com/aws/aws-network-policy-agent/pkg/utils"

	"github.com/aws/amazon-vpc-cni-k8s/rpc"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	POLICIES_APPLIED = 0
	DEFAULT_ALLOW    = 1
	DEFAULT_DENY     = 2
)

const (
	npgRPCaddress         = "127.0.0.1:50052"
	grpcHealthServiceName = "grpc.health.v1.np-agent"
)

// server controls RPC service responses.
type server struct {
	policyReconciler *controllers.PolicyEndpointsReconciler
	log              logr.Logger
}

// EnforceNpToPod processes CNI Enforce NP network request
func (s *server) EnforceNpToPod(ctx context.Context, in *rpc.EnforceNpRequest) (*rpc.EnforceNpReply, error) {
	if s.policyReconciler.GeteBPFClient() == nil {
		s.log.Info("Network policy is disabled, returning success")
		success := rpc.EnforceNpReply{
			Success: true,
		}
		return &success, nil
	}

	s.log.Info("Received Enforce Network Policy Request for Pod", "Name", in.K8S_POD_NAME, "Namespace", in.K8S_POD_NAMESPACE, "Mode", in.NETWORK_POLICY_MODE)
	var err error

	s.policyReconciler.SetNetworkPolicyMode(in.NETWORK_POLICY_MODE)
	podIdentifier := utils.GetPodIdentifier(in.K8S_POD_NAME, in.K8S_POD_NAMESPACE, s.log)
	isFirstPodInPodIdentifier := s.policyReconciler.GeteBPFClient().IsFirstPodInPodIdentifier(podIdentifier)
	err = s.policyReconciler.GeteBPFClient().AttacheBPFProbes(types.NamespacedName{Name: in.K8S_POD_NAME, Namespace: in.K8S_POD_NAMESPACE},
		podIdentifier)
	if err != nil {
		s.log.Error(err, "Attaching eBPF probe failed for", "pod", in.K8S_POD_NAME, "namespace", in.K8S_POD_NAMESPACE)
		return nil, err
	}

	// We attempt to program eBPF firewall map entries for this pod, if the local agent is aware of the policies
	// configured against it. For example, if this is a new replica of an existing pod/deployment then the local
	// node agent will have the policy information available to it. If not, we will leave the pod in default allow
	// or default deny state based on NP mode until the Network Policy controller reconciles existing policies
	// against this pod.

	// Check if there are active policies against the new pod and if there are other pods on the local node that share
	// the eBPF firewall maps with the newly launched pod, if already present we can skip the map update and return
	policiesAvailableInLocalCache := s.policyReconciler.ArePoliciesAvailableInLocalCache(podIdentifier)
	if policiesAvailableInLocalCache && isFirstPodInPodIdentifier {
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
		// If no active policies present against this pod identifier, set pod_state to default_allow or default_deny
		if !policiesAvailableInLocalCache {
			s.log.Info("No active policies present for ", "podIdentifier: ", podIdentifier)
			if utils.IsStrictMode(in.NETWORK_POLICY_MODE) {
				s.log.Info("Updating pod_state map to default_deny for ", "podIdentifier: ", podIdentifier)
				err = s.policyReconciler.GeteBPFClient().UpdatePodStateEbpfMaps(podIdentifier, DEFAULT_DENY, true, true)
				if err != nil {
					s.log.Error(err, "Map update(s) failed for, ", "podIdentifier ", podIdentifier)
					return nil, err
				}
			} else {
				s.log.Info("Updating pod_state map to default_allow for ", "podIdentifier: ", podIdentifier)
				err = s.policyReconciler.GeteBPFClient().UpdatePodStateEbpfMaps(podIdentifier, DEFAULT_ALLOW, true, true)
				if err != nil {
					s.log.Error(err, "Map update(s) failed for, ", "podIdentifier ", podIdentifier)
					return nil, err
				}
			}
		} else {
			s.log.Info("Pod shares the eBPF firewall maps with other local pods. No Map update required..")
		}
	}

	resp := rpc.EnforceNpReply{
		Success: err == nil,
	}
	return &resp, nil
}

// DeletePodNp processes CNI Delete Pod NP network request
func (s *server) DeletePodNp(ctx context.Context, in *rpc.DeleteNpRequest) (*rpc.DeleteNpReply, error) {
	if s.policyReconciler.GeteBPFClient() == nil {
		s.log.Info("Network policy is disabled, returning success")
		success := rpc.DeleteNpReply{
			Success: true,
		}
		return &success, nil
	}

	s.log.Info("Received Delete Network Policy Request for Pod", "Name", in.K8S_POD_NAME, "Namespace", in.K8S_POD_NAMESPACE)
	var err error
	podIdentifier := utils.GetPodIdentifier(in.K8S_POD_NAME, in.K8S_POD_NAMESPACE, s.log)

	value, _ := s.policyReconciler.GeteBPFClient().GetDeletePodLockMap().LoadOrStore(podIdentifier, &sync.Mutex{})
	deletePodLock := value.(*sync.Mutex)
	deletePodLock.Lock()
	s.log.Info("Got the deletePodLock for", "Pod: ", in.K8S_POD_NAME, " Namespace: ", in.K8S_POD_NAMESPACE, " PodIdentifier: ", podIdentifier)

	isProgFdShared, err := s.policyReconciler.IsProgFdShared(in.K8S_POD_NAME, in.K8S_POD_NAMESPACE)
	s.policyReconciler.GeteBPFClient().DeletePodFromIngressProgPodCaches(in.K8S_POD_NAME, in.K8S_POD_NAMESPACE)
	s.policyReconciler.GeteBPFClient().DeletePodFromEgressProgPodCaches(in.K8S_POD_NAME, in.K8S_POD_NAMESPACE)
	if err == nil && !isProgFdShared {
		err = s.policyReconciler.GeteBPFClient().DeleteBPFProgramAndMaps(podIdentifier)
		if err != nil {
			s.log.Error(err, "BPF programs and Maps delete failed for ", "podIdentifier ", podIdentifier)
		}
		deletePodLock.Unlock()
		s.policyReconciler.GeteBPFClient().GetDeletePodLockMap().Delete(podIdentifier)
	} else {
		deletePodLock.Unlock()
	}
	resp := rpc.DeleteNpReply{
		Success: true,
	}
	return &resp, nil
}

// RunRPCHandler handles request from gRPC
func RunRPCHandler(policyReconciler *controllers.PolicyEndpointsReconciler) error {
	rpcLog := ctrl.Log.WithName("rpc-handler")

	rpcLog.Info("Serving RPC Handler", "Address", npgRPCaddress)
	listener, err := net.Listen("tcp", npgRPCaddress)
	if err != nil {
		rpcLog.Error(err, "Failed to listen gRPC port")
		return errors.Wrap(err, "network policy agent: failed to listen to gRPC port")
	}
	grpcServer := grpc.NewServer()
	rpc.RegisterNPBackendServer(grpcServer, &server{policyReconciler: policyReconciler, log: rpcLog})
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

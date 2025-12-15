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
	"os"

	"github.com/aws/aws-network-policy-agent/controllers"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	"github.com/aws/aws-network-policy-agent/pkg/utils"

	"github.com/aws/amazon-vpc-cni-k8s/rpc"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"k8s.io/apimachinery/pkg/types"
)

func log() logger.Logger {
	return logger.Get()
}

const (
	grpcHealthServiceName = "grpc.health.v1.np-agent"
)

// server controls RPC service responses.
type server struct {
	policyReconciler        *controllers.PolicyEndpointsReconciler
	clusterPolicyReconciler *controllers.ClusterPolicyEndpointsReconciler
	rpc.UnimplementedNPBackendServer
}

// EnforceNpToPod processes CNI Enforce NP network request
func (s *server) EnforceNpToPod(ctx context.Context, in *rpc.EnforceNpRequest) (*rpc.EnforceNpReply, error) {
	// TODO: Add the clusterPolicyReconciler nil check here once cluster policies CRDs are available everywhere
	if s.policyReconciler == nil || s.policyReconciler.GeteBPFClient() == nil {
		log().Debug("Network policy is disabled, returning success")
		success := rpc.EnforceNpReply{
			Success: true,
		}
		return &success, nil
	}

	log().Infof("Received Enforce Network Policy Request for Pod: %s Namespace: %s Mode: %s", in.K8S_POD_NAME, in.K8S_POD_NAMESPACE, in.NETWORK_POLICY_MODE)
	var err error

	if !utils.IsValidNetworkPolicyEnforcingMode(in.NETWORK_POLICY_MODE) {
		err = errors.New("Invalid Network Policy Mode")
		log().Errorf("Network Policy Mode validation failed: %s, error: %v", in.NETWORK_POLICY_MODE, err)
		return nil, err
	}

	podIdentifier := utils.GetPodIdentifier(in.K8S_POD_NAME, in.K8S_POD_NAMESPACE)
	isFirstPodInPodIdentifier := s.policyReconciler.GeteBPFClient().IsFirstPodInPodIdentifier(podIdentifier)
	err = s.policyReconciler.GeteBPFClient().AttacheBPFProbes(types.NamespacedName{Name: in.K8S_POD_NAME, Namespace: in.K8S_POD_NAMESPACE},
		podIdentifier, int(in.InterfaceCount))
	if err != nil {
		log().Errorf("Attaching eBPF probe failed for pod: %s namespace: %s, error: %v", in.K8S_POD_NAME, in.K8S_POD_NAMESPACE, err)
		return nil, err
	}
	var podState, clusterPolicyState int

	if utils.IsStrictMode(in.NETWORK_POLICY_MODE) {
		podState = ebpf.DEFAULT_DENY
	} else {
		podState = ebpf.DEFAULT_ALLOW
	}

	clusterPolicyState = ebpf.DEFAULT_ALLOW

	// We attempt to program eBPF firewall map entries for this pod, if the local agent is aware of the policies
	// configured against it. For example, if this is a new replica of an existing pod/deployment then the local
	// node agent will have the policy information available to it. If not, we will leave the pod in default allow
	// or default deny state based on NP mode until the Network Policy controller reconciles existing policies
	// against this pod.

	// Check if there are active policies against the new pod and if there are other pods on the local node that share
	// the eBPF firewall maps with the newly launched pod, if already present we can skip the map update and return
	policiesAvailableInLocalCache := s.policyReconciler.ArePoliciesAvailableInLocalCache(podIdentifier)
	clusterPolicyAvailableInLocalCache := s.clusterPolicyReconciler != nil && s.clusterPolicyReconciler.ArePoliciesAvailableInLocalCache(podIdentifier)

	if (policiesAvailableInLocalCache || clusterPolicyAvailableInLocalCache) && isFirstPodInPodIdentifier {
		// If we're here, then the local agent knows the list of active policies that apply to this pod and
		// this is the first pod of it's type to land on the local node/cluster
		log().Info("Active policies present against this pod and this is a new Pod to the local node, configuring firewall rules....")

		if policiesAvailableInLocalCache {
			//Derive Ingress and Egress Firewall Rules and Update the relevant eBPF maps
			ingressRules, egressRules, _ :=
				s.policyReconciler.DeriveFireWallRulesPerPodIdentifier(podIdentifier, in.K8S_POD_NAMESPACE)

			err = s.policyReconciler.GeteBPFClient().UpdateEbpfMaps(podIdentifier, ingressRules, egressRules)
			if err != nil {
				log().Errorf("Map update(s) failed for podIdentifier: %s, error: %v", podIdentifier, err)
				return nil, err
			}
			podState = ebpf.POLICIES_APPLIED
		}

		if clusterPolicyAvailableInLocalCache && s.clusterPolicyReconciler != nil {

			ingressRules, egressRules, _ :=
				s.clusterPolicyReconciler.DeriveClusterPolicyFireWallRulesPerPodIdentifier(ctx, podIdentifier)

			err = s.policyReconciler.GeteBPFClient().UpdateEbpfMaps(podIdentifier, ingressRules, egressRules)
			if err != nil {
				log().Errorf("Map update(s) failed for podIdentifier: %s, error: %v", podIdentifier, err)
				return nil, err
			}
			clusterPolicyState = ebpf.POLICIES_APPLIED
		}

		err = s.policyReconciler.GeteBPFClient().UpdatePodStateEbpfMaps(podIdentifier, ebpf.POD_STATE_MAP_KEY, podState, true, true)
		if err != nil {
			log().Errorf("Pod state map update failed for podIdentifier: %s, error: %v", podIdentifier, err)
			return nil, err
		}

		err = s.policyReconciler.GeteBPFClient().UpdatePodStateEbpfMaps(podIdentifier, ebpf.CLUSTER_POLICY_POD_STATE_MAP_KEY, clusterPolicyState, true, true)
		if err != nil {
			log().Errorf("Map update failed for podIdentifier: %s, error: %v", podIdentifier, err)
			return nil, err
		}

	} else {
		// If no active policies present against this pod identifier, set pod_state to default_allow or default_deny
		if !(policiesAvailableInLocalCache || clusterPolicyAvailableInLocalCache) {

			log().Debugf("No active policies present for podIdentifier: %s", podIdentifier)
			log().Infof("Updating pod_state map to default allow/default deny for podIdentifier: %s, state: %d", podIdentifier, podState)

			err = s.policyReconciler.GeteBPFClient().UpdatePodStateEbpfMaps(podIdentifier, ebpf.POD_STATE_MAP_KEY, podState, true, true)
			if err != nil {
				log().Errorf("Map update(s) failed for podIdentifier: %s, error: %v", podIdentifier, err)
				return nil, err
			}

			// No concept of default deny for cluster policies. Either we have a rule that allows or denies traffic
			err = s.policyReconciler.GeteBPFClient().UpdatePodStateEbpfMaps(podIdentifier, ebpf.CLUSTER_POLICY_POD_STATE_MAP_KEY, ebpf.DEFAULT_ALLOW, true, true)
			if err != nil {
				log().Errorf("Map update(s) failed for podIdentifier: %s, error: %v", podIdentifier, err)
				return nil, err
			}
		} else {
			log().Info("Pod shares the eBPF firewall maps with other local pods. No Map update required..")
		}
	}

	resp := rpc.EnforceNpReply{
		Success: err == nil,
	}
	return &resp, nil
}

// DeletePodNp processes CNI Delete Pod NP network request
func (s *server) DeletePodNp(ctx context.Context, in *rpc.DeleteNpRequest) (*rpc.DeleteNpReply, error) {
	if s.policyReconciler == nil || s.policyReconciler.GeteBPFClient() == nil {
		log().Debug("Network policy is disabled, returning success")
		success := rpc.DeleteNpReply{
			Success: true,
		}
		return &success, nil
	}

	log().Infof("Received Delete Network Policy Request for Pod: %s Namespace: %s", in.K8S_POD_NAME, in.K8S_POD_NAMESPACE)
	podIdentifier := utils.GetPodIdentifier(in.K8S_POD_NAME, in.K8S_POD_NAMESPACE)
	pod := types.NamespacedName{Name: in.K8S_POD_NAME, Namespace: in.K8S_POD_NAMESPACE}

	err := s.policyReconciler.GeteBPFClient().DeleteBPFProbes(pod, podIdentifier)
	if err != nil {
		log().Errorf("Failed to delete BPF probes for pod: %s namespace: %s, error: %v", in.K8S_POD_NAME, in.K8S_POD_NAMESPACE, err)
		return &rpc.DeleteNpReply{Success: false}, err
	}

	resp := rpc.DeleteNpReply{
		Success: true,
	}
	return &resp, nil
}

// RunRPCHandler handles request from gRPC
func RunRPCHandler(policyReconciler *controllers.PolicyEndpointsReconciler, clusterPolicyReconciler *controllers.ClusterPolicyEndpointsReconciler, npaSocketPath string) (<-chan error, error) {
	log().Infof("Serving RPC Handler on Unix socket: %s", npaSocketPath)

	if _, err := os.Stat(npaSocketPath); err == nil {
		log().Infof("Removing stale socket file: %s", npaSocketPath)
		err = os.Remove(npaSocketPath)
		if err != nil {
			log().Warnf("got error in removing socket file %v", err)
		}
	}

	listener, err := net.Listen("unix", npaSocketPath)
	if err != nil {
		log().Errorf("Failed to listen on unix socket: %v", err)
		return nil, errors.Wrap(err, "network policy agent: failed to listen on unix socket")
	}
	grpcServer := grpc.NewServer()
	rpc.RegisterNPBackendServer(grpcServer, &server{policyReconciler: policyReconciler, clusterPolicyReconciler: clusterPolicyReconciler})
	healthServer := health.NewServer()
	// No need to ever change this to HealthCheckResponse_NOT_SERVING since it's a local service only
	healthServer.SetServingStatus(grpcHealthServiceName, healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(grpcServer, healthServer)

	// Register reflection service on gRPC server.
	reflection.Register(grpcServer)
	errCh := make(chan error, 1)
	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			errCh <- errors.Wrap(err, "network policy agent: grpc serve failed")
		}
		close(errCh)
	}()
	log().Info("Done with RPC Handler initialization")
	return errCh, nil
}

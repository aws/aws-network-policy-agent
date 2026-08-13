/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"time"

	cnirpc "github.com/aws/amazon-vpc-cni-k8s/rpc"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/rpc"
	"github.com/aws/aws-network-policy-agent/pkg/rpcclient"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/aws/aws-network-policy-agent/pkg/version"
	"github.com/samber/lo"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/aws/aws-network-policy-agent/pkg/logger"

	"github.com/spf13/pflag"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/controllers"
	"github.com/aws/aws-network-policy-agent/pkg/config"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	//+kubebuilder:scaffold:imports
)

var (
	scheme              = runtime.NewScheme()
	LOCAL_IPAMD_ADDRESS = "unix:///var/run/aws-node/ipamd.sock"
	npaSocketPath       = "/var/run/aws-node/npa.sock"
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(policyk8sawsv1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	initLogger := logger.New("info", "", logger.DEFAULT_LOG_FILE_MAX_SIZE, logger.DEFAULT_LOG_FILE_MAX_BACKUPS)

	ctrlConfig, err := loadControllerConfig()
	if err != nil {
		initLogger.Errorf("unable to load policy endpoint controller config %v", err)
		os.Exit(1)
	}
	log := logger.New(ctrlConfig.LogLevel, ctrlConfig.LogFile, ctrlConfig.LogFileMaxSize, ctrlConfig.LogFileMaxBackups)
	log.Infof("Starting network policy agent: %s, log level: %s", version.String(), ctrlConfig.LogLevel)

	ctrl.SetLogger(logger.GetControllerRuntimeLogger())
	if ctrlConfig.EnableProfiling {
		go func() {
			log.Errorf("failed to setup pprof server: %v", http.ListenAndServe("localhost:6060", nil))
		}()
	}
	restCFG, err := config.BuildRestConfig(ctrlConfig.RuntimeConfig)
	if err != nil {
		log.Errorf("unable to build REST config %v", err)
		os.Exit(1)
	}

	runtimeOpts := config.BuildRuntimeOptions(ctrlConfig.RuntimeConfig, scheme)
	mgr, err := ctrl.NewManager(restCFG, runtimeOpts)
	if err != nil {
		log.Errorf("unable to create controller manager %v", err)
		os.Exit(1)
	}

	err = ctrlConfig.ValidControllerFlags()
	if err != nil {
		log.Errorf("Controller flags validation failed %v", err)
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()

	var policyEndpointController *controllers.PolicyEndpointsReconciler
	var clusterPolicyEndpointController *controllers.ClusterPolicyEndpointsReconciler
	if ctrlConfig.EnableNetworkPolicy {
		log.Info("Network Policy is enabled, registering controllers...")

		ipamdConfig := lo.Must1(getNetworkPolicyConfigsFromIpamd(ctx, log))

		nodeIP, err := selectNodeIP(ipamdConfig, ctrlConfig.EnableIPv6)
		if err != nil {
			log.Errorf("failed to determine node IP: %v", err)
			os.Exit(1)
		}

		ebpfClient := lo.Must1(ebpf.NewBpfClient(ctx, nodeIP, ctrlConfig.EnablePolicyEventLogs, ctrlConfig.EnableCloudWatchLogs,
			ctrlConfig.EnableIPv6, ctrlConfig.ConntrackCacheCleanupPeriod, ctrlConfig.ConntrackCacheTableSize, ipamdConfig.NetworkPolicyMode, ipamdConfig.MultiNICEnabled, ctrlConfig.LogLevel, ipamdConfig.InstanceID, ipamdConfig.Region))
		ebpfClient.ReAttachEbpfProbes()

		policyEndpointController = controllers.NewPolicyEndpointsReconciler(mgr.GetClient(), nodeIP, ebpfClient, ctrlConfig.EnableIPv6)

		if err = policyEndpointController.SetupWithManager(ctx, mgr); err != nil {
			log.Errorf("unable to create controller PolicyEndpoints %v", err)
			os.Exit(1)
		}

		clusterPolicyEndpointController = controllers.NewClusterPolicyEndpointsReconciler(mgr.GetClient(), nodeIP, ebpfClient)
		if err = clusterPolicyEndpointController.SetupWithManager(ctx, mgr); err != nil {
			log.Errorf("unable to create controller ClusterPolicyEndpoints %v", err)
			os.Exit(1)
		}

		readyzPaths := []string{ebpf.CONNTRACK_MAP_PIN_PATH, ebpf.POLICY_EVENTS_MAP_PIN_PATH}
		if err := mgr.AddReadyzCheck("bpf-maps", ebpf.NewGlobalMapsReadinessCheck(readyzPaths)); err != nil {
			log.Errorf("unable to set up bpf-maps readiness check %v", err)
			os.Exit(1)
		}

		if err := mgr.AddReadyzCheck("bpf-fs", ebpf.NewBpfFsReadinessCheck(ebpf.BPF_FS_ROOT)); err != nil {
			log.Errorf("unable to set up bpf-fs readiness check %v", err)
			os.Exit(1)
		}
	} else {
		log.Info("Network Policy is disabled, skip the controller registration")
	}

	//+kubebuilder:scaffold:builder

	// The gRPC server runs whether or not network policy is enabled, so its
	// health checks are registered unconditionally. The checker is created once
	// and shared between the liveness and readiness probes.
	grpcHealthChecker, err := rpc.NewGRPCSocketHealthChecker(npaSocketPath)
	if err != nil {
		log.Errorf("unable to set up gRPC socket health checker %v", err)
		os.Exit(1)
	}
	defer grpcHealthChecker.Close()

	if err := mgr.AddHealthzCheck("grpc-socket", grpcHealthChecker.Check); err != nil {
		log.Errorf("unable to set up gRPC socket health check %v", err)
		os.Exit(1)
	}

	if err := mgr.AddReadyzCheck("grpc-socket", grpcHealthChecker.Check); err != nil {
		log.Errorf("unable to set up grpc-socket readiness check %v", err)
		os.Exit(1)
	}

	// CNI makes rpc calls to NP agent regardless NP is enabled or not
	// need to start rpc always
	// todo: add a liveness probe to this gRPC server and remove closing based on this errCh, liveness probe will check and re-start this container
	errCh, err := rpc.RunRPCHandler(policyEndpointController, clusterPolicyEndpointController, npaSocketPath)
	if err != nil {
		log.Errorf("Failed to set up gRPC Handler %v", err)
		os.Exit(1)
	}
	go func() {
		if err := <-errCh; err != nil {
			log.Errorf("gRPC server stopped: %v", err)
			os.Exit(1)
		}
	}()

	log.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		log.Errorf("problem running manager %v", err)
		os.Exit(1)
	}

}

// loadControllerConfig loads the controller configuration
func loadControllerConfig() (config.ControllerConfig, error) {
	controllerConfig := config.ControllerConfig{}
	fs := pflag.NewFlagSet("", pflag.ExitOnError)
	controllerConfig.BindFlags(fs)

	if err := fs.Parse(os.Args); err != nil {
		return controllerConfig, err
	}

	return controllerConfig, nil
}

func getNetworkPolicyConfigsFromIpamd(ctx context.Context, log logger.Logger) (*cnirpc.NetworkPolicyAgentConfigReply, error) {
	log.Infof("Trying to establish GRPC connection to ipamd at %s", LOCAL_IPAMD_ADDRESS)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	grpcConn, err := rpcclient.New().Dial(ctx, LOCAL_IPAMD_ADDRESS, rpcclient.GetDefaultServiceRetryConfig(), rpcclient.GetInsecureConnectionType())
	if err != nil {
		log.Errorf("Failed to connect to ipamd at %s: %v", LOCAL_IPAMD_ADDRESS, err)
		return nil, err
	}
	defer grpcConn.Close()

	ipamd := cnirpc.NewConfigServerBackendClient(grpcConn)
	resp, err := ipamd.GetNetworkPolicyConfigs(ctx, &emptypb.Empty{})
	if err != nil {
		log.Errorf("Failed to get network policy configs %v", err)
		return nil, err
	}
	log.Infof("Connected to ipamd at %s. NetworkPolicyMode: %s MultiNICEnabled: %v NodeIPv4: %s NodeIPv6: %s InstanceID: %s Region: %s",
		LOCAL_IPAMD_ADDRESS, resp.NetworkPolicyMode, resp.MultiNICEnabled, resp.NodeIPv4, resp.NodeIPv6, resp.InstanceID, resp.Region)
	if !utils.IsValidNetworkPolicyEnforcingMode(resp.NetworkPolicyMode) {
		err = errors.New("Invalid Network Policy Mode")
		log.Errorf("Invalid Network Policy Mode from ipamd %s error: %v", resp.NetworkPolicyMode, err)
		return nil, err
	}
	return resp, nil
}

// selectNodeIP returns the ipamd-supplied node IP for the configured address family.
func selectNodeIP(ipamdConfig *cnirpc.NetworkPolicyAgentConfigReply, enableIPv6 bool) (string, error) {
	nodeIP := ipamdConfig.NodeIPv4
	if enableIPv6 {
		nodeIP = ipamdConfig.NodeIPv6
	}
	if nodeIP == "" {
		return "", fmt.Errorf("ipamd did not provide a node IP (EnableIPv6=%v)", enableIPv6)
	}
	return nodeIP, nil
}

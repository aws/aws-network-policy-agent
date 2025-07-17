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
	"os"

	cnirpc "github.com/aws/amazon-vpc-cni-k8s/rpc"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/rpc"
	"github.com/aws/aws-network-policy-agent/pkg/rpcclient"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/aws/aws-network-policy-agent/pkg/utils/imds"
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
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	//+kubebuilder:scaffold:imports
)

var (
	scheme              = runtime.NewScheme()
	LOCAL_IPAMD_ADDRESS = "127.0.0.1:50051"
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
	log.Infof("Starting network policy agent with log level: %s", ctrlConfig.LogLevel)

	ctrl.SetLogger(logger.GetControllerRuntimeLogger())
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
	if ctrlConfig.EnableNetworkPolicy {
		log.Info("Network Policy is enabled, registering the policyEndpointController...")

		var nodeIP string
		if !ctrlConfig.EnableIPv6 {
			nodeIP = lo.Must1(imds.GetMetaData("local-ipv4"))
		} else {
			nodeIP = lo.Must1(imds.GetMetaData("ipv6"))
		}

		npMode, isMultiNICEnabled := lo.Must2(getNetworkPolicyConfigsFromIpamd(log))

		ebpfClient := lo.Must1(ebpf.NewBpfClient(nodeIP, ctrlConfig.EnablePolicyEventLogs, ctrlConfig.EnableCloudWatchLogs,
			ctrlConfig.EnableIPv6, ctrlConfig.ConntrackCacheCleanupPeriod, ctrlConfig.ConntrackCacheTableSize, npMode, isMultiNICEnabled))
		ebpfClient.ReAttachEbpfProbes()

		policyEndpointController = controllers.NewPolicyEndpointsReconciler(mgr.GetClient(), nodeIP, ebpfClient)

		if err = policyEndpointController.SetupWithManager(ctx, mgr); err != nil {
			log.Errorf("unable to create controller PolicyEndpoints %v", err)
			os.Exit(1)
		}
	} else {
		log.Info("Network Policy is disabled, skip the policyEndpointController registration")
	}

	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		log.Errorf("unable to set up health check %v", err)
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		log.Errorf("unable to set up ready check %v", err)
		os.Exit(1)
	}

	// CNI makes rpc calls to NP agent regardless NP is enabled or not
	// need to start rpc always
	go func() {
		if err := rpc.RunRPCHandler(policyEndpointController); err != nil {
			log.Errorf("Failed to set up gRPC Handler %v", err)
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

func getNetworkPolicyConfigsFromIpamd(log logger.Logger) (string, bool, error) {
	ctx := context.Background()

	// grpc connection waits till the ipmad is up and running
	log.Info("Trying to establish GRPC connection to ipamd")
	grpcConn, err := rpcclient.New().Dial(ctx, LOCAL_IPAMD_ADDRESS, rpcclient.GetDefaultServiceRetryConfig(), rpcclient.GetInsecureConnectionType())
	if err != nil {
		log.Errorf("Failed to connect to ipamd %v", err)
		return "", false, err
	}
	defer grpcConn.Close()

	ipamd := cnirpc.NewConfigServerBackendClient(grpcConn)
	resp, err := ipamd.GetNetworkPolicyConfigs(ctx, &emptypb.Empty{})
	if err != nil {
		log.Errorf("Failed to get network policy configs %v", err)
		return "", false, err
	}
	log.Infof("Connected to ipamd grpc endpoint. NetworkPolicyMode: %s MultiNICEnabled: %v", resp.NetworkPolicyMode, resp.MultiNICEnabled)
	if !utils.IsValidNetworkPolicyEnforcingMode(resp.NetworkPolicyMode) {
		err = errors.New("Invalid Network Policy Mode")
		log.Errorf("Invalid Network Policy Mode from ipamd %s error: %v", resp.NetworkPolicyMode, err)
		return "", false, err
	}
	return resp.NetworkPolicyMode, resp.MultiNICEnabled, nil
}

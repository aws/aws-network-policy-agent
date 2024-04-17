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
	"os"

	"github.com/aws/aws-network-policy-agent/pkg/rpc"

	"github.com/aws/aws-network-policy-agent/pkg/logger"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/spf13/pflag"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/aws/aws-network-policy-agent/controllers"
	"github.com/aws/aws-network-policy-agent/pkg/config"
	"github.com/aws/aws-network-policy-agent/pkg/metrics"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	//+kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(policyk8sawsv1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	initLogger, _ := getLoggerWithLogLevel("info", "")

	ctrlConfig, err := loadControllerConfig()
	if err != nil {
		initLogger.Error(err, "unable to load policy endpoint controller config")
		os.Exit(1)
	}

	ctrlLogger, err := getLoggerWithLogLevel(ctrlConfig.LogLevel, ctrlConfig.LogFile)
	if err != nil {
		initLogger.Error(err, "unable to setup logger")
		os.Exit(1)
	}
	ctrl.SetLogger(ctrlLogger)
	restCFG, err := config.BuildRestConfig(ctrlConfig.RuntimeConfig)
	if err != nil {
		setupLog.Error(err, "unable to build REST config")
		os.Exit(1)
	}

	runtimeOpts := config.BuildRuntimeOptions(ctrlConfig.RuntimeConfig, scheme)
	mgr, err := ctrl.NewManager(restCFG, runtimeOpts)
	if err != nil {
		setupLog.Error(err, "unable to create controller manager")
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()
	policyEndpointController, err := controllers.NewPolicyEndpointsReconciler(mgr.GetClient(),
		ctrl.Log.WithName("controllers").WithName("policyEndpoints"), ctrlConfig.EnablePolicyEventLogs, ctrlConfig.EnableCloudWatchLogs,
		ctrlConfig.EnableIPv6, ctrlConfig.EnableNetworkPolicy, ctrlConfig.ConntrackCacheCleanupPeriod)
	if err != nil {
		setupLog.Error(err, "unable to setup controller", "controller", "PolicyEndpoints init failed")
		os.Exit(1)
	}

	if err = policyEndpointController.SetupWithManager(ctx, mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PolicyEndpoints")
		os.Exit(1)
	}
	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	go metrics.ServeMetrics()
	go rpc.RunRPCHandler(policyEndpointController)

	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
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

// getLoggerWithLogLevel returns logger with specific log level.
func getLoggerWithLogLevel(logLevel string, logFilePath string) (logr.Logger, error) {
	ctrlLogger := logger.New(logLevel, logFilePath)
	return zapr.NewLogger(ctrlLogger), nil
}

package config

import (
	"context"

	"github.com/aws/aws-network-policy-agent/pkg/rpc"
	"github.com/spf13/pflag"
	"google.golang.org/protobuf/types/known/emptypb"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	flagLogLevel                       = "log-level"
	flagLogFile                        = "log-file"
	flagMaxConcurrentReconciles        = "max-concurrent-reconciles"
	defaultLogLevel                    = "info"
	defaultLogFile                     = "/var/log/aws-routed-eni/network-policy-agent.log"
	defaultMaxConcurrentReconciles     = 3
	defaultConntrackCacheCleanupPeriod = 300
	flagEnablePolicyEventLogs          = "enable-policy-event-logs"
	flagEnableCloudWatchLogs           = "enable-cloudwatch-logs"
	flagEnableIPv6                     = "enable-ipv6"
	flagEnableNetworkPolicy            = "enable-network-policy"
	flagConntrackCacheCleanupPeriod    = "conntrack-cache-cleanup-period"
	flagRunAsSystemProcess             = "run-as-system-process"
	localIpamAddress                   = "127.0.0.1:50051"
)

// ControllerConfig contains the controller configuration
type ControllerConfig struct {
	// Log level for the controller logs
	LogLevel string
	// Local log file for Network Policy Agent
	LogFile string
	// MaxConcurrentReconciles specifies the max number of reconcile loops
	MaxConcurrentReconciles int
	// Enable Policy decision logs
	EnablePolicyEventLogs bool
	// Enable Policy decision logs streaming to CloudWatch
	EnableCloudWatchLogs bool
	// Enable IPv6 mode
	EnableIPv6 bool
	// Enable Network Policy
	EnableNetworkPolicy bool
	// ConntrackCacheCleanupPeriod specifies the cleanup period
	ConntrackCacheCleanupPeriod int
	// Configurations for the Controller Runtime
	RuntimeConfig RuntimeConfig
	// Run the controller as a system process
	RunAsSystemProcess bool
}

func (cfg *ControllerConfig) BindFlags(fs *pflag.FlagSet) {
	fs.StringVar(&cfg.LogLevel, flagLogLevel, defaultLogLevel,
		"Set the controller log level - info, debug")
	fs.StringVar(&cfg.LogFile, flagLogFile, defaultLogFile, ""+
		"Set the controller log file - if not specified logs are written to stdout")
	fs.IntVar(&cfg.MaxConcurrentReconciles, flagMaxConcurrentReconciles, defaultMaxConcurrentReconciles, ""+
		"Maximum number of concurrent reconcile loops")
	fs.BoolVar(&cfg.EnablePolicyEventLogs, flagEnablePolicyEventLogs, false, "If enabled, policy decision logs will be collected & logged")
	fs.BoolVar(&cfg.EnableCloudWatchLogs, flagEnableCloudWatchLogs, false, "If enabled, policy decision logs will be streamed to CloudWatch, requires \"enable-policy-event-logs=true\"")
	fs.BoolVar(&cfg.EnableIPv6, flagEnableIPv6, false, "If enabled, Network Policy agent will operate in IPv6 mode")
	fs.BoolVar(&cfg.EnableNetworkPolicy, flagEnableNetworkPolicy, false, "If enabled, Network Policy agent will initialize BPF maps and start reconciler")
	fs.IntVar(&cfg.ConntrackCacheCleanupPeriod, flagConntrackCacheCleanupPeriod, defaultConntrackCacheCleanupPeriod, ""+
		"Cleanup interval for network policy agent conntrack cache")
	fs.BoolVar(&cfg.RunAsSystemProcess, flagRunAsSystemProcess, false, "If enabled, Network Policy Agent will run as a systemd process")

	cfg.RuntimeConfig.BindFlags(fs)
}

func (cfg *ControllerConfig) GetUpdatedControllerConfigsFromIPAM(ctx context.Context) {

	if cfg.RunAsSystemProcess {

		grpcLogger := ctrl.Log.WithName("grpcLogger")

		grpcLogger.Info("Trying to establish GRPC connection to IPAM")
		grpcConn, err := rpc.New().Dial(ctx, localIpamAddress, rpc.GetDefaultServiceRetryConfig(), rpc.GetInsecureConnectionType())
		if err != nil {
			grpcLogger.Error(err, "Failed to connect to IPAM server")
		}
		defer grpcConn.Close()

		ipamd := rpc.NewConfigServerBackendClient(grpcConn)
		resp, err := ipamd.GetNetworkPolicyAgentConfigs(ctx, &emptypb.Empty{})
		if err != nil {
			grpcLogger.Info("Failed to get controller configs, using the default values", "error", err)
			return
		}

		// Validate if the values are within valid range (1 sec to 10 mins)
		if resp.ConntrackCleanupInterval > 0 && resp.ConntrackCleanupInterval <= 600 {
			cfg.ConntrackCacheCleanupPeriod = int(resp.ConntrackCleanupInterval)
		}
	}
}

package config

import "github.com/spf13/pflag"

const (
	flagLogLevel                   = "log-level"
	flagLogFile                    = "log-file"
	flagMaxConcurrentReconciles    = "max-concurrent-reconciles"
	defaultLogLevel                = "info"
	defaultLogFile                 = "/var/log/aws-routed-eni/network-policy-agent.log"
	defaultMaxConcurrentReconciles = 3
	flagEnablePolicyEventLogs      = "enable-policy-event-logs"
	flagEnableCloudWatchLogs       = "enable-cloudwatch-logs"
	flagEnableIPv6                 = "enable-ipv6"
	flagEnableNetworkPolicy        = "enable-network-policy"
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
	// Configurations for the Controller Runtime
	RuntimeConfig RuntimeConfig
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

	cfg.RuntimeConfig.BindFlags(fs)
}

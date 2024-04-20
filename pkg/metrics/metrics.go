package metrics

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/aws/amazon-vpc-cni-k8s/pkg/utils/retry"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	// metricsPort is the port for prometheus metrics
	metricsPort = 61680
)

func ServeMetrics() {
	metricsLogger := getMetricsLogger()
	metricsLogger.Info("Serving metrics on ", "port", metricsPort)
	server := setupMetricsServer()
	for {
		once := sync.Once{}
		_ = retry.WithBackoff(retry.NewSimpleBackoff(time.Second, time.Minute, 0.2, 2), func() error {
			err := server.ListenAndServe()
			once.Do(func() {
				metricsLogger.Error(err, "Error running http API: %v")
			})
			return err
		})
	}
}

func setupMetricsServer() *http.Server {
	serveMux := http.NewServeMux()
	serveMux.Handle("/metrics", promhttp.Handler())
	server := &http.Server{
		Addr:         ":" + strconv.Itoa(metricsPort),
		Handler:      serveMux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	return server
}

func getMetricsLogger() logr.Logger {
	ctrlLogger := logger.New("info", "")
	return zapr.NewLogger(ctrlLogger)
}

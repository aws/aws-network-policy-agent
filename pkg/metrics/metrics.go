package metrics

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/aws/amazon-vpc-cni-k8s/pkg/utils/retry"
	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	// metricsPort is the port for prometheus metrics
	metricsPort = 61680
)

func ServeMetrics(log logr.Logger) {

	log.Info("Serving metrics on ", "port", metricsPort)
	server := setupMetricsServer()
	for {
		once := sync.Once{}
		_ = retry.WithBackoff(retry.NewSimpleBackoff(time.Second, time.Minute, 0.2, 2), func() error {
			err := server.ListenAndServe()
			once.Do(func() {
				log.Error(err, "Error running http API: %v")
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

package main

import (
	"context"
	"net/http"
	"time"

	"github.com/asymmetric-research/solana-exporter/pkg/rpc"
	"github.com/asymmetric-research/solana-exporter/pkg/slog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// readHeaderTimeout bounds how long the metrics server will wait to read request headers.
const readHeaderTimeout = 10 * time.Second

func main() {
	slog.Init()
	logger := slog.Get()
	ctx := context.Background()

	config, err := NewExporterConfigFromCLI(ctx)
	if err != nil {
		logger.Fatal(err)
	}
	if config.ComprehensiveSlotTracking {
		logger.Warn(
			"Comprehensive slot tracking will lead to potentially thousands of new " +
				"Prometheus metrics being created every epoch.",
		)
	}

	rpcClient := rpc.NewRPCClient(config.RPCURL, config.HTTPTimeout)
	collector := NewSolanaCollector(rpcClient, config)
	slotWatcher := NewSlotWatcher(rpcClient, config)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go slotWatcher.WatchSlots(ctx)
	if config.MonitorAlpenglowVoteInclusion {
		voteInclusionWatcher := NewVoteInclusionWatcher(rpcClient, config)
		go voteInclusionWatcher.WatchVoteInclusion(ctx)
	}

	prometheus.MustRegister(collector)
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	server := &http.Server{
		Addr:              config.ListenAddress,
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	logger.Infof("listening on %s", config.ListenAddress)
	logger.Fatal(server.ListenAndServe())
}

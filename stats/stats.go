// Package stats provides a debug HTTP server exposing pprof and Prometheus metrics.
package stats

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// New creates a Prometheus registry and listens on debugAddr if non-empty
// debugAddr exposes /metrics and pprof
func New(ctx context.Context, debugAddr string) *prometheus.Registry {
	registry := prometheus.NewRegistry()

	registry.MustRegister(collectors.NewGoCollector())
	registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	registry.MustRegister(version.NewCollector("test-certs-site"))

	if debugAddr == "" {
		slog.Info("No debug listen address specified")

		return registry
	}

	mux := http.NewServeMux()
	mux.Handle("/debug/pprof/", http.HandlerFunc(pprof.Index))
	mux.Handle("/debug/pprof/profile", http.HandlerFunc(pprof.Profile))
	mux.Handle("/debug/pprof/symbol", http.HandlerFunc(pprof.Symbol))
	mux.Handle("/debug/pprof/trace", http.HandlerFunc(pprof.Trace))
	mux.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
	mux.Handle("/debug/pprof/block", pprof.Handler("block"))
	mux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
	mux.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
	mux.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))

	srv := http.Server{
		Addr:        debugAddr,
		Handler:     mux,
		ReadTimeout: time.Minute,
	}

	// Wait for a signal to shut down the server.
	go func() {
		<-ctx.Done()

		err := srv.Shutdown(context.WithoutCancel(ctx))
		if err != nil {
			slog.Error("debug server error", slog.String("error", err.Error()))
		}
	}()

	go func() {
		slog.Info("Debug server listening", slog.String("debugAddr", debugAddr))

		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("debug server exited", slog.String("error", err.Error()))
		}
	}()

	return registry
}

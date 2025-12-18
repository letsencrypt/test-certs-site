// Package server is the HTTPS server for test-certs-site.
package server

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"time"

	"github.com/letsencrypt/test-certs-site/config"
)

// GetCertificateFunc is the type of the TLSConfig.GetCertificate function.
// The webserver will use it to obtain certificates, including fulfilling
// ACME TLS-ALPN-01 challenges.
type GetCertificateFunc func(info *tls.ClientHelloInfo) (*tls.Certificate, error)

// Run the server, until ctx is cancelled
func Run(ctx context.Context, cfg *config.Config, getCert GetCertificateFunc) error {
	// We want http requests to time out relatively quickly, as this server shouldn't be doing much.
	const timeout = 5 * time.Second

	srv := http.Server{
		Addr:    cfg.ListenAddr,
		Handler: newHandler(cfg),

		IdleTimeout:       timeout,
		ReadHeaderTimeout: timeout,
		ReadTimeout:       timeout,
		WriteTimeout:      timeout,

		TLSConfig: &tls.Config{
			GetCertificate: getCert,
			MinVersion:     tls.VersionTLS13,
			NextProtos:     []string{"acme-tls/1"},
		},
	}

	// Wait for a signal to shut down the server.
	go func() {
		<-ctx.Done()

		err := srv.Shutdown(context.Background())
		if err != nil {
			slog.Error(err.Error())
		}
	}()

	return srv.ListenAndServeTLS("", "")
}

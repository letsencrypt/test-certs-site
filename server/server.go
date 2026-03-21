// Package server is the HTTPS server for test-certs-site.
package server

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/letsencrypt/test-certs-site/config"
)

// GetCertificateFunc is the type of the TLSConfig.GetCertificate function.
// The webserver will use it to obtain certificates, including fulfilling
// ACME TLS-ALPN-01 challenges.
type GetCertificateFunc func(info *tls.ClientHelloInfo) (*tls.Certificate, error)

// tlsNoiseFilterHandler is a slog.Handler that drops "http: TLS handshake
// error" messages. These are mostly internet-scanning noise and would
// otherwise drown out useful log entries.
type tlsNoiseFilterHandler struct {
	slog.Handler
}

func (h tlsNoiseFilterHandler) Handle(ctx context.Context, r slog.Record) error {
	if strings.HasPrefix(r.Message, "http: TLS handshake error") {
		return nil
	}
	return h.Handler.Handle(ctx, r)
}

// wrapGetCertificate returns a GetCertificateFunc that logs any error returned
// by fn via slog before propagating it. This is needed because the http server's
// ErrorLog is filtered to drop TLS handshake noise (see tlsNoiseFilterHandler),
// so errors from GetCertificate would otherwise be silently discarded.
func wrapGetCertificate(fn GetCertificateFunc) GetCertificateFunc {
	return func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := fn(info)
		if err != nil {
			slog.Error("GetCertificate", "err", err, "serverName", info.ServerName)
		}
		return cert, err
	}
}

// Run the server, until the context is canceled.
func Run(ctx context.Context, cfg *config.Config, getCert GetCertificateFunc) error {
	// We want http requests to time out relatively quickly, as this server shouldn't be doing much.
	const timeout = 5 * time.Second

	handler, err := newHandler(cfg)
	if err != nil {
		return err
	}

	// Route the http server's error log through a slog filter that drops
	// TLS handshake noise (internet-scanning traffic).
	filteredHandler := tlsNoiseFilterHandler{slog.Default().Handler()}
	errorLog := slog.NewLogLogger(filteredHandler, slog.LevelError)

	srv := http.Server{
		Addr:     cfg.ListenAddr,
		Handler:  handler,
		ErrorLog: errorLog,

		IdleTimeout:       timeout,
		ReadHeaderTimeout: timeout,
		ReadTimeout:       timeout,
		WriteTimeout:      timeout,

		//nolint:gosec // This is an explicit TLS test site, so allow TLS1.0
		TLSConfig: &tls.Config{
			GetCertificate: wrapGetCertificate(getCert),
			MinVersion:     tls.VersionTLS10,
			NextProtos:     []string{"acme-tls/1"},
		},
	}

	// Wait for a signal to shut down the server.
	go func() {
		<-ctx.Done()

		err := srv.Shutdown(context.WithoutCancel(ctx))
		if err != nil {
			slog.Error(err.Error())
		}
	}()

	return srv.ListenAndServeTLS("", "")
}

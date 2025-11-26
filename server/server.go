// Package server is the HTTPS server for test-certs-site.
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// handle an http request with a placeholder response.
func handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != "/" {
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, "404 Not Found")

		return
	}

	// This is just a placeholder until we make a nice site.
	_, _ = fmt.Fprintf(w, "This is a demontration site for %s", r.TLS.ServerName)
}

// GetCertificateFunc is the type of the TLSConfig.GetCertificate function.
// The webserver will use it to obtain certificates, including fulfilling
// ACME TLS-ALPN-01 challenges.
type GetCertificateFunc func(info *tls.ClientHelloInfo) (*tls.Certificate, error)

// Run the server, until the process is signaled to exit.
func Run(addr string, getCert GetCertificateFunc) error {
	// We want http requests to time out relatively quickly, as this server shouldn't be doing much.
	const timeout = 5 * time.Second

	srv := http.Server{
		Addr:    addr,
		Handler: http.HandlerFunc(handle),

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
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		err := srv.Shutdown(context.Background())
		if err != nil {
			slog.Error(err.Error())
		}
	}()

	return srv.ListenAndServeTLS("", "")
}

package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"testing"
	"time"
)

// TestTLSNoiseFilterHandler verifies that tlsNoiseFilterHandler drops
// "http: TLS handshake error" messages and passes everything else through.
func TestTLSNoiseFilterHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		msg     string
		dropped bool
	}{
		{
			msg:     "http: TLS handshake error from [::1]:1234: EOF",
			dropped: true,
		},
		{
			msg:     "http: TLS handshake error from 1.2.3.4:5678: no certificate for name",
			dropped: true,
		},
		{
			msg:     "http: TLS handshake error from 1.2.3.4:5678: client sent an HTTP request to an HTTPS server",
			dropped: true,
		},
		{
			msg:     "some other server error",
			dropped: false,
		},
		{
			msg:     "GetCertificate",
			dropped: false,
		},
	}

	for _, test := range tests {
		t.Run(test.msg, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			inner := slog.NewTextHandler(&buf, nil)
			filter := tlsNoiseFilterHandler{inner}

			r := slog.NewRecord(time.Time{}, slog.LevelError, test.msg, 0)
			_ = filter.Handle(context.Background(), r)

			got := buf.String()
			if test.dropped && got != "" {
				t.Errorf("expected message %q to be dropped, but got: %s", test.msg, got)
			}
			if !test.dropped && got == "" {
				t.Errorf("expected message %q to pass through, but got nothing", test.msg)
			}
		})
	}
}

// TestWrapGetCertificate verifies that wrapGetCertificate logs errors from the
// wrapped function via slog and still returns them to the caller.
func TestWrapGetCertificate(t *testing.T) {
	t.Parallel()

	certErr := errors.New("certificate not found")

	t.Run("error is logged and returned", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		oldDefault := slog.Default()
		slog.SetDefault(logger)
		t.Cleanup(func() { slog.SetDefault(oldDefault) })

		fn := func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return nil, certErr
		}
		wrapped := wrapGetCertificate(fn)

		_, err := wrapped(&tls.ClientHelloInfo{ServerName: "example.com"})
		if !errors.Is(err, certErr) {
			t.Fatalf("expected error %v, got %v", certErr, err)
		}

		logged := buf.String()
		if logged == "" {
			t.Error("expected error to be logged, but nothing was written")
		}
		if !bytes.Contains([]byte(logged), []byte("GetCertificate")) {
			t.Errorf("expected log to contain 'GetCertificate', got: %s", logged)
		}
		if !bytes.Contains([]byte(logged), []byte(certErr.Error())) {
			t.Errorf("expected log to contain error message %q, got: %s", certErr.Error(), logged)
		}
	})

	t.Run("success is not logged", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		oldDefault := slog.Default()
		slog.SetDefault(logger)
		t.Cleanup(func() { slog.SetDefault(oldDefault) })

		expectedCert := &tls.Certificate{}
		fn := func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return expectedCert, nil
		}
		wrapped := wrapGetCertificate(fn)

		got, err := wrapped(&tls.ClientHelloInfo{ServerName: "example.com"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != expectedCert {
			t.Error("expected returned certificate to match")
		}
		if buf.Len() != 0 {
			t.Errorf("expected nothing logged on success, but got: %s", buf.String())
		}
	})
}

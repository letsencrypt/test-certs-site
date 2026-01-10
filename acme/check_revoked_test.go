package acme

import (
	"crypto/x509"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCheckRevoked(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/128.crl" {
			t.Errorf("Unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)

		// TODO, mock an actual crl response
		_, err := w.Write([]byte("OK"))
		if err != nil {
			t.Errorf("Failed to write response: %s", err)
		}
	}))
	defer server.Close()

	r := &revoked{
		http:          http.DefaultClient,
		logger:        slog.Default(),
		checkInterval: time.Minute,
	}

	if !r.shouldRevoke() {
		t.Fatal("revoked certs should revoke")
	}

	now := time.Now()
	minuteAhead := now.Add(time.Minute)
	hourAhead := now.Add(time.Hour)

	renew := r.checkRenew(t.Context(), &x509.Certificate{NotBefore: now, NotAfter: hourAhead})
	if renew.Before(minuteAhead) {
		t.Fatal("renew time should be in the future")
	}
	if renew.After(hourAhead) {
		t.Fatal("renew time should be before cert expires")
	}

	// TODO: test r.checkReady with a mock certificate, issuer, and CRL
}

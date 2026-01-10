package acme

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestCheckExpired(t *testing.T) {
	t.Parallel()

	e := expired{}

	if e.shouldRevoke() {
		t.Fatal("expired certs should not revoke")
	}

	now := time.Now()

	currentCert := x509.Certificate{
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(time.Minute),
	}

	ready, err := e.checkReady(t.Context(), &currentCert, nil)
	if err != nil {
		t.Fatal(err)
	}

	if ready.Before(currentCert.NotAfter) {
		t.Fatal("the expired cert won't be ready before it expires")
	}

	renew := e.checkRenew(t.Context(), &currentCert)

	if renew.Before(currentCert.NotAfter) {
		t.Fatal("the expired cert should be renewed after it expires")
	}
}

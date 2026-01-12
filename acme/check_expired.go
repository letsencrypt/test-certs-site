package acme

import (
	"context"
	"crypto/x509"
	"time"
)

type expired struct{}

// checkReady returns the time this certificate is ready: its expiry date.
func (expired) checkReady(_ context.Context, cert, _ *x509.Certificate) (time.Time, error) {
	return cert.NotAfter, nil
}

// checkRenew for expired certs waits the cert's lifetime after it expired.
// That way we replace them to keep up with any profile changes, even if we
// could just keep using one expired cert.
func (expired) checkRenew(_ context.Context, cert *x509.Certificate) time.Time {
	return cert.NotAfter.Add(cert.NotAfter.Sub(cert.NotBefore))
}

// shouldRevoke returns false, as we don't need to revoke the expired certificates.
func (expired) shouldRevoke() bool {
	return false
}

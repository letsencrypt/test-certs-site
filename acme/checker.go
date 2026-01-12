package acme

import (
	"context"
	"crypto/x509"
	"log/slog"
	mathrand "math/rand/v2"
	"time"
)

// checker is the interface used to handle the differences between (valid, revoked, expired) by the issue state machine.
type checker interface {
	// checkReady returns if a certificate is ready.
	// It returns a time to wait with a nil error if we should wait and re-check.
	// If that time has already passed, then the cert is ready to go.
	// It returns an error if we should throw out this cert.
	// Checks CRLs for revoked certs.
	checkReady(ctx context.Context, cert, issuer *x509.Certificate) (time.Time, error)

	// checkRenew returns when we should renew it.
	// Checks ARI for valid certs.
	checkRenew(ctx context.Context, cert *x509.Certificate) time.Time

	// shouldRevoke returns true if this certificate should be revoked.
	// Returns true for revoked certs, and false otherwise.
	shouldRevoke() bool
}

func halfTime(cert *x509.Certificate) time.Time {
	lifetime := cert.NotAfter.Sub(cert.NotBefore)

	return cert.NotBefore.Add(lifetime / 2) //nolint:mnd
}

func randTime(start, end time.Time) time.Time {
	window := int64(end.Sub(start))
	if window <= 0 {
		// If start == end, we'll get a 0 duration, which we can't pass to mathrand.Int64N
		return start
	}

	return start.Add(time.Duration(mathrand.Int64N(window))) //nolint:gosec // math/rand is safe here
}

func slogErr(err error) slog.Attr {
	return slog.String("error", err.Error())
}

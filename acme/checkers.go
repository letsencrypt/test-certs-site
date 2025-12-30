package acme

import (
	"crypto/x509"
	"fmt"
	"time"
)

// checker is the interface used to handle the differences between (valid, revoked, expired) by the issue state machine.
type checker interface {
	// checkReady returns if a certificate is ready.
	// It returns a time to wait with a nil error if we should wait and re-check.
	// If that time has already passed, then the cert is ready to go.
	// It returns an error if we should throw out this cert.
	checkReady(cert *x509.Certificate) (time.Time, error)

	// checkRenew returns when we should renew it.
	checkRenew(cert *x509.Certificate) time.Time

	shouldRevoke() bool
}

type valid struct{}

func (valid) checkReady(cert *x509.Certificate) (time.Time, error) {
	if time.Now().After(cert.NotAfter) {
		return time.Time{}, fmt.Errorf("certificate expired: %s", cert.NotAfter.Format(time.DateTime))
	}

	return time.Time{}, nil
}

func (valid) checkRenew(cert *x509.Certificate) time.Time {
	// TODO: Use ARI, recheck daily
	// Renew at 50% lifetime
	lifetime := cert.NotAfter.Sub(cert.NotBefore)

	return cert.NotBefore.Add(lifetime / 2) //nolint:mnd
}

func (valid) shouldRevoke() bool {
	return false
}

type revoked struct{}

func (revoked) checkReady(cert *x509.Certificate) (time.Time, error) {
	if time.Now().After(cert.NotAfter) {
		return time.Time{}, fmt.Errorf("certificate expired: %s", cert.NotAfter.Format(time.DateTime))
	}

	// TODO: Actually check CRLs.
	return time.Time{}, nil
}

func (revoked) checkRenew(cert *x509.Certificate) time.Time {
	// Can't use ARI for revoked, because it'll want to revoke immediately
	// Renew at 50% lifetime
	lifetime := cert.NotAfter.Sub(cert.NotBefore)

	return cert.NotBefore.Add(lifetime / 2) //nolint:mnd
}

func (revoked) shouldRevoke() bool {
	return true
}

type expired struct{}

func (expired) checkReady(cert *x509.Certificate) (time.Time, error) {
	// Certificate is "ready" when it is expired
	return cert.NotAfter, nil
}

func (expired) checkRenew(cert *x509.Certificate) time.Time {
	// Expired certs could just hang out forever, but we should still routinely replace them
	// That makes sure any certificate changes will still show up.
	// We kick off the renewal once it's been expired for its lifetime
	lifetime := cert.NotAfter.Sub(cert.NotBefore)

	return cert.NotAfter.Add(lifetime)
}

func (expired) shouldRevoke() bool {
	return false
}

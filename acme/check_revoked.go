package acme

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"time"
)

type revoked struct {
	http   *http.Client
	logger *slog.Logger

	checkInterval time.Duration
}

func (r *revoked) checkCRL(ctx context.Context, cert, issuer *x509.Certificate) (bool, error) {
	if len(cert.CRLDistributionPoints) == 0 {
		r.logger.Info("No CRL found")

		// Assume revoked in the no-CRL case
		return true, nil
	}

	url := cert.CRLDistributionPoints[0]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("creating HTTP request: %w", err)
	}

	resp, err := r.http.Do(req)
	if err != nil {
		return false, fmt.Errorf("downloading CRL %q: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("downloading CRL %q: invalid status code: %d", url, resp.StatusCode)
	}

	der, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("reading CRL %q: %w", url, err)
	}

	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return false, fmt.Errorf("parsing CRL %q: %w", url, err)
	}

	err = crl.CheckSignatureFrom(issuer)
	if err != nil {
		return false, fmt.Errorf("validating CRL: %w", err)
	}

	return slices.ContainsFunc(crl.RevokedCertificateEntries, func(entry x509.RevocationListEntry) bool {
		return entry.SerialNumber.Cmp(cert.SerialNumber) == 0
	}), nil
}

func (r *revoked) checkReady(ctx context.Context, cert, issuer *x509.Certificate) (time.Time, error) {
	if time.Now().After(cert.NotAfter) {
		return time.Time{}, fmt.Errorf("certificate expired: %s", cert.NotAfter.Format(time.DateTime))
	}

	isRevoked, err := r.checkCRL(ctx, cert, issuer)
	if err != nil {
		r.logger.Warn("Error checking CRL", slogErr(err))

		return time.Now().Add(r.checkInterval), err
	}

	if !isRevoked {
		retryAt := time.Now().Add(r.checkInterval)
		r.logger.Info("Certificate not yet revoked: will recheck", slog.Time("at", retryAt))

		return retryAt, nil
	}

	// The certificate is revoked, so it is ready
	return time.Time{}, nil
}

// checkRenew for a revoked certificate always returns the midpoint of the
// cert's lifetime. We can't use ARI because it'll want to always replace a
// revoked certificate immediately.
func (r *revoked) checkRenew(_ context.Context, cert *x509.Certificate) time.Time {
	return halfTime(cert)
}

func (r *revoked) shouldRevoke() bool {
	return true
}

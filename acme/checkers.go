package acme

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mathrand "math/rand/v2"
	"net/http"
	"slices"
	"time"

	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
)

// checker is the interface used to handle the differences between (valid, revoked, expired) by the issue state machine.
type checker interface {
	// checkReady returns if a certificate is ready.
	// It returns a time to wait with a nil error if we should wait and re-check.
	// If that time has already passed, then the cert is ready to go.
	// It returns an error if we should throw out this cert.
	checkReady(ctx context.Context, cert *x509.Certificate) (time.Time, error)

	// checkRenew returns when we should renew it.
	checkRenew(ctx context.Context, cert *x509.Certificate) time.Time

	// shouldRevoke returns true if this certificate should be revoked.
	shouldRevoke() bool
}

type valid struct {
	client *lego.Client
	logger *slog.Logger
}

func (vc *valid) checkReady(_ context.Context, cert *x509.Certificate) (time.Time, error) {
	if time.Now().After(cert.NotAfter) {
		return time.Time{}, fmt.Errorf("certificate expired: %s", cert.NotAfter.Format(time.DateTime))
	}

	return time.Time{}, nil
}

func (vc *valid) checkRenew(_ context.Context, cert *x509.Certificate) time.Time {
	resp, err := vc.client.Certificate.GetRenewalInfo(certificate.RenewalInfoRequest{
		Cert: cert,
	})
	if errors.Is(err, api.ErrNoARI) {
		// without ARI, renew at 50% lifetime
		return halfTime(cert)
	}
	if err != nil {
		vc.logger.Warn("Error getting renewal info", slogErr(err))

		// Retry in an hour
		return time.Now().Add(time.Hour)
	}

	retry := time.Now().Add(resp.RetryAfter)
	renew := randTime(resp.SuggestedWindow.Start, resp.SuggestedWindow.End)

	if renew.After(retry) {
		// If the renewal time is after RetryAfter, recheck then
		vc.logger.Info("ARI retry", slog.Time("at", retry))

		return retry
	}

	vc.logger.Info("ARI renewal", slog.Time("at", renew))

	return renew
}

func (vc *valid) shouldRevoke() bool {
	return false
}

type revoked struct {
	http   *http.Client
	logger *slog.Logger

	checkInterval time.Duration
}

func (r *revoked) checkCRL(ctx context.Context, cert *x509.Certificate) (bool, error) {
	if len(cert.CRLDistributionPoints) == 0 {
		r.logger.Info("No CRL found")

		// Assume revoked in the no-CRL case
		return true, nil
	}

	DP := cert.CRLDistributionPoints[0]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, DP, nil)
	if err != nil {
		return false, fmt.Errorf("creating HTTP request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("downloading CRL %q: %w", DP, err)
	}
	defer resp.Body.Close()

	der, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("reading CRL %q: %w", DP, err)
	}

	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return false, fmt.Errorf("parsing CRL %q: %w", DP, err)
	}

	// TODO: Need to plumb issuer in here to check the CRL's signature.
	// For now, assume it's OK.
	// err = crl.CheckSignatureFrom(issuer)

	return slices.ContainsFunc(crl.RevokedCertificateEntries, func(entry x509.RevocationListEntry) bool {
		return entry.SerialNumber.Cmp(cert.SerialNumber) == 0
	}), nil
}

func (r *revoked) checkReady(ctx context.Context, cert *x509.Certificate) (time.Time, error) {
	if time.Now().After(cert.NotAfter) {
		return time.Time{}, fmt.Errorf("certificate expired: %s", cert.NotAfter.Format(time.DateTime))
	}

	isRevoked, err := r.checkCRL(ctx, cert)
	if err != nil {
		r.logger.Warn("Error checking CRL", slogErr(err))

		return time.Now().Add(r.checkInterval), err
	}

	if !isRevoked {
		retryAt := time.Now().Add(r.checkInterval)
		r.logger.Info("Certificate not yet revoked: will recheck", slog.Time("at", retryAt))

		return retryAt, err
	}

	// If we don't have a CRLDP, we don't check.
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

type expired struct{}

// checkReady for expired returns when it expires
func (expired) checkReady(_ context.Context, cert *x509.Certificate) (time.Time, error) {
	return cert.NotAfter, nil
}

// checkRenew for expired certs waits the cert's lifetime after it expired.
// That way we replace them to keep up with any profile changes, even if we
// could just keep using one expired cert.
func (expired) checkRenew(_ context.Context, cert *x509.Certificate) time.Time {
	return cert.NotAfter.Add(cert.NotAfter.Sub(cert.NotBefore))
}

func (expired) shouldRevoke() bool {
	return false
}

func randTime(start, end time.Time) time.Time {
	window := int64(end.Sub(start))
	if window <= 0 {
		// If start == end, we'll get a 0 duration, which we can't pass to mathrand.Int64N
		return start
	}

	return start.Add(time.Duration(mathrand.Int64N(window))) //nolint:gosec // math/rand is safe here
}

func halfTime(cert *x509.Certificate) time.Time {
	lifetime := cert.NotAfter.Sub(cert.NotBefore)

	return cert.NotBefore.Add(lifetime / 2) //nolint:mnd
}

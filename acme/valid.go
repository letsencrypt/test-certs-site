package acme

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	mathrand "math/rand/v2"
	"time"

	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
)

type valid struct {
	client *lego.Client
	logger *slog.Logger
}

func (vc *valid) checkReady(_ context.Context, cert, _ *x509.Certificate) (time.Time, error) {
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

func randTime(start, end time.Time) time.Time {
	window := int64(end.Sub(start))
	if window <= 0 {
		// If start == end, we'll get a 0 duration, which we can't pass to mathrand.Int64N
		return start
	}

	return start.Add(time.Duration(mathrand.Int64N(window))) //nolint:gosec // math/rand is safe here
}

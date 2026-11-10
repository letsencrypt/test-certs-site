package acme

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/go-acme/lego/v5/acme/api"
	"github.com/go-acme/lego/v5/certificate"
)

type ari interface {
	GetRenewalInfo(ctx context.Context, cert *x509.Certificate) (*certificate.RenewalInfo, error)
}

type valid struct {
	ari    ari
	logger *slog.Logger
}

func (v *valid) checkReady(_ context.Context, cert, _ *x509.Certificate) (time.Time, error) {
	if time.Now().After(cert.NotAfter) {
		return time.Time{}, fmt.Errorf("certificate expired: %s", cert.NotAfter.Format(time.DateTime))
	}

	return time.Time{}, nil
}

func (v *valid) checkRenew(ctx context.Context, cert *x509.Certificate) time.Time {
	resp, err := v.ari.GetRenewalInfo(ctx, cert)
	if errors.Is(err, api.ErrNoARI) {
		// without ARI, renew at 50% lifetime
		return halfTime(cert)
	}
	if err != nil {
		v.logger.Warn("Error getting renewal info", slogErr(err))

		// Retry in an hour
		return time.Now().Add(time.Hour)
	}

	retry := time.Now().Add(resp.RetryAfter)
	renew := randTime(resp.SuggestedWindow.Start, resp.SuggestedWindow.End)

	if renew.After(retry) {
		// If the renewal time is after RetryAfter, recheck then
		v.logger.Info("ARI retry", slog.Time("at", retry))

		return retry
	}

	v.logger.Info("ARI renewal", slog.Time("at", renew))

	return renew
}

func (v *valid) shouldRevoke() bool {
	return false
}

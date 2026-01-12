package acme

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"

	"github.com/letsencrypt/test-certs-site/certs"
	"github.com/letsencrypt/test-certs-site/scheduler"
	"github.com/letsencrypt/test-certs-site/storage"
)

type issuer struct {
	checker

	domain   string
	issuerCN string
	keyType  string
	profile  string

	client   *lego.Client
	logger   *slog.Logger
	manager  *certs.CertManager
	schedule *scheduler.Schedule
	store    *storage.Storage
}

// start is the main entry point for issuing a certificate.
// It runs as a scheduled job, and reschedules itself to run again.
func (i *issuer) start(ctx context.Context) {
	var renewAt time.Time

	i.logger.Info("checking certificate")

	curr, err := i.store.ReadCurrent(i.domain)
	if err != nil {
		i.logger.Error("reading current certificate", slogErr(err))
		// If we failed to read, leave renewAt zero, and we'll issue a new cert
	} else {
		renewAt = i.checkRenew(ctx, curr.Leaf)
	}

	var nextRun time.Time

	if time.Now().After(renewAt) {
		rerunAt, err := i.issue(ctx)
		if err != nil {
			i.logger.Error("issuing new certificate; will retry", slogErr(err))
			nextRun = time.Now().Add(time.Hour)
		} else {
			nextRun = rerunAt
		}
	} else {
		nextRun = renewAt
		i.logger.Info("scheduling renewal", slog.Time("at", renewAt))
	}

	i.schedule.RunAt(nextRun, i.start)
}

// issue the next certificate, then take it.
// Return the time to call Start next
func (i *issuer) issue(ctx context.Context) (time.Time, error) {
	// Check if there's a next certificate already in progress
	next, err := i.store.ReadNext(i.domain)
	if err != nil {
		i.logger.Info("couldn't read next certificate so issuing", slogErr(err))

		next, err = i.issueNext()
		if err != nil {
			return time.Time{}, err
		}
	}

	if len(next.Certificate) <= 1 {
		return time.Time{}, fmt.Errorf("no issuer certificate: chain length %d", len(next.Certificate))
	}

	issuerCert, err := x509.ParseCertificate(next.Certificate[1])
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing issuer certificate: %w", err)
	}

	readyTime, err := i.checkReady(ctx, next.Leaf, issuerCert)
	if err != nil {
		// checkReady can return an error if the current "next" cert is broken (eg, expired)
		// and so we need to issue a new one to start over.
		_, errNext := i.issueNext()
		if errNext != nil {
			return time.Time{}, errNext
		}

		// Return the original error from checkReady, for logging
		return time.Time{}, err
	}

	if time.Now().After(readyTime) {
		err := i.takeNext()
		if err != nil {
			return time.Time{}, err
		}

		i.logger.Info("certificate issuance completed")

		// Return a zero time and no error, which will restart immediately to schedule renewal
		return time.Time{}, nil
	}

	// Re-check at readyTime
	return readyTime, nil
}

// issueNext is called to actually issue the next certificate
func (i *issuer) issueNext() (tls.Certificate, error) {
	i.logger.Info("issuing new next certificate")
	key, err := i.store.StoreNextKey(i.domain, i.keyType)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not store next key: %w", err)
	}
	resp, err := i.client.Certificate.Obtain(certificate.ObtainRequest{
		Profile:        i.profile,
		Domains:        []string{i.domain},
		Bundle:         true,
		PrivateKey:     key,
		PreferredChain: i.issuerCN,
	})
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not obtain certificate: %w", err)
	}

	if i.shouldRevoke() {
		// Revoke with reason keyCompromise so browsers actually process this revocation
		reasonKeyCompromise := uint(1)
		err := i.client.Certificate.RevokeWithReason(resp.Certificate, &reasonKeyCompromise)
		if err != nil {
			// TODO: if we failed to revoke, we should probably retry revoking
			return tls.Certificate{}, fmt.Errorf("could not revoke certificate: %w", err)
		}
	}

	err = i.store.StoreNextCert(i.domain, resp.Certificate)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not store next certificate: %w", err)
	}

	i.logger.Info("next certificate issued", slog.String("domain", i.domain))

	return i.store.ReadNext(i.domain)
}

// takeNext checks if the next certificate is ready, and takes it if so
func (i *issuer) takeNext() error {
	i.logger.Info("next certificate is ready")
	_, err := i.store.TakeNext(i.domain)
	if err != nil {
		return err
	}

	return i.manager.LoadCertificate(i.domain)
}

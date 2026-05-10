package acme

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	mathrand "math/rand/v2"
	"slices"
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
	issuerO  string
	keyType  string
	profile  string

	// retryWindow is the upper bound on the random delay used when scheduling
	// a retry after an issuance failure.
	retryWindow time.Duration

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
			// Pick a delay uniformly in [retryWindow/10, retryWindow). The
			// floor keeps us from immediately re-hammering the ACME server
			// when several issuers fail in close succession.
			minDelay := i.retryWindow / 10                                                         //nolint:mnd
			retryDelay := minDelay + time.Duration(mathrand.Int64N(int64(i.retryWindow-minDelay))) //nolint:gosec // Not security-sensitive use
			nextRun = time.Now().Add(retryDelay)
			i.logger.Error("issuing new certificate; will retry",
				slogErr(err),
				slog.Duration("retryIn", retryDelay),
				slog.Time("retryAt", nextRun))
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
// Return the time to call i.start next
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

	// Lego silently falls back to the CA's default chain when no alternate
	// chain matches PreferredChain, and PreferredChain only matches Issuer
	// CN. We must never serve the wrong chain on this site, so reject the
	// certificate if the chain doesn't end at the expected issuer (matched
	// on both CN and, if configured, Organization).
	err = verifyIssuerChain(resp.Certificate, i.issuerCN, i.issuerO)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("could not verify issuer chain: %w", err)
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

// verifyIssuerChain checks that the topmost certificate in the PEM bundle is
// issued by issuerCN, and (if non-empty) by issuerO. The bundle returned by
// Lego does not contain the root, so the top certificate is typically the
// intermediate, and its Issuer fields name the root.
func verifyIssuerChain(bundle []byte, issuerCN, issuerO string) error {
	var top *x509.Certificate

	rest := bundle
	for {
		var block *pem.Block

		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parsing certificate in chain: %w", err)
		}

		top = cert
	}

	if top == nil {
		return fmt.Errorf("no certificates found in chain")
	}

	if top.Issuer.CommonName != issuerCN {
		return fmt.Errorf("chain does not end at expected issuer CN %q: top certificate issued by CN %q",
			issuerCN, top.Issuer.CommonName)
	}

	if issuerO != "" && !slices.Contains(top.Issuer.Organization, issuerO) {
		return fmt.Errorf("chain does not end at expected issuer O %q: top certificate issued by O %v",
			issuerO, top.Issuer.Organization)
	}

	return nil
}

package acme

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"

	"github.com/letsencrypt/test-certs-site/certs"
	"github.com/letsencrypt/test-certs-site/scheduler"
	"github.com/letsencrypt/test-certs-site/storage"
)

func slogErr(err error) slog.Attr {
	return slog.String("error", err.Error())
}

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

func (i *issuer) start() {
	var renewAt time.Time

	i.logger.Info("checking certificate")

	curr, err := i.store.ReadCurrent(i.domain)
	if err != nil {
		i.logger.Error("reading current certificate", slogErr(err))
		// If we failed to read, leave renewAt zero, and we'll issue a new cert
	} else {
		renewAt = i.checkRenew(curr.Leaf)
	}

	if time.Now().After(renewAt) {
		err := i.issue()
		if err != nil {
			i.logger.Error("issuing new certificate; will retry", slogErr(err))

			i.schedule.RunIn(time.Hour, func() { i.start() })
		}

		return
	}

	// Otherwise, schedule rechecking into the future
	i.logger.Info("scheduling renewal", slog.String("at", renewAt.Format(time.DateTime)))
	i.schedule.RunAt(renewAt, func() { i.start() })
}

// issue the next certificate, then take it.
func (i *issuer) issue() error {
	// Check if there's a next certificate already in progress
	next, err := i.store.ReadNext(i.domain)
	if err != nil {
		i.logger.Info("couldn't read next certificate so issuing", slogErr(err))

		next, err = i.issueNext()
		if err != nil {
			return err
		}
	}

	readyTime, err := i.checkReady(next.Leaf)
	if err != nil {
		i.logger.Error("checking ready certificate", slogErr(err))

		// checkReady can return an error if the current "next" cert is broken (eg, expired)
		// and so we need to issue a new one and start over.
		_, err = i.issueNext()
		if err != nil {
			return err
		}

		return i.issue()
	}

	if time.Now().After(readyTime) {
		err := i.takeNext()
		if err != nil {
			return err
		}

		i.logger.Info("certificate issuance completed")

		// Jump back to start to schedule renewal
		i.start()

		return nil
	}

	// Re-check at readyTime
	i.logger.Info("waiting for next certificate to be ready", slog.String("at", readyTime.Format(time.DateTime)))
	i.schedule.RunAt(readyTime, i.start)

	return nil
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
		// Revoke with reason keyCompromise because browsers believe that one
		reasonKeyCompromise := uint(0)
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
// It returns the time to start() next
func (i *issuer) takeNext() error {
	i.logger.Info("next certificate is ready")
	// Next cert is ready! Take it.
	_, err := i.store.TakeNext(i.domain)
	if err != nil {
		return err
	}
	err = i.manager.LoadCertificate(i.domain)
	if err != nil {
		return err
	}

	return nil
}

// Package certs handles issuing certificates specified in the configuration.
package certs

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/letsencrypt/test-certs-site/config"
	"github.com/letsencrypt/test-certs-site/storage"
)

type certificate struct {
	*tls.Certificate

	shouldBeExpired bool
}

// CertManager manages the issued certificates
type CertManager struct {
	// mu protects certs
	mu sync.Mutex

	// certs is a map of domain to the certificate served
	certs map[string]*certificate

	// storage provides persistent storage for certs
	storage *storage.Storage
}

// New sets up the certs issuer.
// This will register an ACME account if needed.
func New(_ context.Context, cfg *config.Config, store *storage.Storage) (*CertManager, error) {
	c := &CertManager{
		certs:   make(map[string]*certificate),
		storage: store,
	}

	// Load "Current" certs for each domain, if they exist
	for _, site := range cfg.Sites {
		c.certs[site.Domains.Valid] = &certificate{shouldBeExpired: false}
		err := c.LoadCertificate(site.Domains.Valid)
		if err != nil {
			slog.Info("No current valid certificate", slog.String("domain", site.Domains.Valid), slog.String("error", err.Error()))
		}

		c.certs[site.Domains.Revoked] = &certificate{shouldBeExpired: false}
		err = c.LoadCertificate(site.Domains.Revoked)
		if err != nil {
			slog.Info("No current revoked certificate", slog.String("domain", site.Domains.Revoked), slog.String("error", err.Error()))
		}

		c.certs[site.Domains.Expired] = &certificate{shouldBeExpired: true}
		err = c.LoadCertificate(site.Domains.Expired)
		if err != nil {
			slog.Info("No current expired certificate", slog.String("domain", site.Domains.Expired), slog.String("error", err.Error()))
		}
	}

	return c, nil
}

// LoadCertificate will reload a certificate from storage.
// Called at startup and by the ACME client when a new certificate is current.
func (c *CertManager) LoadCertificate(domain string) error {
	currCert, err := c.storage.ReadCurrent(domain)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	cert, ok := c.certs[domain]
	if !ok {
		return fmt.Errorf("unknown site %s", domain)
	}

	cert.Certificate = &currCert

	return nil
}

// GetCertificate implements the interface required by tls.Config
func (c *CertManager) GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	sni := info.ServerName

	c.mu.Lock()
	defer c.mu.Unlock()

	cert, ok := c.certs[info.ServerName]
	if !ok {
		return nil, fmt.Errorf("unknown site %s", sni)
	}

	if cert.Certificate == nil {
		return nil, fmt.Errorf("no certificate for %s", sni)
	}

	expired := time.Now().After(cert.Leaf.NotAfter)
	if expired && !cert.shouldBeExpired {
		return nil, fmt.Errorf("certificate for %s is expired", sni)
	}

	if !expired && cert.shouldBeExpired {
		return nil, fmt.Errorf("certificate for %s is not expired, but should be", sni)
	}

	return cert.Certificate, nil
}

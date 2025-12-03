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

	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
)

// CertManager manages the issued certificates
type CertManager struct {
	// mu protects certs
	mu sync.Mutex

	// certs is a map of domain to the certificate served
	certs map[string]*tls.Certificate

	// challengeCerts is a map of domain to TLS-ALPN-01 challenge certs
	challengeCerts map[string]*tls.Certificate

	// expired is a map of domain to whether the cert is expected to be expired
	expired map[string]bool

	// storage provides persistent storage for certs
	storage *storage.Storage
}

// New sets up the certs issuer.
// This will register an ACME account if needed.
func New(_ context.Context, cfg *config.Config, store *storage.Storage) (*CertManager, error) {
	c := &CertManager{
		certs:          make(map[string]*tls.Certificate),
		challengeCerts: make(map[string]*tls.Certificate),
		expired:        make(map[string]bool),
		storage:        store,
	}

	// Load "Current" certs for each domain, if they exist
	for _, site := range cfg.Sites {
		err := c.LoadCertificate(site.Domains.Valid)
		if err != nil {
			slog.Info("No current valid certificate", slog.String("domain", site.Domains.Valid), slog.String("error", err.Error()))
		}
		c.expired[site.Domains.Valid] = false

		err = c.LoadCertificate(site.Domains.Revoked)
		if err != nil {
			slog.Info("No current revoked certificate", slog.String("domain", site.Domains.Revoked), slog.String("error", err.Error()))
		}
		c.expired[site.Domains.Revoked] = false

		err = c.LoadCertificate(site.Domains.Expired)
		if err != nil {
			slog.Info("No current expired certificate", slog.String("domain", site.Domains.Expired), slog.String("error", err.Error()))
		}
		c.expired[site.Domains.Expired] = true
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

	c.certs[domain] = &currCert

	return nil
}

// isACME returns true if this ClientHello looks like a TLS-ALPN challenge
func isACME(info *tls.ClientHelloInfo) bool {
	return len(info.SupportedProtos) == 1 && info.SupportedProtos[0] == tlsalpn01.ACMETLS1Protocol
}

// GetCertificate implements the interface required by tls.Config
func (c *CertManager) GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	sni := info.ServerName

	c.mu.Lock()
	defer c.mu.Unlock()

	if isACME(info) {
		challengeCert, ok := c.challengeCerts[sni]
		if !ok {
			return nil, fmt.Errorf("no challenge certificate found for %q", sni)
		}

		return challengeCert, nil
	}

	cert, ok := c.certs[info.ServerName]
	if !ok {
		return nil, fmt.Errorf("no certificate for %s", sni)
	}

	expired := time.Now().After(cert.Leaf.NotAfter)
	shouldBeExpired, ok := c.expired[info.ServerName]
	if !ok {
		return nil, fmt.Errorf("cert for %s not in c.expired", sni)
	}

	if expired && !shouldBeExpired {
		return nil, fmt.Errorf("certificate for %s is expired", sni)
	}

	if !expired && shouldBeExpired {
		return nil, fmt.Errorf("certificate for %s is not expired, but should be", sni)
	}

	return cert, nil
}

// Present is a method from the lego challenge.Provider interface.
// It creates and stores a TLS-ALPN-01 challenge certificate.
func (c *CertManager) Present(domain, _, keyAuth string) error {
	challengeCert, err := tlsalpn01.ChallengeCert(domain, keyAuth)
	if err != nil {
		return fmt.Errorf("creating challenge certificate: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.challengeCerts[domain] = challengeCert

	return nil
}

// CleanUp implements the lego challenge.Provider interface.
// It removes the challenge certificate once it is no longer needed.
func (c *CertManager) CleanUp(domain, _, _ string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.challengeCerts, domain)

	return nil
}

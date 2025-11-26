// Package certs handles issuing certificates specified in the configuration.
package certs

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"sync"

	"github.com/letsencrypt/test-certs-site/config"
	"github.com/letsencrypt/test-certs-site/storage"

	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
)

// CertManager manages the issued certificates
type CertManager struct {
	// mu protects certs
	mu sync.Mutex

	// certs is a map of domain to a cert struct
	certs map[string]cert

	// challengeCerts is a map of domain to TLS-ALPN-01 challenge certs
	challengeCerts map[string]*tls.Certificate

	// storage provides persistent storage for certs
	storage *storage.Storage
}

// cert holds an individual certificate
type cert struct {
	it *tls.Certificate

	// shouldBeExpired is true if this certificate is expected to be expired.
	shouldBeExpired bool
}

// load tries to load a certificate, if one exists.
// It logs if it fails.
func load(store *storage.Storage, cm *CertManager, domain string, expired bool) {
	curr, err := store.ReadCurrent(domain)
	if err != nil {
		slog.Info("No current certificate", slog.String("domain", domain), slog.String("error", err.Error()))
		return
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.certs[domain] = cert{it: &curr, shouldBeExpired: expired}
}

// New sets up the certs issuer.
// This will register an ACME account if needed.
func New(_ context.Context, cfg *config.Config, store *storage.Storage) (*CertManager, error) {
	c := CertManager{
		certs:          make(map[string]cert),
		challengeCerts: make(map[string]*tls.Certificate),
		storage:        store,
	}

	// Load "Current" certs for each domain, if they exist
	for _, site := range cfg.Sites {
		load(store, &c, site.Domains.Valid, false)
		load(store, &c, site.Domains.Revoked, false)
		load(store, &c, site.Domains.Expired, true)
	}

	return &c, nil
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

	return cert.it, nil
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

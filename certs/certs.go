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
)

// CertManager manages the issued certificates
type CertManager struct {
	// mu protects certs
	mu sync.Mutex

	// certs is a map of domain to a cert struct
	certs map[string]cert

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
func load(store *storage.Storage, domain string, expired bool) cert {
	curr, err := store.ReadCurrent(domain)
	if err != nil {
		slog.Info("No current certificate", slog.String("domain", domain), slog.String("error", err.Error()))
		return cert{shouldBeExpired: expired}
	}
	return cert{it: &curr, shouldBeExpired: expired}
}

// New sets up the certs issuer.
// This will register an ACME account if needed.
func New(_ context.Context, cfg *config.Config, store *storage.Storage) (*CertManager, error) {
	c := CertManager{
		certs:   make(map[string]cert),
		storage: store,
	}

	// Load "Current" certs for each domain, if they exist
	for _, site := range cfg.Sites {
		c.certs[site.Domains.Valid] = load(store, site.Domains.Valid, false)
		c.certs[site.Domains.Revoked] = load(store, site.Domains.Revoked, false)
		c.certs[site.Domains.Expired] = load(store, site.Domains.Expired, true)
	}

	return &c, nil
}

// GetCertificate implements the interface required by tls.Config
func (c *CertManager) GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	sni := info.ServerName

	c.mu.Lock()
	defer c.mu.Unlock()

	cert, ok := c.certs[info.ServerName]
	if !ok {
		return nil, fmt.Errorf("no certificate for %s", sni)
	}

	return cert.it, nil
}

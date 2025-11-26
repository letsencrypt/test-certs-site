// Package certs handles issuing certificates specified in the configuration.
package certs

import (
	"context"
	"crypto/tls"
	"fmt"
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
}

// New sets up the certs issuer.
// This will register an ACME account if needed.
func New(_ context.Context, cfg *config.Config, store *storage.Storage) (*CertManager, error) {
	c := CertManager{
		certs:   make(map[string]cert),
		storage: store,
	}

	for _, site := range cfg.Sites {
		c.certs[site.Domains.Valid] = cert{
			// TODO: Set up the valid cert
		}
		c.certs[site.Domains.Revoked] = cert{
			// TODO: Set up the revoked cert
		}
		c.certs[site.Domains.Expired] = cert{
			// TODO: Set up the expired cert
		}
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

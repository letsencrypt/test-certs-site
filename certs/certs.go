// Package certs handles issuing certificates specified in the configuration.
package certs

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
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

	// This is just a temporary placeholder, using a single static test certificate
	certFile := os.Getenv("TEST_CERT")
	keyFile := os.Getenv("TEST_KEY")
	temporaryStaticCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading temporary certificate: %w", err)
	}

	for _, site := range cfg.Sites {
		c.certs[site.Domains.Valid] = cert{
			// TODO: Set up the valid cert
			it: &temporaryStaticCert,
		}
		c.certs[site.Domains.Revoked] = cert{
			// TODO: Set up the revoked cert
			it: &temporaryStaticCert,
		}
		c.certs[site.Domains.Expired] = cert{
			// TODO: Set up the expired cert
			it: &temporaryStaticCert,
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

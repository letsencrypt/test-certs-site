// Package config handles test-cert-site's configuration file loading.
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Load a configuration file from cfgPath.
func Load(cfgPath string) (*Config, error) {
	cfgBytes, err := os.ReadFile(cfgPath) //nolint:gosec // Reading arbitrary config file is expected
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var cfg Config

	err = json.Unmarshal(cfgBytes, &cfg)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", cfgPath, err)
	}

	return &cfg, nil
}

// Config is the structure of the JSON configuration file.
type Config struct {
	// Sites is a list of sites to host.
	Sites []Site

	// DataDir where the application will write its local state.
	// This includes keys for certificates and ACME, as well as certificates.
	// It should exist and be writable.
	DataDir string

	// ACME client configuration.
	ACME ACME
}

// Site configures a particular site.
type Site struct {
	// IssuerCN that the certificate chain must end in.
	IssuerCN string

	// KeyType to use for this site. Should be "p256" or "rsa2048".
	KeyType string

	// Profile selects the ACME profile to use for this certificate.
	Profile string

	// Domain names to use.
	Domains Domains
}

// Domains that this demo site will serve.
type Domains struct {
	Valid   string
	Expired string
	Revoked string
}

// ACME client configuration, shared between all sites.
type ACME struct {
	// Directory URL.
	Directory string

	// CACerts file used when connecting via TLS to the CA.
	// Optional and typically only used in test environments.
	CACerts string
}

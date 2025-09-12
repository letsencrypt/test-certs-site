// Package config handles test-cert-site's configuration file loading
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
	// Sites is a map hostname -> Site specific configuration
	Sites map[string]Site

	ACME ACME
}

// Site configures a particular site.
type Site struct {
	// Status for this site. Must be "valid", "expired", or "revoked".
	Status string

	// RootCN is the Common Name that this certificate must chain up to.
	RootCN string

	// KeyType to use for this site. Should be "p256" or "rsa2048".
	KeyType string

	// Profile selects the ACME profile to use for this certificate.
	Profile string

	// Files stored for this site.
	Files Files

	// FilesNext stores files during issuance that will be used next.
	// Especially for "expired" sites, this may be a long time and so
	// should be stored on durable storage.
	FilesNext Files
}

// Files has a list of file paths on disk.
type Files struct {
	// Cert stores the x509 certificate and chain
	Cert string

	// Key storing private key for certificate
	Key string
}

// ACME client configuration, shared between all sites.
type ACME struct {
	// Directory URL
	Directory string

	// ClientKey stores the JWS key used for authentication
	ClientKey string

	// CACerts file used when connecting via TLS to the CA.
	// Optional and typically only used in test environments.
	CACerts string
}

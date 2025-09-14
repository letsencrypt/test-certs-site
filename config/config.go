// Package config handles test-cert-site's configuration file loading.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

const (
	// KeyTypeP256 is one of the valid key types in configuration.
	KeyTypeP256 = "p256"

	// KeyTypeRSA2048 is one of the valid key types in configuration.
	KeyTypeRSA2048 = "rsa2048"
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

	err = validate(&cfg)
	if err != nil {
		return nil, fmt.Errorf("validating %s: %w", cfgPath, err)
	}

	return &cfg, nil
}

// validate the loaded configuration.
// This checks domains are unique, key types are valid, and that an issuer CN is set.
func validate(cfg *Config) error {
	domains := make(map[string]struct{}, 0)
	var errs []error
	for i, site := range cfg.Sites {
		switch site.KeyType {
		case KeyTypeP256, KeyTypeRSA2048:
			// Valid key types
		default:
			errs = append(errs, fmt.Errorf("site %d unsupported key type: %s", i, site.KeyType))
		}

		for _, d := range []string{site.Domains.Valid, site.Domains.Revoked, site.Domains.Expired} {
			_, seen := domains[d]
			if seen {
				errs = append(errs, fmt.Errorf("site %d duplicate domain: %s", i, d))
			}
			domains[d] = struct{}{}
		}

		if site.IssuerCN == "" {
			errs = append(errs, fmt.Errorf("site %d missing issuer CN", i))
		}
	}

	return errors.Join(errs...)
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
	// Optional.
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

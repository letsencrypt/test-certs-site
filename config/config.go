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

	// KeyTypeMLDSA44 is one of the valid key types in configuration.
	KeyTypeMLDSA44 = "mldsa44"
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
// This checks domains are unique, key types are valid, and that an issuer is set.
func validate(cfg *Config) error {
	domains := make(map[string]struct{}, 0)
	var errs []error
	for i, site := range cfg.Sites {
		switch site.KeyType {
		case KeyTypeP256, KeyTypeRSA2048, KeyTypeMLDSA44:
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

		errs = append(errs, validateIssuer(i, site)...)
	}

	if cfg.ACME.Directory == "" {
		errs = append(errs, fmt.Errorf("acme directory required"))
	}

	if !cfg.ACME.TermsOfServiceAgreed {
		errs = append(errs, fmt.Errorf("review and agree to terms of service"))
	}

	return errors.Join(errs...)
}

// validateIssuer checks that the site identifies its issuer either by CN (and
// optionally O), or by certificate, but not both.
func validateIssuer(i int, site Site) []error {
	var errs []error

	switch {
	case site.MTCIssuerCertificate == "" && site.IssuerCN == "":
		errs = append(errs, fmt.Errorf("site %d missing issuer CN or MTC issuer certificate", i))
	case site.MTCIssuerCertificate == "":
		// Identified by CN. IssuerO is optional.
	default:
		if site.IssuerCN != "" {
			errs = append(errs, fmt.Errorf("site %d has both issuer CN and MTC issuer certificate", i))
		}

		if site.IssuerO != "" {
			errs = append(errs, fmt.Errorf("site %d has both issuer O and MTC issuer certificate", i))
		}
	}

	return errs
}

// Config is the structure of the JSON configuration file.
type Config struct {
	// ListenAddr for the demo site to listen on. Eg, ":443".
	ListenAddr string

	// DebugAddr is the listen address for metrics and pprof
	DebugAddr string

	// Sites is a list of sites to host.
	Sites []Site

	// DataDir where the application will write its local state.
	// This includes keys for certificates and ACME, as well as certificates.
	// It should exist and be writable.
	DataDir string

	// ACME client configuration.
	ACME ACME

	// HTMLTemplate overrides the default HTML webpage
	HTMLTemplate string

	// TextTemplate overrides the default plain text webpage
	TextTemplate string

	// LogDebug enables debug level logs when set to true
	LogDebug bool

	// RevokeDelay wait to use a revoked certificate, from the certificate's NotBefore time.
	RevokeDelay Duration

	// CRLCheckInterval is the re-checking interval for CRLs
	CRLCheckInterval Duration
}

// Site configures a particular site.
type Site struct {
	// IssuerCN that the certificate chain must end in.
	// Exactly one of IssuerCN or MTCIssuerCertificate must be set.
	IssuerCN string

	// IssuerO that the certificate chain must end in. Optional.
	// If set, the topmost certificate's Issuer Organization must contain
	// this value in addition to matching IssuerCN.
	IssuerO string

	// MTCIssuerCertificate is the path to the PEM certificate of the merkle tree
	// CA expected to issue the certificate. Must be set if issuing a merkle
	// tree certificate, which is verified against this CA: it must name the CA
	// as its issuer, and carry a valid cosignature from the CA's key.
	// Can't be combined with IssuerCN or IssuerO.
	MTCIssuerCertificate string

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

	// TermsOfServicesAgreed should be set after reviewing the CA's TOS.
	TermsOfServiceAgreed bool
}

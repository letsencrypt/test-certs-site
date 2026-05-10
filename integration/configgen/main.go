// Package main generates the integration test's test-certs-site config by
// fetching Pebble's randomized root CA CN from its management API and writing
// out a config that pins to that CN.
//
// Pebble assigns a fresh `Pebble Root CA <hex>` CN on every startup, and
// test-certs-site now requires the configured IssuerCN to match the chain
// it actually receives. This helper bridges those two facts.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/letsencrypt/test-certs-site/config"
)

const (
	httpTimeout    = 10 * time.Second
	configFileMode = 0o644
)

func main() {
	rootsURL := flag.String("roots-url", "https://localhost:15000/roots/0",
		"Pebble management API URL for the root certificate")
	outputPath := flag.String("output", "integration/test-certs-site-config.json",
		"Path to write the generated config")
	timeout := flag.Duration("timeout", time.Minute,
		"How long to wait for Pebble to start responding")
	flag.Parse()

	err := run(*rootsURL, *outputPath, *timeout)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func run(rootsURL, outputPath string, timeout time.Duration) error {
	// Don't validate Pebble's cert, so we can avoid hardcoding its test root
	client := &http.Client{
		Timeout: httpTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // Test-only fixture
		},
	}

	cn, err := fetchRootCN(client, rootsURL, timeout)
	if err != nil {
		return fmt.Errorf("fetching pebble root CN: %w", err)
	}

	slog.Info("got pebble root CN", slog.String("cn", cn))

	cfg := config.Config{
		ListenAddr: ":5001",
		DebugAddr:  ":9001",
		Sites: []config.Site{
			{
				IssuerCN: cn,
				KeyType:  config.KeyTypeP256,
				Domains: config.Domains{
					Valid:   "valid.localhost",
					Expired: "expired.localhost",
					Revoked: "revoked.localhost",
				},
			},
		},
		ACME: config.ACME{
			Directory:            "https://pebble:14000/dir",
			TermsOfServiceAgreed: true,
		},
		DataDir:          "/data",
		LogDebug:         true,
		RevokeDelay:      config.Duration(time.Second),
		CRLCheckInterval: config.Duration(time.Second),
		IssueRetryWindow: config.Duration(time.Second),
	}

	body, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	err = os.WriteFile(outputPath, append(body, '\n'), configFileMode)
	if err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	slog.Info("wrote config", slog.String("path", outputPath))

	return nil
}

func fetchRootCN(client *http.Client, url string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error

	for time.Now().Before(deadline) {
		cn, err := tryFetch(client, url)
		if err == nil {
			return cn, nil
		}
		lastErr = err
		slog.Info("pebble not ready, retrying", slog.String("error", err.Error()))
		time.Sleep(time.Second)
	}

	return "", fmt.Errorf("timed out after %s: %w", timeout, lastErr)
}

func tryFetch(client *http.Client, url string) (string, error) {
	resp, err := client.Get(url) //nolint:noctx // Short-lived helper
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading body: %w", err)
	}

	block, _ := pem.Decode(body)
	if block == nil {
		return "", fmt.Errorf("no PEM block in response")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parsing certificate: %w", err)
	}

	if cert.Subject.CommonName == "" {
		return "", fmt.Errorf("certificate has empty Subject CN")
	}

	return cert.Subject.CommonName, nil
}

//go:build integration

package integration

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"testing"
	"time"
)

func httpClient(rootPEM []byte) *http.Client {
	x509CertPool := x509.NewCertPool()
	ok := x509CertPool.AppendCertsFromPEM(rootPEM)
	if !ok {
		panic("failed to parse root certificate")
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: x509CertPool,
			},
		},
	}
}

func pemCert(cert []byte) *x509.Certificate {
	block, _ := pem.Decode(cert)
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}
	return parsed
}

// getPebbleRoot uses Pebble's management API to get the root it is using.
func getPebbleRoot() ([]byte, error) {
	// Pebble is listening with a hardcoded CA, which we load from this PEM:
	data, err := os.ReadFile("pebble.minica.pem")
	if err != nil {
		return nil, err
	}

	client := httpClient(data)
	resp, err := client.Get("https://localhost:15000/roots/0")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

// checkCert returns the expiry date of a cert
// It checks that it got an http 200 response
// It assumes the server is listening on localhost:5001
func checkCert(serverName string, root []byte, insecure bool) (time.Time, error) {
	client := httpClient(root)
	client.Transport.(*http.Transport).TLSClientConfig.ServerName = serverName
	client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = insecure

	resp, err := client.Get("https://localhost:5001/")
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return time.Time{}, err
	}

	if !bytes.Contains(body, []byte(serverName)) {
		return time.Time{}, fmt.Errorf("response body didn't contain server name: %s", string(body))
	}

	chainIssuer := resp.TLS.PeerCertificates[len(resp.TLS.PeerCertificates)-1].Issuer
	if chainIssuer.CommonName != pemCert(root).Subject.CommonName {
		return time.Time{}, fmt.Errorf("chain didn't end in expected issuer: %s", chainIssuer)
	}

	return resp.TLS.PeerCertificates[0].NotAfter, nil
}

func checkAll(root []byte) (time.Time, time.Time, time.Time, error) {
	valid, err := checkCert("valid.tsc", root, false)
	if err != nil {
		return time.Time{}, time.Time{}, time.Time{}, fmt.Errorf("error checking valid certificate: %s", err)
	}

	if valid.Before(time.Now()) {
		return time.Time{}, time.Time{}, time.Time{}, fmt.Errorf("valid cert expired: %s", valid)
	}

	revoked, err := checkCert("revoked.tsc", root, false)
	if err != nil {
		return time.Time{}, time.Time{}, time.Time{}, fmt.Errorf("error checking revoked certificate: %s", err)
	}

	if revoked.Before(time.Now()) {
		return time.Time{}, time.Time{}, time.Time{}, fmt.Errorf("revoked cert expired: %s", revoked)
	}

	expired, err := checkCert("expired.tsc", root, true)
	if err != nil {
		return time.Time{}, time.Time{}, time.Time{}, fmt.Errorf("error checking expired certificate: %s", err)
	}

	if expired.After(time.Now()) {
		return time.Time{}, time.Time{}, time.Time{}, fmt.Errorf("expired cert NOT expired: %s", expired)
	}

	return valid, revoked, expired, nil
}

// Wait for all the certs to be ready, which should happen once the "expired" cert expires
func waitForAll(root []byte) error {
	var err error
	for range 5 {
		_, _, _, err = checkAll(root)
		if err == nil {
			return nil
		}

		slog.Info("not ready, sleeping", slog.Duration("sleep", time.Minute), slog.String("error", err.Error()))
		time.Sleep(time.Minute)
	}

	return err
}

// Wait for all certificates to renew
func waitRenew(root []byte) error {
	valid, revoked, expired, err := checkAll(root)
	if err != nil {
		return err
	}

	for range 5 {
		newValid, newRevoked, newExpired, err := checkAll(root)
		if err != nil {
			return err
		}

		if newValid.After(valid) && newRevoked.After(revoked) && newExpired.After(expired) {
			slog.Info("All certificates renewed",
				slog.Time("valid", newValid), slog.Time("revoked", newRevoked), slog.Time("expired", newExpired))

			return nil
		}

		slog.Info("certs not renewed, sleeping", slog.Duration("sleep", time.Minute),
			slog.Time("valid", newValid), slog.Time("revoked", newRevoked), slog.Time("expired", newExpired))

		time.Sleep(time.Minute)
	}

	return fmt.Errorf("certificates not renewed after 5 minutes: %s %s %s", valid, revoked, expired)
}

// TestIntegration verifies that test-certs-site is working properly.
// It assumes that test-certs-site and pebble are running with the configurations
// in this directory.
func TestPebbleIntegration(t *testing.T) {
	root, err := getPebbleRoot()
	if err != nil {
		t.Fatal(err)
	}

	err = waitForAll(root)
	if err != nil {
		t.Fatal(err)
	}

	err = waitRenew(root)
	if err != nil {
		t.Fatal(err)
	}
}

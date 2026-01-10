package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCheckRevokedRenew(t *testing.T) {
	t.Parallel()

	r := &revoked{}
	now := time.Now()
	minuteAhead := now.Add(time.Minute)
	hourAhead := now.Add(time.Hour)

	renew := r.checkRenew(t.Context(), &x509.Certificate{NotBefore: now, NotAfter: hourAhead})
	if renew.Before(minuteAhead) {
		t.Fatal("renew time should be in the future")
	}
	if renew.After(hourAhead) {
		t.Fatal("renew time should be before cert expires")
	}
}

func TestCheckRevoked(t *testing.T) {
	t.Parallel()

	caKey, caCert := createMockCA(t)
	crlData := createMockCRL(t, caCert, caKey)
	crlPath := "/test.crl"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != crlPath {
			t.Errorf("Unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(crlData)
	}))
	t.Cleanup(server.Close)

	r := &revoked{
		http:          server.Client(),
		logger:        slog.Default(),
		checkInterval: time.Minute,
	}

	if !r.shouldRevoke() {
		t.Fatal("revoked certs should revoke")
	}

	readyTime, err := r.checkReady(t.Context(), createMockCert(t, caCert, caKey, server.URL+crlPath), caCert)
	if err != nil {
		t.Fatal(err)
	}
	if !readyTime.IsZero() {
		t.Fatal("expected revoked cert to be ready")
	}
}

func createMockCA(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	return caKey, caCert
}

func createMockCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, crlURL string) *x509.Certificate {
	t.Helper()

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(12345),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		CRLDistributionPoints: []string{crlURL},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, caCert, &certKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}

func createMockCRL(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) []byte {
	t.Helper()

	crlTemplate := &x509.RevocationList{
		Number: big.NewInt(1),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{
				SerialNumber:   big.NewInt(12345),
				RevocationTime: time.Now(),
			},
		},
	}

	crlData, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	if err != nil {
		t.Fatal(err)
	}

	return crlData
}

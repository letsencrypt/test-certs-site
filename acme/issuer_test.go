package acme

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// signCert generates a key, signs a cert with the parent (or self-signs if
// parent is nil), and returns the parsed cert plus its private key.
func signCert(t *testing.T, tmpl, parent *x509.Certificate, parentKey crypto.Signer) (*x509.Certificate, crypto.Signer) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer := parentKey
	signedBy := parent
	if signer == nil {
		signer = key
		signedBy = tmpl
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, signedBy, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return cert, key
}

// makeChain returns a PEM bundle of leaf + intermediate, where the intermediate
// has the given issuer CN and Organization as its Issuer field (to mimic an
// ACME-issued chain).
func makeChain(t *testing.T, intermediateIssuerCN string, intermediateIssuerO []string) []byte {
	t.Helper()

	notBefore := time.Now().Add(-time.Hour)
	notAfter := time.Now().Add(time.Hour)

	rootCert, rootKey := signCert(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: intermediateIssuerCN, Organization: intermediateIssuerO},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil, nil)

	intCert, intKey := signCert(t, &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Intermediate"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, rootCert, rootKey)

	leafCert, _ := signCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "leaf.example"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{"leaf.example"},
	}, intCert, intKey)

	var buf bytes.Buffer
	for _, cert := range []*x509.Certificate{leafCert, intCert} {
		err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		if err != nil {
			t.Fatal(err)
		}
	}

	return buf.Bytes()
}

func TestVerifyIssuerChain(t *testing.T) {
	t.Parallel()

	chain := makeChain(t, "Root YE", []string{"ISRG"})

	err := verifyIssuerChain(chain, "Root YE", "")
	if err != nil {
		t.Fatalf("CN-only match should verify, got: %v", err)
	}

	err = verifyIssuerChain(chain, "Root YE", "ISRG")
	if err != nil {
		t.Fatalf("CN+O match should verify, got: %v", err)
	}

	err = verifyIssuerChain(chain, "Wrong Root CA", "")
	if err == nil {
		t.Fatal("expected error for mismatched issuer CN")
	}

	err = verifyIssuerChain(chain, "Root YE", "Acme Inc")
	if err == nil {
		t.Fatal("expected error for mismatched issuer O")
	}

	noO := makeChain(t, "Root YE", nil)

	err = verifyIssuerChain(noO, "Root YE", "")
	if err != nil {
		t.Fatalf("CN-only match against cert with no O should verify, got: %v", err)
	}

	err = verifyIssuerChain(noO, "Root YE", "ISRG")
	if err == nil {
		t.Fatal("expected error when configured O is not present")
	}

	err = verifyIssuerChain(nil, "Root YE", "")
	if err == nil {
		t.Fatal("expected error for empty bundle")
	}

	err = verifyIssuerChain([]byte("not a pem"), "Root YE", "")
	if err == nil {
		t.Fatal("expected error for non-PEM input")
	}
}

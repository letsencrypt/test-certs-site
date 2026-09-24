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
	"errors"
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
// ACME-issued chain), and the leaf has the given CRL distribution points.
func makeChain(t *testing.T, intermediateIssuerCN string, intermediateIssuerO []string, leafCRLDPs []string) []byte {
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
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "leaf.example"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              []string{"leaf.example"},
		CRLDistributionPoints: leafCRLDPs,
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

// mustParseChain parses a PEM bundle from makeChain, failing the test on error.
func mustParseChain(t *testing.T, bundle []byte) []*x509.Certificate {
	t.Helper()

	chain, err := parseChain(bundle)
	if err != nil {
		t.Fatal(err)
	}

	return chain
}

func TestParseChain(t *testing.T) {
	t.Parallel()

	bundle := makeChain(t, "Root YE", nil, nil)

	chain, err := parseChain(bundle)
	if err != nil {
		t.Fatalf("valid chain should parse, got: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("expected 2 certificates, got %d", len(chain))
	}
	if chain[0].Subject.CommonName != "leaf.example" {
		t.Fatalf("expected leaf first, got CN %q", chain[0].Subject.CommonName)
	}
	if chain[1].Subject.CommonName != "Test Intermediate" {
		t.Fatalf("expected intermediate second, got CN %q", chain[1].Subject.CommonName)
	}

	block, _ := pem.Decode(bundle)

	_, err = parseChain(block.Bytes)
	if err == nil {
		t.Fatal("expected error for DER input, since lego returns a PEM bundle")
	}

	_, err = parseChain(nil)
	if err == nil {
		t.Fatal("expected error for empty bundle")
	}

	_, err = parseChain([]byte("not a pem"))
	if err == nil {
		t.Fatal("expected error for non-PEM input")
	}

	keyFirst := append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("junk")}), bundle...)

	_, err = parseChain(keyFirst)
	if err == nil {
		t.Fatal("expected error for non-certificate PEM block")
	}
}

func TestVerifyIssuerChain(t *testing.T) {
	t.Parallel()

	chain := mustParseChain(t, makeChain(t, "Root YE", []string{"ISRG"}, nil))

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

	noO := mustParseChain(t, makeChain(t, "Root YE", nil, nil))

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
		t.Fatal("expected error for empty chain")
	}
}

func TestVerifyCRLDistributionPoints(t *testing.T) {
	t.Parallel()

	withCRL := mustParseChain(t, makeChain(t, "Root YE", nil, []string{"http://crl.example/1.crl"}))

	err := verifyCRLDistributionPoints(withCRL)
	if err != nil {
		t.Fatalf("leaf with CRL distribution point should verify, got: %v", err)
	}

	noCRL := mustParseChain(t, makeChain(t, "Root YE", nil, nil))

	err = verifyCRLDistributionPoints(noCRL)
	if !errors.Is(err, errNoCRL) {
		t.Fatalf("leaf without CRL distribution points should be rejected with errNoCRL, got: %v", err)
	}

	err = verifyCRLDistributionPoints(nil)
	if err == nil {
		t.Fatal("expected error for empty chain")
	}
}

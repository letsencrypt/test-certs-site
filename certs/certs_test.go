package certs

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"
	"testing"

	"github.com/go-acme/lego/v4/challenge/tlsalpn01"

	"github.com/letsencrypt/test-certs-site/config"
	"github.com/letsencrypt/test-certs-site/storage"
)

func TestACME(t *testing.T) {
	t.Parallel()

	store, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	manager, err := New(t.Context(), &config.Config{
		Sites: nil,
	}, store)
	if err != nil {
		t.Fatal(err)
	}

	testDomain := "mytestsite.com"

	err = manager.Present(testDomain, "unused-token", "the-key-auth")
	if err != nil {
		t.Fatal(err)
	}

	clientHello := tls.ClientHelloInfo{
		ServerName:      testDomain,
		SupportedProtos: []string{tlsalpn01.ACMETLS1Protocol},
	}

	certificate, err := manager.GetCertificate(&clientHello)
	if err != nil {
		t.Fatalf("error getting certificate: %v", err)
	}

	if len(certificate.Leaf.DNSNames) != 1 {
		t.Fatalf("Expected one DNS name, got %q", certificate.Leaf.DNSNames)
	}
	if certificate.Leaf.DNSNames[0] != testDomain {
		t.Fatalf("Expected DNS name to be mytestsite.com, got %q", certificate.Leaf.DNSNames[0])
	}

	if slices.IndexFunc(certificate.Leaf.Extensions, func(ext pkix.Extension) bool {
		return ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31})
	}) == -1 {
		t.Fatalf("Didn't find ACME identifier")
	}

	err = manager.CleanUp(testDomain, "", "")
	if err != nil {
		t.Fatal(err)
	}

	_, err = manager.GetCertificate(&clientHello)
	if err == nil {
		t.Fatal("Expected error after cleanup, got none")
	}
}

package certs

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/letsencrypt/test-certs-site/config"
	"github.com/letsencrypt/test-certs-site/storage"
)

// TestExpiredHandling checks the four possible cases with expiry handling.
// A cert can either be expired or not, and it should be expired or not.
func TestExpiredHandling(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name            string
		NotAfter        time.Time
		shouldBeExpired bool
		shouldErr       bool
	}{
		{
			name:            "should-be-expired.is-expired",
			NotAfter:        time.Now().Add(-time.Hour),
			shouldBeExpired: true,
			shouldErr:       false,
		},
		{
			name:            "should-not-be-expired.is-expired",
			NotAfter:        time.Now().Add(-time.Hour),
			shouldBeExpired: false,
			shouldErr:       true,
		},
		{
			name:            "should-be-expired.not-expired",
			NotAfter:        time.Now().Add(time.Hour),
			shouldBeExpired: true,
			shouldErr:       true,
		},
		{
			name:            "should-not-be-expired.not-expired",
			NotAfter:        time.Now().Add(time.Hour),
			shouldBeExpired: false,
			shouldErr:       false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cm := CertManager{
				mu: sync.Mutex{},
				certs: map[string]*tls.Certificate{
					tc.name: {
						Leaf: &x509.Certificate{
							NotAfter: tc.NotAfter,
							DNSNames: []string{tc.name},
						},
					},
				},
				expired: map[string]bool{
					tc.name: tc.shouldBeExpired,
				},
			}

			c, err := cm.GetCertificate(&tls.ClientHelloInfo{
				ServerName: tc.name,
			})

			if tc.shouldErr && err == nil {
				t.Fatal("Expected error, got none")
			}

			if !tc.shouldErr {
				if err != nil {
					t.Fatalf("Didn't expect error, got %v", err)
				}

				if c == nil {
					t.Fatal("Expected non-nil Certificate")
				}

				if c.Leaf.DNSNames[0] != tc.name {
					t.Fatalf("Expected DNS name to be %q, got %q", tc.name, c.Leaf.DNSNames[0])
				}
			}
		})
	}
}

func TestACME(t *testing.T) {
	t.Parallel()

	store, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	manager, err := New(&config.Config{
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
		SupportedProtos: []string{"acme-tls/1"},
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

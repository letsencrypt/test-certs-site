package certs

import (
	"crypto/tls"
	"crypto/x509"
	"sync"
	"testing"
	"time"
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
				certs: map[string]*certificate{
					tc.name: {
						Certificate: &tls.Certificate{
							Leaf: &x509.Certificate{
								NotAfter: tc.NotAfter,
								DNSNames: []string{tc.name},
							},
						},
						shouldBeExpired: tc.shouldBeExpired,
					},
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

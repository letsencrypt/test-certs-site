package storage

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/letsencrypt/test-certs-site/config"
)

// TestStorage goes through the expected storage lifecycle.
func TestStorage(t *testing.T) {
	t.Parallel()

	storage, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	const domain = "interesting.salad"

	// Go through the lifecycle 3 times
	for i := range 3 {
		// Alternate key types to test both
		keyType := config.KeyTypeP256
		if i%2 == 1 {
			keyType = config.KeyTypeRSA2048
		}
		key, err := storage.StoreNextKey(domain, keyType)
		if err != nil {
			t.Fatal(err)
		}

		// Outside of tests, this would come from a CA:
		certs := testCert(t, domain, key)

		err = storage.StoreNextCert(domain, certs)
		if err != nil {
			t.Fatal(err)
		}

		_, err = storage.ReadNext(domain)
		if err != nil {
			t.Fatal(err)
		}

		// A real user of the storage package would validate the certs here.
		// Eg, checking if they're expired or revoked.

		_, err = storage.TakeNext(domain)
		if err != nil {
			t.Fatal(err)
		}

		current, err := storage.ReadCurrent(domain)
		if err != nil {
			t.Fatal(err)
		}

		if current.Leaf.DNSNames[0] != domain {
			t.Fatalf("Expected %s DNS SAN", domain)
		}
	}
}

// testCert returns a test self-signed cert for the given key.
func testCert(t *testing.T, domain string, key crypto.Signer) [][]byte {
	t.Helper()

	// Create a certificate template
	template := x509.Certificate{
		DNSNames: []string{domain},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	return [][]byte{certDER}
}

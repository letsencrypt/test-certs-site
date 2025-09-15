package config_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/letsencrypt/test-certs-site/config"
)

// TestLoadConfig checks test.json matches the expected Go structure.
func TestLoadConfig(t *testing.T) {
	t.Parallel()
	expected := config.Config{
		ListenAddr: "localhost:8443",

		Sites: []config.Site{
			{
				IssuerCN: "minica root ca 5345e6",
				KeyType:  "p256",
				Profile:  "shortlived",
				Domains: config.Domains{
					Valid:   "minica-valid.localhost",
					Expired: "minica-expired.localhost",
					Revoked: "minica-revoked.localhost",
				},
			},
			{
				IssuerCN: "Interesting Salad Root Greens",
				KeyType:  "rsa2048",
				Profile:  "tlsserver",
				Domains: config.Domains{
					Valid:   "valid.isrg.example.org",
					Expired: "expired.isrg.example.org",
					Revoked: "revoked.isrg.example.org",
				},
			},
		},

		ACME: config.ACME{
			Directory: "https://localhost:14000/dir",
			CACerts:   "/testdata/pebble.crt",
		},

		DataDir: "/testdata/data_dir/",
	}

	_, err := config.Load("non-existant.json")
	if err == nil {
		t.Fatal("LoadConfig should have returned an error on non-existant.json")
	}

	cfg, err := config.Load("test.json")
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(cfg, &expected) {
		t.Fatalf("got:\n%+q\nwant:\n%+q", cfg, &expected)
	}
}

func TestInvalidConfig(t *testing.T) {
	t.Parallel()
	_, err := config.Load("invalid.json")
	if err == nil {
		t.Fatal("LoadConfig should have returned an error on invalid json")
	}

	errStr := err.Error()

	for _, expected := range []string{
		"site 0 missing issuer CN",
		"site 0 duplicate domain: duplicate.domain",
		"site 1 duplicate domain: valid.salad",
		"site 0 unsupported key type: 3des",
		"site 1 unsupported key type: ",
	} {
		if !strings.Contains(errStr, expected) {
			t.Errorf("got error %q, want error containing %q", errStr, expected)
		}
	}
}

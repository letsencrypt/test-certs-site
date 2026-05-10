package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/test-certs-site/config"
)

// TestLoadConfig checks test.json matches the expected Go structure.
func TestLoadConfig(t *testing.T) {
	t.Parallel()
	expected := config.Config{
		ListenAddr: "localhost:8443",
		DebugAddr:  "localhost:9876",

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
			Directory:            "https://localhost:14000/dir",
			TermsOfServiceAgreed: true,
		},

		DataDir:          "testdata/data_dir/",
		HTMLTemplate:     "testdata/template.html",
		TextTemplate:     "testdata/template.txt",
		RevokeDelay:      config.Duration(time.Hour),
		CRLCheckInterval: config.Duration(time.Minute),
		IssueRetryWindow: config.Duration(12 * time.Hour),
	}

	_, err := config.Load("non-existant.json")
	if err == nil {
		t.Fatal("LoadConfig should have returned an error on non-existant.json")
	}

	cfg, err := config.Load("testdata/test.json")
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(cfg, &expected) {
		t.Fatalf("got:\n%v\nwant:\n%v", cfg, &expected)
	}
}

// TestRoundTrip ensures a Config can be marshaled and reloaded losslessly.
// configgen relies on this to write a config that test-certs-site can read.
func TestRoundTrip(t *testing.T) {
	t.Parallel()

	original := config.Config{
		ListenAddr: ":5001",
		DebugAddr:  ":9001",
		Sites: []config.Site{
			{
				IssuerCN: "Pebble Root CA abcdef",
				IssuerO:  "ISRG",
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

	body, err := json.Marshal(&original)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "roundtrip.json")
	err = os.WriteFile(path, body, 0o600)
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("loading round-tripped config: %v", err)
	}

	if !reflect.DeepEqual(loaded, &original) {
		t.Fatalf("round-trip mismatch:\ngot:  %#v\nwant: %#v", loaded, &original)
	}
}

func TestInvalidConfig(t *testing.T) {
	t.Parallel()
	_, err := config.Load("testdata/invalid.json")
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

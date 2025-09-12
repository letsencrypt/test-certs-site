package config_test

import (
	"reflect"
	"testing"

	"github.com/letsencrypt/test-certs-site/config"
)

// TestLoadConfig checks test.json matches the expected Go structure.
func TestLoadConfig(t *testing.T) {
	t.Parallel()
	expected := config.Config{
		Sites: map[string]config.Site{
			"valid.test": {
				Status:  "valid",
				RootCN:  "minica root ca 5345e6",
				KeyType: "p256",
				Profile: "shortlived",
				Files: config.Files{
					Cert: "/testdata/test-certs-site/valid.crt",
					Key:  "/testdata/test-certs-site/valid.key",
				},
				FilesNext: config.Files{
					Cert: "/testdata/test-certs-site/valid.next.crt",
					Key:  "/testdata/test-certs-site/valid.next.key",
				},
			},
			"expired.test": {
				Status:  "expired",
				RootCN:  "minica root ca 5345e6",
				KeyType: "p256",
				Profile: "shortlived",
				Files: config.Files{
					Cert: "/testdata/test-certs-site/expired.crt",
					Key:  "/testdata/test-certs-site/expired.key",
				},
				FilesNext: config.Files{
					Cert: "/testdata/test-certs-site/expired.next.crt",
					Key:  "/testdata/test-certs-site/expired.next.key",
				},
			},
			"revoked.test": {
				Status:  "revoked",
				RootCN:  "minica root ca 5345e6",
				KeyType: "p256",
				Profile: "shortlived",
				Files: config.Files{
					Cert: "/testdata/test-certs-site/revoked.crt",
					Key:  "/testdata/test-certs-site/revoked.key",
				},
				FilesNext: config.Files{
					Cert: "/testdata/test-certs-site/revoked.next.crt",
					Key:  "/testdata/test-certs-site/revoked.next.key",
				},
			},
		},

		ACME: config.ACME{
			Directory: "https://localhost:14000/dir",
			ClientKey: "/testdata/test-certs-site/acme.key",
			CACerts:   "/testdata/pebble.crt",
		},
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

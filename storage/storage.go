// Package storage handles keeping the files on disk.
package storage

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/letsencrypt/test-certs-site/config"
)

const (
	privateKeyFilename  = "private.pem"
	certificateFilename = "certificate.pem"
)

const (
	// dirPerms rwxr-xr-x for created directories. Writable only by user, but global r & x for debugging.
	dirPerms = 0o755

	// keyPerms rw------- for private keys. No permissions outside of user.
	keyPerms = 0o600

	// certPerms rw-r--r-- for cert files. Globally readable certs for debugging.
	certPerms = 0o644
)

// Storage of files for a domain.
type Storage struct {
	// mu prevents simultaneous writing of files, or reading while writing.
	mu  sync.Mutex
	dir string
}

// New storage handle.
func New(storageDir string) (*Storage, error) {
	return &Storage{dir: storageDir}, nil
}

// NewKey generates a new "next" key. If there was a next certificate, it will be removed.
func (s *Storage) NewKey(domain string, keyType string) (crypto.PrivateKey, error) {
	var key crypto.PrivateKey
	switch keyType {
	case config.KeyTypeP256:
		p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		key = p256Key
	case config.KeyTypeRSA2048:
		bits := 2048
		rsaKey, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, err
		}
		key = rsaKey
	default:
		// Should be unreachable due to config validation
		return nil, fmt.Errorf("unknown key type: %s", keyType)
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	path := s.pathFor(domain, true, privateKeyFilename)

	s.mu.Lock()
	defer s.mu.Unlock()

	err = os.MkdirAll(filepath.Dir(path), dirPerms)
	if err != nil {
		return nil, err
	}

	err = os.WriteFile(path, pemBytes, keyPerms)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// StoreNextCert stores the next certificate for the domain.
// Certificates should be a sequence of DER certificates.
func (s *Storage) StoreNextCert(domain string, certificates [][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	certPath := s.pathFor(domain, true, certificateFilename)
	cert, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, certPerms) //nolint:gosec // Arbitrary file is not a risk here
	if err != nil {
		return fmt.Errorf("could not open certificate file: %w", err)
	}
	defer cert.Close()

	for _, data := range certificates {
		err := pem.Encode(cert, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: data,
		})
		if err != nil {
			return fmt.Errorf("could not write certificate: %w", err)
		}
	}

	return nil
}

// TakeNext overwrites the current cert/key with the next cert/key.
func (s *Storage) TakeNext(domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := os.MkdirAll(s.pathFor(domain, false, ""), dirPerms)
	if err != nil {
		return err
	}

	for _, path := range []string{privateKeyFilename, certificateFilename} {
		nextPath := s.pathFor(domain, true, path)
		currPath := s.pathFor(domain, false, path)
		err := os.Rename(nextPath, currPath)
		if err != nil {
			return err
		}
	}

	return nil
}

// ReadCurrent the cert and key for this domain.
// Returns an error if the stored value couldn't be read or parsed.
func (s *Storage) ReadCurrent(domain string) (tls.Certificate, error) {
	return s.read(domain, false)
}

// ReadNext returns the next cert and key.
// Returns an error if the stored value couldn't be read or parsed.
func (s *Storage) ReadNext(domain string) (tls.Certificate, error) {
	return s.read(domain, true)
}

// read a keypair. Common logic for ReadCurrent and ReadNext.
func (s *Storage) read(domain string, next bool) (tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return tls.LoadX509KeyPair(s.pathFor(domain, next, certificateFilename), s.pathFor(domain, next, privateKeyFilename))
}

func versionDir(next bool) string {
	if next {
		return "next"
	}

	return "current"
}

func (s *Storage) pathFor(domain string, next bool, file string) string {
	return filepath.Join(s.dir, domain, versionDir(next), file)
}

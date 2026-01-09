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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	"github.com/letsencrypt/test-certs-site/config"
)

type version string

const (
	next    version = "next"
	current version = "current"
)

const (
	privateKeyFilename  = "private.pem"
	certificateFilename = "certificate.pem"
	acmeAccountFilename = "acme.json"
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

// account is the stored JSON for an ACME account.
type account struct {
	// ACME Account URI
	AccountURI string

	// P256 Private Key
	PrivateKey []byte
}

// ReadACME returns the stored ACME account for a given ACME server, identified by its directory URL.
// If an account was previously saved, the account URI and its private key are returned.
func (s *Storage) ReadACME(directory string) (string, *ecdsa.PrivateKey, error) {
	if directory == "" {
		return "", nil, errors.New("no ACME directory specified")
	}

	file, err := os.Open(s.pathFor(url.PathEscape(directory), current, acmeAccountFilename))
	if err != nil {
		return "", nil, err
	}

	defer file.Close()

	var acct account
	err = json.NewDecoder(file).Decode(&acct)
	if err != nil {
		return "", nil, fmt.Errorf("reading account json: %w", err)
	}

	key, err := x509.ParseECPrivateKey(acct.PrivateKey)
	if err != nil {
		return "", nil, fmt.Errorf("parsing account private key: %w", err)
	}

	return acct.AccountURI, key, nil
}

// StoreACME persists an account to disk, for later retrieval with ReadACME.
func (s *Storage) StoreACME(directory string, accountURI string, key *ecdsa.PrivateKey) error {
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}

	acct := account{
		AccountURI: accountURI,
		PrivateKey: keyBytes,
	}

	err = os.MkdirAll(s.pathFor(url.PathEscape(directory), current, ""), dirPerms)
	if err != nil {
		return err
	}

	path := s.pathFor(url.PathEscape(directory), current, acmeAccountFilename)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, certPerms) //nolint:gosec // Arbitrary file is not a risk here
	if err != nil {
		return err
	}

	return json.NewEncoder(file).Encode(acct)
}

// StoreNextKey generates a new "next" key, writing it to disk.
func (s *Storage) StoreNextKey(domain string, keyType string) (crypto.Signer, error) {
	var key crypto.Signer
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

	path := s.pathFor(domain, next, privateKeyFilename)

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
// Certificates should be a PEM sequence to write to disk.
func (s *Storage) StoreNextCert(domain string, certificates []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	certPath := s.pathFor(domain, next, certificateFilename)
	err := os.WriteFile(certPath, certificates, certPerms)
	if err != nil {
		return fmt.Errorf("could not write certificate: %w", err)
	}

	return nil
}

// TakeNext overwrites the current cert/key with the next cert/key, and returns the new current values.
func (s *Storage) TakeNext(domain string) (tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := os.MkdirAll(s.pathFor(domain, current, ""), dirPerms)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Read the next values we're about to make current.
	// Doing this before renaming ensures the key and certificate match.
	cert, err := s.read(domain, next)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("reading next certificate: %w", err)
	}

	for _, path := range []string{privateKeyFilename, certificateFilename} {
		nextPath := s.pathFor(domain, next, path)
		currPath := s.pathFor(domain, current, path)
		err := os.Rename(nextPath, currPath)
		if err != nil {
			return tls.Certificate{}, err
		}
	}

	return cert, nil
}

// ReadCurrent reads the current cert and key for this domain.
// Returns an error if the stored value couldn't be read or parsed.
func (s *Storage) ReadCurrent(domain string) (tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.read(domain, current)
}

// ReadNext reads the next cert and key for this domain.
// Returns an error if the stored value couldn't be read or parsed.
func (s *Storage) ReadNext(domain string) (tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.read(domain, next)
}

// read a cert and key. Common logic for ReadCurrent and ReadNext. Caller should hold mu.
func (s *Storage) read(domain string, ver version) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(s.pathFor(domain, ver, certificateFilename), s.pathFor(domain, ver, privateKeyFilename))
}

func (s *Storage) pathFor(domain string, ver version, file string) string {
	return filepath.Join(s.dir, domain, string(ver), file)
}

package authn

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrEmptyTrustBundle indicates that the trust bundle is empty.
var ErrEmptyTrustBundle = errors.New("empty trust bundle")

// LoadTrustBundle reads the PEM file at path and returns a pool of trusted roots.
func LoadTrustBundle(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("load trust bundle [%s]: %w", path, err)
	}

	pool := x509.NewCertPool()

	ok := pool.AppendCertsFromPEM(pem)
	if !ok {
		// false == zero certs parsed
		// Note: AppendCertsFromPEM silently skips individual malformed blocks
		return nil, fmt.Errorf("load trust bundle [%s]: %w", path, ErrEmptyTrustBundle)
	}

	return pool, nil
}

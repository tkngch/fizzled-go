package authn

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tkngch/fizzled-go/internal/authn/x509svid"
)

const (
	// certificatePEMType is the PEM block type a trust bundle is made of.
	certificatePEMType = "CERTIFICATE"

	// pemBeginMarker opens a PEM block. A trust bundle is read as a sequence of
	// them and nothing else.
	pemBeginMarker = "-----BEGIN "
)

// loadedBundle is a parsed trust bundle: the roots a chain anchors to, and the
// earliest expiry among them. The roots are carried as certificates rather than
// as an x509.CertPool because a pool can hold more than the certificates put
// into it, and x509svid.NewVerifier builds its own for that reason.
type loadedBundle struct {
	roots          []*x509.Certificate
	earliestExpiry time.Time
}

// loadTrustBundle reads the PEM file at path and returns a pool of trusted
// roots.
//
// The file is read block by block rather than handed to
// x509.CertPool.AppendCertsFromPEM, which silently skips every block it cannot
// use and reports only whether anything at all was added. A bundle that is
// malformed, or that carries a certificate this app must not anchor to, is a
// misconfiguration the operator should hear about at start-up.
func loadTrustBundle(path string) (loadedBundle, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return loadedBundle{}, fmt.Errorf("trust bundle [%s]: %w", path, err)
	}

	loaded, err := parseTrustBundle(raw)
	if err != nil {
		return loadedBundle{}, fmt.Errorf("trust bundle [%s]: %w", path, err)
	}

	return loaded, nil
}

// parseTrustBundle reads raw as a sequence of PEM blocks and nothing else. It
// is separate from loadTrustBundle only to keep the reading of the file apart
// from the reading of its contents: every way this can fail names the same
// path, and naming it once is what leaves the checks below legible.
func parseTrustBundle(raw []byte) (loadedBundle, error) {
	var (
		roots          []*x509.Certificate
		earliestExpiry time.Time
	)

	trimmed := bytes.TrimSpace(raw)
	rest := trimmed

	// x509.CertPool keeps one copy of a certificate added twice, so a duplicate
	// would leave the pool smaller than the count reported at start-up.
	seen := make(map[string]bool)

	for len(rest) > 0 {
		certificate, remainder, err := decodeBlock(rest, len(roots)+1)
		if err != nil {
			return loadedBundle{}, fmt.Errorf("parse trust bundle: %w", err)
		}

		if seen[string(certificate.Raw)] {
			return loadedBundle{}, fmt.Errorf(
				"parse trust bundle: block %d [serial %s]: %w",
				len(roots)+1, serialNumber(certificate), ErrBundleDuplicateCertificate,
			)
		}

		seen[string(certificate.Raw)] = true

		roots = append(roots, certificate)

		if earliestExpiry.IsZero() || certificate.NotAfter.Before(earliestExpiry) {
			earliestExpiry = certificate.NotAfter
		}

		rest = bytes.TrimSpace(remainder)
	}

	if len(roots) == 0 {
		return loadedBundle{}, fmt.Errorf("parse trust bundle: %w", ErrEmptyTrustBundle)
	}

	// Ensure no block was dropped, by comparing the number of certificates
	// added to the pool against the number of blocks in the file.
	//
	// In case when any block was dropped, we cannot infer which block was
	// dropped here, so the error reports the counts instead.
	markers := beginMarkers(trimmed)
	if len(roots) != markers {
		return loadedBundle{}, fmt.Errorf(
			"parse trust bundle: read %d of %d blocks: %w",
			len(roots),
			markers,
			ErrBundleBlockDropped,
		)
	}

	bundle := loadedBundle{
		roots:          roots,
		earliestExpiry: earliestExpiry,
	}

	return bundle, nil
}

// decodeBlock reads the PEM block at the head of rest as a trust-bundle
// certificate, and returns it with whatever follows the block.
//
// A block begins where the one before it ended, so anything in between is data
// pem.Decode would skip over. ordinal counts the blocks the file sets out to
// carry, so an error names the block an operator has to go and look at rather
// than the byte offset of the damage.
func decodeBlock(rest []byte, ordinal int) (*x509.Certificate, []byte, error) {
	if !bytes.HasPrefix(rest, []byte(pemBeginMarker)) {
		return nil, nil, fmt.Errorf(
			"decode block [%d] before: %w",
			ordinal,
			ErrBundleUnexpectedData,
		)
	}

	block, remainder := pem.Decode(rest)
	if block == nil {
		return nil, nil, fmt.Errorf(
			"decode block [%d] unreadable: %w",
			ordinal,
			ErrBundleBlockDropped,
		)
	}

	certificate, err := bundleCertificate(block)
	if err != nil {
		return nil, nil, fmt.Errorf("decode block [%d]: %w", ordinal, err)
	}

	return certificate, remainder, nil
}

// beginMarkers is the number of blocks the file carries, indicated by
// the PEM begin marker.
func beginMarkers(trimmed []byte) int {
	// Note: A marker cannot appear inside a block: the base64 a certificate is
	// written in has no dash in its alphabet.
	count := bytes.Count(trimmed, []byte("\n"+pemBeginMarker))

	if bytes.HasPrefix(trimmed, []byte(pemBeginMarker)) {
		count++
	}

	return count
}

// bundleCertificate parses one PEM block of a trust bundle into the CA
// certificate. The certificate is validated with
// x509svid.ValidateSigningCertificate.
func bundleCertificate(block *pem.Block) (*x509.Certificate, error) {
	if block.Type != certificatePEMType {
		return nil, fmt.Errorf(
			"bundle certificate: pem block [%s]: %w",
			block.Type,
			ErrBundleNotCertificate,
		)
	}

	if len(block.Headers) > 0 {
		return nil, fmt.Errorf(
			"bundle certificate: pem block [%s]: %w",
			block.Type,
			ErrBundleBlockHasHeaders,
		)
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("bundle certificate: %w", err)
	}

	spiffeID, hasSPIFFEID, err := x509svid.ValidateSigningCertificate(certificate)
	if err != nil {
		return nil, fmt.Errorf("bundle certificate [serial %s]: %w", serialNumber(certificate), err)
	}

	// A CA is not required to carry a URI SAN at all; one that does must carry
	// it in this trust domain.
	if hasSPIFFEID && spiffeID.TrustDomain() != TrustDomain {
		return nil, fmt.Errorf("bundle certificate uri [%s]: %w", spiffeID, ErrWrongTrustDomain)
	}

	return certificate, nil
}

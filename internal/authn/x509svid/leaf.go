package x509svid

import (
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/tkngch/fizzled-go/internal/authn/spiffeid"
)

// Leaf represents X509 leaf-certificate with SVID information.
type Leaf struct {
	spiffeID    spiffeid.ID
	certificate *x509.Certificate
}

var (
	// ErrNoCertificate indicates that no certificate is provided.
	ErrNoCertificate = errors.New("no certificate")

	// ErrLeafCertIsNotCA indicates that a leaf certificate has true in cA
	// field.
	ErrLeafCertIsNotCA = errors.New("leaf certificate is not CA")

	// ErrLeafCertHasKeyCertSign indicates that a leaf certificate sets
	// keyCertSign.
	ErrLeafCertHasKeyCertSign = errors.New("leaf certificate has keyCertSign")

	// ErrLeafCertHasCrlSign indicates that a leaf certificate sets cRLSign.
	ErrLeafCertHasCrlSign = errors.New("leaf certificate has cRLSign")

	// ErrLeafCertMissingDigitalSignature indicates that a leaf certificate is
	// missing digitalSignature.
	ErrLeafCertMissingDigitalSignature = errors.New("leaf certificate is missing digitalSignature")

	// ErrLeafSpiffeMissingPath indicates that SPIFFE-ID in the leaf certificate
	// has only a root path component.
	ErrLeafSpiffeMissingPath = errors.New("leaf spiffe-ID is missing path components")

	// ErrCertHasNoURI indicates that a certificate has no URI SAN and thus that
	// SPIFFE ID cannot extracted.
	ErrCertHasNoURI = errors.New("leaf certificate has no URI")

	// ErrCertHasMultiplURIs indicates that a certificate has more than one URI
	// SANs.
	ErrCertHasMultiplURIs = errors.New("leaf certificate has multiple URIs")

	// ErrSigningCertIsNotCA indicates that an intermediate or a root
	// certificate does not have true in cA field.
	ErrSigningCertIsNotCA = errors.New("signing certificate is not CA")

	// ErrSigningCertMissingKeyCertSign indicates that an intermediate or a root
	// certificate is missing keyCertSign.
	ErrSigningCertMissingKeyCertSign = errors.New(
		"signing certificate is missing keyCertSign",
	)

	// ErrSigningSpiffeHasPath indicates that an intermediate or a root
	// certificate has an URI SAN with a non-root path component.
	ErrSigningSpiffeHasPath = errors.New("signing certificate has path")

	// ErrSigningSpiffeInDifferentTrustDomainThanLeaf indicates that an
	// intermediate or a root certificate is in a different trust-domain than
	// the leaf certificate.
	ErrSigningSpiffeInDifferentTrustDomainThanLeaf = errors.New(
		"signing spiffe-ID is in a different trust-domain than the leaf spiffe-ID",
	)
)

// NewLeaf builds an ID from a parsed chain of certificates. The first entry in the
// certificates is expected to be a leaf.
func NewLeaf(certificates []*x509.Certificate) (Leaf, error) {
	if len(certificates) == 0 {
		return Leaf{}, fmt.Errorf("x509svid new: %w", ErrNoCertificate)
	}

	leafCertificate := certificates[0]

	err := validatedLeafCertificate(leafCertificate)
	if err != nil {
		return Leaf{}, fmt.Errorf("x509svid new: %w", err)
	}

	leafSpiffeID, err := validatedLeafSpiffeID(leafCertificate)
	if err != nil {
		return Leaf{}, fmt.Errorf("x509svid new: %w", err)
	}

	for _, signingCertificate := range certificates[1:] {
		err = validateSigningCertificate(signingCertificate, leafSpiffeID)
		if err != nil {
			return Leaf{}, fmt.Errorf("x509svid new: %w", err)
		}
	}

	return Leaf{spiffeID: leafSpiffeID, certificate: leafCertificate}, nil
}

// ID is the SPIFFE ID.
func (l Leaf) ID() spiffeid.ID {
	return l.spiffeID
}

// Certificate is X509 certificate.
func (l Leaf) Certificate() *x509.Certificate {
	return l.certificate
}

// validatedSpiffeID compares the leaf certificate against the standard:
// https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md
func validatedLeafCertificate(leafCertificate *x509.Certificate) error {
	if leafCertificate.IsCA {
		return fmt.Errorf("verified spiffe-ID: %w", ErrLeafCertIsNotCA)
	}

	if leafCertificate.KeyUsage&x509.KeyUsageCertSign > 0 {
		return fmt.Errorf("verified spiffe-ID: %w", ErrLeafCertHasKeyCertSign)
	}

	if leafCertificate.KeyUsage&x509.KeyUsageCRLSign > 0 {
		return fmt.Errorf("verified spiffe-ID: %w", ErrLeafCertHasCrlSign)
	}

	if leafCertificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("verified spiffe-ID: %w", ErrLeafCertMissingDigitalSignature)
	}

	// TO-DO: verify that Extended Key Usage (EKU) is included in the leaf, and
	// that id-kp-serverAuth and id-kp-clientAuth are set.

	return nil
}

func validatedLeafSpiffeID(leafCertificate *x509.Certificate) (spiffeid.ID, error) {
	leafSpiffeID, err := spiffeID(leafCertificate)
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("validated leaf spiffeID: %w", err)
	}

	if len(leafSpiffeID.PathComponents()) == 0 {
		return spiffeid.ID{}, fmt.Errorf("validated leaf spiffeID: %w", ErrLeafSpiffeMissingPath)
	}

	return leafSpiffeID, nil
}

// validateSigningCertificate compares the signing certificate against the standard:
// https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md
func validateSigningCertificate(signingCertificate *x509.Certificate, leaf spiffeid.ID) error {
	if !signingCertificate.IsCA {
		return fmt.Errorf("validate signing-certificate: %w", ErrSigningCertIsNotCA)
	}

	if signingCertificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("validate signing-certificate: %w", ErrSigningCertMissingKeyCertSign)
	}

	if len(signingCertificate.URIs) == 0 {
		return nil
	}

	intermediate, err := spiffeID(signingCertificate)
	if err != nil {
		return fmt.Errorf("validate csigning-ertificate: %w", err)
	}

	if leaf.TrustDomain() != intermediate.TrustDomain() {
		return fmt.Errorf(
			"validate csigning-ertificate: %w",
			ErrSigningSpiffeInDifferentTrustDomainThanLeaf,
		)
	}

	if len(intermediate.PathComponents()) > 0 {
		return fmt.Errorf("validate csigning-ertificate: %w", ErrSigningSpiffeHasPath)
	}

	return nil
}

func spiffeID(certificate *x509.Certificate) (spiffeid.ID, error) {
	if len(certificate.URIs) == 0 {
		return spiffeid.ID{}, fmt.Errorf("spiffeID: %w", ErrCertHasNoURI)
	}

	if len(certificate.URIs) > 1 {
		return spiffeid.ID{}, fmt.Errorf("spiffeID: %w", ErrCertHasMultiplURIs)
	}

	spiffeID, err := spiffeid.New(certificate.URIs[0].String())
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("spiffeID: %w", err)
	}

	return spiffeID, nil
}

package x509svid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"slices"
	"time"

	"github.com/tkngch/fizzled-go/internal/authn/spiffeid"
)

// Leaf represents X509 leaf-certificate with SVID information.
type Leaf struct {
	spiffeID    spiffeid.ID
	certificate *x509.Certificate
}

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

	intermediateCertificatePool := x509.NewCertPool()
	rootCertificatePool := x509.NewCertPool()

	for idx, signingCertificate := range certificates[1:] {
		err = validateSigningCertificate(signingCertificate, leafSpiffeID)
		if err != nil {
			return Leaf{}, fmt.Errorf("x509svid new: %w", err)
		}

		if idx == len(certificates)-2 {
			// Add the last entry to the root certificate-pool
			rootCertificatePool.AddCert(signingCertificate)
		} else {
			// Add the rest of entries to the intermediate certificate-pool
			intermediateCertificatePool.AddCert(signingCertificate)
		}
	}

	_, err = leafCertificate.Verify(
		x509.VerifyOptions{
			DNSName:       "", // Set this to empty to skip hostname verification.
			Intermediates: intermediateCertificatePool,
			Roots:         rootCertificatePool,
			CurrentTime:   time.Now(),
			KeyUsages: []x509.ExtKeyUsage{
				x509.ExtKeyUsageAny,
			}, // Accept any key usage. Validate key usage elsewhere.
			MaxConstraintComparisions: 0,            // Use the default value.
			CertificatePolicies:       []x509.OID{}, // Accept any valid policy.
		},
	)
	if err != nil {
		return Leaf{}, fmt.Errorf("x509svid new: %w", err)
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
		return fmt.Errorf("validated leaf certificate: %w", ErrLeafCertIsCA)
	}

	if leafCertificate.KeyUsage&x509.KeyUsageCertSign > 0 {
		return fmt.Errorf("validated leaf certificate: %w", ErrLeafCertHasKeyCertSign)
	}

	if leafCertificate.KeyUsage&x509.KeyUsageCRLSign > 0 {
		return fmt.Errorf("validated leaf certificate: %w", ErrLeafCertHasCrlSign)
	}

	if leafCertificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("validated leaf certificate: %w", ErrLeafCertMissingDigitalSignature)
	}

	if !slices.Contains(leafCertificate.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return fmt.Errorf("validated leaf certificate: %w", ErrLeafCertMissingServerAuth)
	}

	if !slices.Contains(leafCertificate.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return fmt.Errorf("validated leaf certificate: %w", ErrLeafCertMissingClientAuth)
	}

	publicKey, ok := leafCertificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("validated leaf certificate: %w", ErrLeafPublicKeyNotECDSA)
	}

	if publicKey.Curve != elliptic.P256() {
		return fmt.Errorf("validated leaf certificate: %w", ErrLeafPublicKeyNotP256)
	}

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
		return fmt.Errorf("validate signing-certificate: %w", err)
	}

	if leaf.TrustDomain() != intermediate.TrustDomain() {
		return fmt.Errorf(
			"validate signing-certificate: %w",
			ErrSigningSpiffeInDifferentTrustDomainThanLeaf,
		)
	}

	if len(intermediate.PathComponents()) > 0 {
		return fmt.Errorf("validate signing-certificate: %w", ErrSigningSpiffeHasPath)
	}

	return nil
}

func spiffeID(certificate *x509.Certificate) (spiffeid.ID, error) {
	if len(certificate.URIs) == 0 {
		return spiffeid.ID{}, fmt.Errorf("spiffeID: %w", ErrCertHasNoURI)
	}

	if len(certificate.URIs) > 1 {
		return spiffeid.ID{}, fmt.Errorf("spiffeID: %w", ErrCertHasMultipleURIs)
	}

	spiffeID, err := spiffeid.New(certificate.URIs[0].String())
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("spiffeID: %w", err)
	}

	return spiffeID, nil
}

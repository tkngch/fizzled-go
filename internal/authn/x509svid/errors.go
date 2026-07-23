package x509svid

import "errors"

var (
	// ErrNoCertificate indicates that no certificate is provided.
	ErrNoCertificate = errors.New("no certificate")

	// ErrLeafCertIsCA indicates that a leaf certificate has true in cA field.
	ErrLeafCertIsCA = errors.New("leaf certificate is CA")

	// ErrLeafCertHasKeyCertSign indicates that a leaf certificate sets
	// keyCertSign.
	ErrLeafCertHasKeyCertSign = errors.New("leaf certificate has keyCertSign")

	// ErrLeafCertHasCrlSign indicates that a leaf certificate sets cRLSign.
	ErrLeafCertHasCrlSign = errors.New("leaf certificate has cRLSign")

	// ErrLeafCertMissingDigitalSignature indicates that a leaf certificate is
	// missing digitalSignature.
	ErrLeafCertMissingDigitalSignature = errors.New("leaf certificate is missing digitalSignature")

	// ErrLeafCertMissingServerAuth indicates that `id-kp-serverAuth` is not set
	// in extended key usage extension.
	ErrLeafCertMissingServerAuth = errors.New("leaf certificate is missing server-auth EKU")

	// ErrLeafCertMissingClientAuth indicates that `id-kp-clientAuth` is not set
	// in extended key usage extension.
	ErrLeafCertMissingClientAuth = errors.New("leaf certificate is missing client-auth EKU")

	// ErrLeafSpiffeMissingPath indicates that SPIFFE-ID in the leaf certificate
	// has only a root path component.
	ErrLeafSpiffeMissingPath = errors.New("leaf spiffe-ID is missing path components")

	// ErrLeafPublicKeyNotECDSA indicates that the public-key is not ECDSA.
	ErrLeafPublicKeyNotECDSA = errors.New("leaf public-key is not ECDSA")

	// ErrLeafPublicKeyNotP256 indicates that the public-key is not on the P256 curve.
	ErrLeafPublicKeyNotP256 = errors.New("leaf public-key is not on P256 curve")

	// ErrCertHasNoURI indicates that a certificate has no URI SAN and thus that
	// SPIFFE ID cannot extracted.
	ErrCertHasNoURI = errors.New("leaf certificate has no URI")

	// ErrCertHasMultipleURIs indicates that a certificate has more than one URI
	// SANs.
	ErrCertHasMultipleURIs = errors.New("leaf certificate has multiple URIs")

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

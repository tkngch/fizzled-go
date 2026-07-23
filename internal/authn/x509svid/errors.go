package x509svid

import "errors"

var (
	// ErrNoCertificate indicates that no certificate is provided.
	ErrNoCertificate = errors.New("no certificate")

	// ErrNoTrustBundle indicates that a Verifier carries no trust bundle, and
	// so that there is nothing for a chain to anchor to.
	ErrNoTrustBundle = errors.New("no trust bundle")

	// ErrLeafCertIsCA indicates that a leaf certificate has true in the cA
	// field.
	ErrLeafCertIsCA = errors.New("leaf certificate is CA")

	// ErrLeafCertHasKeyCertSign indicates that a leaf certificate sets
	// keyCertSign.
	ErrLeafCertHasKeyCertSign = errors.New("leaf certificate has keyCertSign")

	// ErrLeafCertHasCRLSign indicates that a leaf certificate sets cRLSign.
	ErrLeafCertHasCRLSign = errors.New("leaf certificate has cRLSign")

	// ErrLeafCertMissingDigitalSignature indicates that a leaf certificate is
	// missing digitalSignature.
	ErrLeafCertMissingDigitalSignature = errors.New("leaf certificate is missing digitalSignature")

	// ErrLeafSPIFFEMissingPath indicates that the SPIFFE ID in the leaf
	// certificate has no path component.
	ErrLeafSPIFFEMissingPath = errors.New("leaf spiffe-ID is missing path components")

	// ErrCertHasNoURI indicates that a certificate has no URI SAN and thus that
	// a SPIFFE ID cannot be extracted.
	ErrCertHasNoURI = errors.New("certificate has no URI")

	// ErrCertHasMultipleURIs indicates that a certificate has more than one URI
	// SAN.
	ErrCertHasMultipleURIs = errors.New("certificate has multiple URIs")

	// ErrSigningCertIsNotCA indicates that an intermediate or a root
	// certificate does not have true in the cA field.
	ErrSigningCertIsNotCA = errors.New("signing certificate is not CA")

	// ErrSigningCertMissingKeyCertSign indicates that an intermediate or a root
	// certificate is missing keyCertSign.
	ErrSigningCertMissingKeyCertSign = errors.New(
		"signing certificate is missing keyCertSign",
	)

	// ErrSigningSPIFFEHasPath indicates that an intermediate or a root
	// certificate has a URI SAN with a non-root path component.
	ErrSigningSPIFFEHasPath = errors.New("signing certificate has path")

	// ErrSigningSPIFFEInDifferentTrustDomainThanLeaf indicates that an
	// intermediate or a root certificate is in a different trust-domain than
	// the leaf certificate.
	ErrSigningSPIFFEInDifferentTrustDomainThanLeaf = errors.New(
		"signing spiffe-ID is in a different trust-domain than the leaf spiffe-ID",
	)

	// ErrNegativeSkew indicates that the clock-skew tolerance argument has a
	// negative value, which suggests misconfiguration.
	ErrNegativeSkew = errors.New("negative clock-skew tolerance")
)

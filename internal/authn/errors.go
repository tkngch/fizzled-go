package authn

import "errors"

var (
	// ErrEmptyTrustBundle indicates that the trust bundle is empty.
	ErrEmptyTrustBundle = errors.New("empty trust bundle")

	// ErrBundleNotCertificate indicates that the trust bundle carries a PEM
	// block that is not a certificate.
	ErrBundleNotCertificate = errors.New("trust bundle block is not a certificate")

	// ErrBundleBlockHasHeaders indicates that the trust bundle carries a PEM
	// block with RFC-1421 headers. A certificate is written without them, and
	// x509.CertPool.AppendCertsFromPEM — the parser every other tool that reads
	// this file reaches for — skips a block that has them. A root annotated
	// this way would therefore anchor chains here and nowhere else.
	ErrBundleBlockHasHeaders = errors.New("trust bundle block has PEM headers")

	// ErrBundleUnexpectedData indicates that the trust bundle carries bytes
	// that are not part of a PEM block. A certificate the operator wrote into
	// the bundle may be missing from it.
	ErrBundleUnexpectedData = errors.New("trust bundle carries data outside a PEM block")

	// ErrBundleBlockDropped indicates that the trust bundle carries a PEM block
	// that could not be read as one. The block is therefore missing from the
	// pool.
	ErrBundleBlockDropped = errors.New("trust bundle block could not be read")

	// ErrBundleDuplicateCertificate indicates that the trust bundle carries the
	// same certificate more than once. x509.CertPool keeps one copy, so the
	// bundle would anchor to fewer roots than it appears to name.
	ErrBundleDuplicateCertificate = errors.New("trust bundle carries a duplicate certificate")

	// ErrWrongTrustDomain indicates that the trust-domain of a SPIFFE ID is not
	// "fizzled.internal".
	ErrWrongTrustDomain = errors.New("wrong trust domain")

	// ErrUnexpectedIdentity indicates that the path components in a SPIFFE ID
	// do not match the server or the client components.
	ErrUnexpectedIdentity = errors.New("unexpected identity")

	// ErrInvalidAgentID indicates that an identifier is blank or carries a
	// character that it must not.
	ErrInvalidAgentID = errors.New("invalid agent id")

	// ErrMissingServerAuth indicates that `id-kp-serverAuth` is not set in the
	// extended key usage extension.
	ErrMissingServerAuth = errors.New("certificate is missing server-auth EKU")

	// ErrMissingClientAuth indicates that `id-kp-clientAuth` is not set in the
	// extended key usage extension.
	ErrMissingClientAuth = errors.New("certificate is missing client-auth EKU")

	// ErrKeyNotECDSA indicates that the public key is not ECDSA.
	ErrKeyNotECDSA = errors.New("public key is not ECDSA")

	// ErrKeyNotP256 indicates that the public key is not on the P-256 curve.
	ErrKeyNotP256 = errors.New("public key is not on the P-256 curve")
)

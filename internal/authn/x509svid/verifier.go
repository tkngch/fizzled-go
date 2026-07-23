package x509svid

import (
	"crypto/x509"
	"fmt"
	"slices"
	"time"

	"github.com/tkngch/fizzled-go/internal/authn/spiffeid"
)

// Verifier checks peer certificate chains against a trust bundle. It binds the
// bundle and the clock-skew tolerance once, so callers do not thread them
// through every call. A Verifier is immutable after construction and safe for
// concurrent use.
type Verifier struct {
	bundle *x509.CertPool
	skew   time.Duration
}

// NewVerifier builds a Verifier anchored to roots.
//
// The pool is built here rather than taken from the caller, so that what the
// Verifier trusts is the roots it was handed and nothing else. roots may be
// empty, which builds a Verifier that anchors nothing and so rejects every
// chain. Whether an empty bundle is a misconfiguration is a question about a
// deployment rather than about the standard, so it is the caller's to ask. No
// entry may be nil: crypto/x509 panics on one rather than reporting it.
//
// skew is the tolerance applied to the leaf's notBefore/notAfter, so that minor
// clock differences between peers do not spuriously reject an otherwise-valid
// certificate. It is a policy value owned by the caller; pass zero to require a
// certificate that is valid at the current instant. skew must not be negative,
// which is rejected to prevent potential exploitation.
func NewVerifier(roots []*x509.Certificate, skew time.Duration) (*Verifier, error) {
	if skew < 0 {
		return nil, fmt.Errorf("new verifier: %w", ErrNegativeSkew)
	}

	index := slices.Index(roots, nil)
	if index >= 0 {
		return nil, fmt.Errorf("new verifier: root [%d]: %w", index, ErrNoCertificate)
	}

	bundle := x509.NewCertPool()
	for _, root := range roots {
		bundle.AddCert(root)
	}

	return &Verifier{bundle: bundle, skew: skew}, nil
}

// Verify cryptographically verifies a chain against the trust bundle and then
// validates it against the SPIFFE X509-SVID standard. The first entry in
// certificates is expected to be the leaf.
//
// Verify asserts only what the standard requires. Any policy on top of it, such
// as a required key algorithm or extended key usage, belongs to the caller and
// is applied to Leaf.Certificate.
//
// The signing-certificate checks are applied to the chain the peer presented,
// not to the one crypto/x509 built from it. That is stricter in one direction: a
// certificate the peer attaches without having signed any of the chain is
// rejected rather than ignored. It is silent in the other: a root the peer does
// not present is never seen here, because it comes from the trust bundle, and
// whoever assembles the bundle is the one who vouches for it.
func (v *Verifier) Verify(certificates []*x509.Certificate) (Leaf, error) {
	// The only emptiness check: both steps below index the leaf directly and
	// rely on this one.
	if len(certificates) == 0 {
		return Leaf{}, fmt.Errorf("verify: %w", ErrNoCertificate)
	}

	// crypto/x509 panics on a nil certificate, so the chain is turned away here
	// before any of it is read.
	index := slices.Index(certificates, nil)
	if index >= 0 {
		return Leaf{}, fmt.Errorf("verify: nil certificate [%d]: %w", index, ErrNoCertificate)
	}

	err := v.verifyChain(certificates)
	if err != nil {
		return Leaf{}, fmt.Errorf("verify: %w", err)
	}

	leaf, err := validateChain(certificates)
	if err != nil {
		return Leaf{}, fmt.Errorf("verify: %w", err)
	}

	return leaf, nil
}

// verifyChain cryptographically verifies a peer's certificate chain against the
// trust bundle. It anchors the chain to the bundle, applying the skew tolerance
// to the leaf's validity window and skipping hostname verification. It does NOT
// assert an identity. certificates must not be empty.
func (v *Verifier) verifyChain(certificates []*x509.Certificate) error {
	// NewVerifier builds a pool, but a Verifier can be directly constructed
	// with a nil pool. Ensure that x509.VerifyOptions does not read a nil Roots
	// and does not use the host's system roots.
	if v.bundle == nil {
		return fmt.Errorf("verify chain: %w", ErrNoTrustBundle)
	}

	leaf := certificates[0]

	intermediates := x509.NewCertPool()
	for _, intermediate := range certificates[1:] {
		intermediates.AddCert(intermediate)
	}

	_, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       "", // hostname verification is skipped.
		Roots:         v.bundle,
		Intermediates: intermediates,
		CurrentTime:   clampToValidity(time.Now(), leaf.NotBefore, leaf.NotAfter, v.skew),
		// The extended key usage is deliberately unconstrained here. The
		// X509-SVID structural checks run in validateChain, and an EKU policy
		// on top of the standard belongs to the caller.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		// Zero here asks for the standard library's default.
		MaxConstraintComparisions: 0,
		CertificatePolicies:       []x509.OID{},
	})
	if err != nil {
		return fmt.Errorf("verify chain [serial %x]: %w", leaf.SerialNumber, err)
	}

	return nil
}

// clampToValidity clamps now into [notBefore, notAfter] when now is within skew
// of a boundary; beyond skew it returns now unchanged and lets Verify reject.
//
// The window is the leaf's, but the clamped instant is the one the whole chain
// is checked at, so a signing certificate is judged up to skew away from now as
// well. The shift is bounded by skew, so a certificate that fell outside its own
// window by more than that is still rejected.
func clampToValidity(now, notBefore, notAfter time.Time, skew time.Duration) time.Time {
	switch {
	case now.Before(notBefore) && !now.Before(notBefore.Add(-skew)):
		return notBefore
	case now.After(notAfter) && !now.After(notAfter.Add(skew)):
		return notAfter
	default:
		return now
	}
}

// validateChain checks a parsed chain against the SPIFFE X509-SVID standard and
// returns the leaf it describes. The first entry in certificates is the leaf,
// and certificates must not be empty.
func validateChain(certificates []*x509.Certificate) (Leaf, error) {
	leafCertificate := certificates[0]

	err := validateLeafCertificate(leafCertificate)
	if err != nil {
		return Leaf{}, err
	}

	leafID, err := leafSPIFFEID(leafCertificate)
	if err != nil {
		return Leaf{}, err
	}

	for _, signingCertificate := range certificates[1:] {
		err = validateSigningCertificateForLeaf(signingCertificate, leafID)
		if err != nil {
			return Leaf{}, err
		}
	}

	return Leaf{spiffeID: leafID, certificate: leafCertificate}, nil
}

// validateLeafCertificate compares the leaf certificate against the standard:
// https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md
//
// It asserts what the standard requires and no more. The key algorithm and the
// extended key usage are issuance policy, so they are left to the caller.
func validateLeafCertificate(leafCertificate *x509.Certificate) error {
	if leafCertificate.IsCA {
		return fmt.Errorf("validate leaf-certificate: %w", ErrLeafCertIsCA)
	}

	if leafCertificate.KeyUsage&x509.KeyUsageCertSign != 0 {
		return fmt.Errorf("validate leaf-certificate: %w", ErrLeafCertHasKeyCertSign)
	}

	if leafCertificate.KeyUsage&x509.KeyUsageCRLSign != 0 {
		return fmt.Errorf("validate leaf-certificate: %w", ErrLeafCertHasCRLSign)
	}

	if leafCertificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("validate leaf-certificate: %w", ErrLeafCertMissingDigitalSignature)
	}

	return nil
}

// leafSPIFFEID is the SPIFFE ID in the leaf's URI SAN, checked against the
// X509-SVID rule that a leaf carries a path.
func leafSPIFFEID(leafCertificate *x509.Certificate) (spiffeid.ID, error) {
	spiffeID, err := newSPIFFEID(leafCertificate)
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("validate leaf-spiffeid: %w", err)
	}

	if spiffeID.Path() == "" {
		return spiffeid.ID{}, fmt.Errorf("validate leaf-spiffeid: %w", ErrLeafSPIFFEMissingPath)
	}

	return spiffeID, nil
}

// ValidateSigningCertificate compares a certificate that signs an X509-SVID
// against the standard, and returns the SPIFFE ID it carries:
// https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md
//
// A signing certificate is not required to carry a URI SAN at all, so the
// second return value reports whether it did. What the standard asks of the ID
// beyond its shape is that it share the leaf's trust domain, which this
// function cannot know; that comparison is the caller's, along with the
// sentinel it wants to name the mismatch by.
//
// It is exported because a root is the same certificate seen twice: an anchor
// somebody installs into a trust bundle, and a certificate this package
// validates during a handshake.
func ValidateSigningCertificate(certificate *x509.Certificate) (spiffeid.ID, bool, error) {
	if certificate == nil {
		return spiffeid.ID{}, false, fmt.Errorf(
			"validate signing-certificate: %w",
			ErrNoCertificate,
		)
	}

	if !certificate.IsCA {
		return spiffeid.ID{}, false, fmt.Errorf(
			"validate signing-certificate: %w",
			ErrSigningCertIsNotCA,
		)
	}

	if certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return spiffeid.ID{}, false, fmt.Errorf(
			"validate signing-certificate: %w",
			ErrSigningCertMissingKeyCertSign,
		)
	}

	if len(certificate.URIs) == 0 {
		return spiffeid.ID{}, false, nil
	}

	spiffeID, err := newSPIFFEID(certificate)
	if err != nil {
		return spiffeid.ID{}, false, fmt.Errorf("validate signing-certificate: %w", err)
	}

	if spiffeID.Path() != "" {
		return spiffeid.ID{}, false, fmt.Errorf(
			"validate signing-certificate: %w",
			ErrSigningSPIFFEHasPath,
		)
	}

	return spiffeID, true, nil
}

// validateSigningCertificateForLeaf is ValidateSigningCertificate with the one
// rule that needs the leaf: a signing certificate that carries a SPIFFE ID
// carries one in the leaf's trust domain.
func validateSigningCertificateForLeaf(
	signingCertificate *x509.Certificate,
	leaf spiffeid.ID,
) error {
	signingID, hasID, err := ValidateSigningCertificate(signingCertificate)
	if err != nil {
		return err
	}

	if hasID && leaf.TrustDomain() != signingID.TrustDomain() {
		return fmt.Errorf(
			"validate signing-certificate: %w",
			ErrSigningSPIFFEInDifferentTrustDomainThanLeaf,
		)
	}

	return nil
}

// newSPIFFEID extracts the SPIFFE ID from a certificate's URI SAN, applying the
// SPIFFE X509-SVID rule that a certificate carries exactly one URI SAN.
//
// It is deliberately unexported: it does not verify the certificate, and an
// identity read outside Verifier is not an authenticated one.
func newSPIFFEID(certificate *x509.Certificate) (spiffeid.ID, error) {
	if len(certificate.URIs) == 0 {
		return spiffeid.ID{}, fmt.Errorf("spiffe id from certificate: %w", ErrCertHasNoURI)
	}

	if len(certificate.URIs) > 1 {
		return spiffeid.ID{}, fmt.Errorf("spiffe id from certificate: %w", ErrCertHasMultipleURIs)
	}

	spiffeID, err := spiffeid.Parse(certificate.URIs[0].String())
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("spiffe id from certificate: %w", err)
	}

	return spiffeID, nil
}

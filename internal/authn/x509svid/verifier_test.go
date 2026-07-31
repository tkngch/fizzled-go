package x509svid_test

import (
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/tkngch/fizzled-go/internal/authn/spiffeid"
	"github.com/tkngch/fizzled-go/internal/authn/x509svid"
	"github.com/tkngch/fizzled-go/internal/testpki"
)

const trustDomain = "trustdomain.internal"

// testSkew is the clock-skew tolerance used by the tests that are not about
// skew. It matches the value the authn package applies in production.
const testSkew = 2 * time.Minute

// TestNewVerifier pins that a Verifier anchors to the bundle it was built from.
// A caller keeps a usable handle on the pool it passed in, and adding to it
// afterwards must not widen the trust of a Verifier already handed out.
func TestNewVerifier(t *testing.T) {
	t.Parallel()

	roots := make([]*x509.Certificate, 0, 1)

	verifier, err := x509svid.NewVerifier(roots, testSkew)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	// The certificate authority is added to the caller's pool only after the
	// Verifier was built from it.
	signer := testpki.NewAuthority(t, testpki.NewAuthorityOptions())

	roots = append(roots, signer.Certificate)
	if len(roots) != 1 {
		t.Fatalf("expected the caller's slice to carry the new root, got %d", len(roots))
	}

	certificate := newCertificate(t, signer, newCertificateOptions())

	_, err = verifier.Verify([]*x509.Certificate{certificate})

	_, ok := errors.AsType[x509.UnknownAuthorityError](err)
	if !ok {
		t.Fatalf("expected an unknown-authority error, got [%v]", err)
	}
}

// TestNewVerifierMisconfigurations covers the misconfigurations that the
// constructor rejects.
func TestNewVerifierMisconfigurations(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		roots         []*x509.Certificate
		skew          time.Duration
		expectedError error
	}{
		{"nil root", []*x509.Certificate{nil}, testSkew, x509svid.ErrNoCertificate},
		{"negative skew", nil, -1 * time.Minute, x509svid.ErrNegativeSkew},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				_, err := x509svid.NewVerifier(testCase.roots, testCase.skew)
				if !errors.Is(err, testCase.expectedError) {
					t.Fatalf("expected [%v], got [%v]", testCase.expectedError, err)
				}
			},
		)
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		parentURIs []string
	}{
		{
			name:       "no parent uri",
			parentURIs: nil,
		},
		{
			name:       "valid parent uri",
			parentURIs: []string{"spiffe://" + trustDomain},
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				issuerOpts := testpki.NewAuthorityOptions()
				issuerOpts.URIs = testCase.parentURIs
				parent := testpki.NewAuthority(t, issuerOpts)

				opts := newCertificateOptions()
				certificate := newCertificate(t, parent, opts)

				verifier := newVerifier(t, parent, testSkew)

				leaf, err := verifier.Verify([]*x509.Certificate{certificate})
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if leaf.ID().String() != opts.URIs[0] {
					t.Errorf("expected [%s], got [%s]", opts.URIs[0], leaf.ID().String())
				}

				if !leaf.Certificate().Equal(certificate) {
					t.Errorf("certificate mismatch")
				}
			},
		)
	}
}

// TestVerifyWithoutConstructor covers the Verifier that never went through
// NewVerifier. Its bundle is nil, and a nil bundle is not an empty one: the
// standard library reads it as a request for the host's system roots, so this
// has to be refused rather than anchored to whatever the machine trusts.
func TestVerifyWithoutConstructor(t *testing.T) {
	t.Parallel()

	signer := testpki.NewAuthority(t, testpki.NewAuthorityOptions())
	certificate := newCertificate(t, signer, newCertificateOptions())

	verifier := &x509svid.Verifier{}

	_, err := verifier.Verify([]*x509.Certificate{certificate})
	if !errors.Is(err, x509svid.ErrNoTrustBundle) {
		t.Fatalf("expected [%v], got [%v]", x509svid.ErrNoTrustBundle, err)
	}
}

// TestVerifyIgnoresIssuancePolicy pins the package boundary: a key
// algorithm and an extended key usage are issuance policy, so the X509-SVID
// checks here must accept a leaf that the fizzled policy in authn rejects.
func TestVerifyIgnoresIssuancePolicy(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		options func(opts *testpki.LeafOptions)
	}{
		{
			name: "RSA key",
			options: func(opts *testpki.LeafOptions) {
				opts.UseRSA = true
			},
		},
		{
			name: "P-384 key",
			options: func(opts *testpki.LeafOptions) {
				opts.Curve = elliptic.P384()
			},
		},
		{
			name: "no extended key usage",
			options: func(opts *testpki.LeafOptions) {
				opts.ExtKeyUsage = nil
			},
		},
		{
			name: "server authentication only",
			options: func(opts *testpki.LeafOptions) {
				opts.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				opts := newCertificateOptions()
				testCase.options(&opts)

				verifier, chain := signedLeaf(t, opts, testSkew)

				_, err := verifier.Verify(chain)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			},
		)
	}
}

// TestVerifyIntermediateChain covers the chain the trust bundle cannot complete
// on its own: the leaf reaches the root only through an intermediate, so it is
// the intermediate the peer presents that makes the chain, and the signing
// checks apply to a certificate that carries the chain rather than one merely
// sent along with it.
func TestVerifyIntermediateChain(t *testing.T) {
	t.Parallel()

	root := testpki.NewAuthority(t, testpki.NewAuthorityOptions())

	intermediateOpts := testpki.NewAuthorityOptions()
	intermediateOpts.URIs = []string{"spiffe://" + trustDomain}
	intermediate := testpki.NewIntermediate(t, root, intermediateOpts)

	certificate := newCertificate(t, intermediate, newCertificateOptions())

	// The bundle holds the root alone, as a trust bundle does.
	verifier := newVerifier(t, root, testSkew)

	t.Run("intermediate presented", func(t *testing.T) {
		t.Parallel()

		leaf, err := verifier.Verify([]*x509.Certificate{certificate, intermediate.Certificate})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if leaf.ID().TrustDomain() != trustDomain {
			t.Errorf("expected [%s], got [%s]", trustDomain, leaf.ID().TrustDomain())
		}
	})

	t.Run("intermediate withheld", func(t *testing.T) {
		t.Parallel()

		_, err := verifier.Verify([]*x509.Certificate{certificate})

		_, ok := errors.AsType[x509.UnknownAuthorityError](err)
		if !ok {
			t.Fatalf("expected an unknown-authority error, got [%v]", err)
		}
	})

	// The skew tolerance is measured against the leaf, so a leaf inside its own
	// window does not carry an expired intermediate with it.
	t.Run("intermediate expired", func(t *testing.T) {
		t.Parallel()

		expiredOpts := testpki.NewAuthorityOptions()
		expiredOpts.URIs = []string{"spiffe://" + trustDomain}
		expiredOpts.NotBefore = time.Now().Add(-2 * time.Hour)
		expiredOpts.NotAfter = time.Now().Add(-time.Hour)
		expired := testpki.NewIntermediate(t, root, expiredOpts)

		expiredLeaf := newCertificate(t, expired, newCertificateOptions())

		_, err := verifier.Verify([]*x509.Certificate{expiredLeaf, expired.Certificate})

		invalid, ok := errors.AsType[x509.CertificateInvalidError](err)
		if !ok {
			t.Fatalf("expected a certificate-invalid error, got [%v]", err)
		}

		if invalid.Reason != x509.Expired {
			t.Errorf("expected an expiry, got reason [%v]", invalid.Reason)
		}
	})

	t.Run("intermediate in another trust domain", func(t *testing.T) {
		t.Parallel()

		otherOpts := testpki.NewAuthorityOptions()
		otherOpts.URIs = []string{"spiffe://another." + trustDomain}
		other := testpki.NewIntermediate(t, root, otherOpts)

		otherLeaf := newCertificate(t, other, newCertificateOptions())

		_, err := verifier.Verify([]*x509.Certificate{otherLeaf, other.Certificate})
		if !errors.Is(err, x509svid.ErrSigningSPIFFEInDifferentTrustDomainThanLeaf) {
			t.Fatalf(
				"expected [%v], got [%v]",
				x509svid.ErrSigningSPIFFEInDifferentTrustDomainThanLeaf,
				err,
			)
		}
	})
}

// newVerifier builds a Verifier trusting parent.
func newVerifier(t *testing.T, parent testpki.Authority, skew time.Duration) *x509svid.Verifier {
	t.Helper()

	return newVerifierWithBundle(t, []*x509.Certificate{parent.Certificate}, skew)
}

// newVerifierWithBundle builds a Verifier trusting bundle, which the tests
// about the bundle itself need to hand over as they please.
func newVerifierWithBundle(
	t *testing.T,
	roots []*x509.Certificate,
	skew time.Duration,
) *x509svid.Verifier {
	t.Helper()

	verifier, err := x509svid.NewVerifier(roots, skew)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	return verifier
}

// signedLeaf issues a leaf described by opts, signed by a fresh CA, and returns
// a verifier trusting that CA along with the presented single-certificate chain.
func signedLeaf(
	t *testing.T,
	opts testpki.LeafOptions,
	skew time.Duration,
) (*x509svid.Verifier, []*x509.Certificate) {
	t.Helper()

	parent := testpki.NewAuthority(t, testpki.NewAuthorityOptions())
	certificate := newCertificate(t, parent, opts)

	return newVerifier(t, parent, skew), []*x509.Certificate{certificate}
}

// signedByIssuer issues a valid leaf signed by a CA described by issuerOpts, and
// returns a verifier trusting that CA together with a chain that also presents
// the CA, so the signing-certificate checks run.
func signedByIssuer(
	t *testing.T,
	issuerOpts testpki.AuthorityOptions,
) (*x509svid.Verifier, []*x509.Certificate) {
	t.Helper()

	parent := testpki.NewAuthority(t, issuerOpts)
	certificate := newCertificate(t, parent, newCertificateOptions())

	return newVerifier(t, parent, testSkew), []*x509.Certificate{certificate, parent.Certificate}
}

// newCertificateOptions describes a leaf carrying a SPIFFE ID in this test's
// trust domain. Everything else about it satisfies the X509-SVID standard, so a
// case states only what it means to break.
func newCertificateOptions() testpki.LeafOptions {
	return testpki.NewLeafOptions("spiffe://" + trustDomain + "/path")
}

// newCertificate issues a leaf signed by parent. The key it was issued to is of
// no interest here: these tests verify chains rather than present them.
func newCertificate(
	t *testing.T,
	parent testpki.Authority,
	opts testpki.LeafOptions,
) *x509.Certificate {
	t.Helper()

	certificate, _ := testpki.NewLeaf(t, parent, opts)

	return certificate
}

func TestVerifierLeafChainError(t *testing.T) {
	t.Parallel()

	t.Run("empty chain", func(t *testing.T) {
		t.Parallel()

		verifier := newVerifierWithBundle(t, nil, testSkew)

		_, err := verifier.Verify([]*x509.Certificate{})
		if !errors.Is(err, x509svid.ErrNoCertificate) {
			t.Fatalf("expected [%v], got [%v]", x509svid.ErrNoCertificate, err)
		}
	})

	// A chain carrying a nil certificate is turned away rather than panicking:
	// crypto/x509 dereferences a leaf without checking, and x509.CertPool.AddCert
	// panics outright on one.
	t.Run("nil certificate in the chain", func(t *testing.T) {
		t.Parallel()

		signer := testpki.NewAuthority(t, testpki.NewAuthorityOptions())
		certificate := newCertificate(t, signer, newCertificateOptions())
		verifier := newVerifier(t, signer, testSkew)

		chains := map[string][]*x509.Certificate{
			"nil leaf":         {nil},
			"nil intermediate": {certificate, nil},
		}

		for name, chain := range chains {
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				_, err := verifier.Verify(chain)
				if !errors.Is(err, x509svid.ErrNoCertificate) {
					t.Fatalf("expected [%v], got [%v]", x509svid.ErrNoCertificate, err)
				}
			})
		}
	})

	// An empty pool is a bundle that trusts nothing, which is a configuration a
	// caller may hold legitimately. A nil one is not: see
	// TestNewVerifierMisconfigurations.
	t.Run("empty bundle trusts nothing", func(t *testing.T) {
		t.Parallel()

		signer := testpki.NewAuthority(t, testpki.NewAuthorityOptions())
		certificate := newCertificate(t, signer, newCertificateOptions())

		verifier := newVerifierWithBundle(t, nil, testSkew)

		_, err := verifier.Verify([]*x509.Certificate{certificate})

		_, ok := errors.AsType[x509.UnknownAuthorityError](err)
		if !ok {
			t.Fatalf("expected an unknown-authority error, got [%v]", err)
		}
	})

	t.Run("chain does not anchor to the bundle", func(t *testing.T) {
		t.Parallel()

		signer := testpki.NewAuthority(t, testpki.NewAuthorityOptions())
		certificate := newCertificate(t, signer, newCertificateOptions())

		other := testpki.NewAuthority(t, testpki.NewAuthorityOptions())
		verifier := newVerifier(t, other, testSkew)

		_, err := verifier.Verify([]*x509.Certificate{certificate})

		_, ok := errors.AsType[x509.UnknownAuthorityError](err)
		if !ok {
			t.Fatalf("expected an unknown-authority error, got [%v]", err)
		}
	})
}

// TestVerifierLeafClockSkew asserts that the tolerance given to NewVerifier is
// what decides whether a leaf outside its validity window is accepted.
//
// Most of the cases sit a few seconds either side of the tolerance rather than
// an hour out, because the edge is where the comparisons decide anything: a
// Before that should have been an !After changes the verdict only for a leaf
// within epsilon of the boundary, and passes every case further away. The
// margin is still four orders of magnitude above the microseconds between
// issuing the certificate below and Verify reading the clock, so the answer
// does not turn on how loaded the machine is.
//
// The boundary itself — a leaf outside its window by exactly the tolerance —
// is not reachable: Verify reads time.Now() internally, and these tests hold to
// the exported API rather than adding a clock seam for a test to drive.
func TestVerifierLeafClockSkew(t *testing.T) {
	t.Parallel()

	const (
		tolerance = 10 * time.Minute
		epsilon   = 5 * time.Second
		far       = time.Hour
	)

	// The offsets are relative to a now the subtest reads, not the table. A
	// parallel subtest does not start until the parent returns, so a time.Time
	// in the table would have aged by an unbounded amount before it was used —
	// which is exactly what the epsilon-wide cases cannot afford.
	testCases := []struct {
		name        string
		skew        time.Duration
		notBefore   time.Duration
		notAfter    time.Duration
		expectError bool
	}{
		{
			name:        "not yet valid, just inside the tolerance",
			skew:        tolerance,
			notBefore:   tolerance - epsilon,
			notAfter:    far,
			expectError: false,
		},
		{
			name:        "not yet valid, just outside the tolerance",
			skew:        tolerance,
			notBefore:   tolerance + epsilon,
			notAfter:    far,
			expectError: true,
		},
		{
			name:        "expired, just inside the tolerance",
			skew:        tolerance,
			notBefore:   -far,
			notAfter:    -(tolerance - epsilon),
			expectError: false,
		},
		{
			name:        "expired, just outside the tolerance",
			skew:        tolerance,
			notBefore:   -far,
			notAfter:    -(tolerance + epsilon),
			expectError: true,
		},
		{
			name:        "no tolerance rejects a leaf valid in a moment",
			skew:        0,
			notBefore:   epsilon,
			notAfter:    far,
			expectError: true,
		},
		{
			name:        "no tolerance rejects a leaf expired a moment ago",
			skew:        0,
			notBefore:   -far,
			notAfter:    -epsilon,
			expectError: true,
		},
		{
			name:        "not yet valid, far outside the tolerance",
			skew:        tolerance,
			notBefore:   far,
			notAfter:    2 * far,
			expectError: true,
		},
		{
			name:        "expired, far outside the tolerance",
			skew:        tolerance,
			notBefore:   -2 * far,
			notAfter:    -far,
			expectError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				now := time.Now()

				opts := newCertificateOptions()
				opts.NotBefore = now.Add(testCase.notBefore)
				opts.NotAfter = now.Add(testCase.notAfter)

				verifier, chain := signedLeaf(t, opts, testCase.skew)

				leaf, err := verifier.Verify(chain)

				if testCase.expectError {
					if err == nil {
						t.Fatal("expected an error, got nil")
					}

					return
				}

				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if leaf.ID().String() != opts.URIs[0] {
					t.Errorf("expected [%s], got [%s]", opts.URIs[0], leaf.ID().String())
				}
			},
		)
	}
}

func TestVerifierLeafValidationError(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		options       func(opts *testpki.LeafOptions)
		expectedError error
	}{
		{
			name: "leaf is a CA",
			options: func(opts *testpki.LeafOptions) {
				opts.IsCA = true
			},
			expectedError: x509svid.ErrLeafCertIsCA,
		},
		{
			name: "leaf may sign certificates",
			options: func(opts *testpki.LeafOptions) {
				opts.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
			},
			expectedError: x509svid.ErrLeafCertHasKeyCertSign,
		},
		{
			name: "leaf may sign CRLs",
			options: func(opts *testpki.LeafOptions) {
				opts.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign
			},
			expectedError: x509svid.ErrLeafCertHasCRLSign,
		},
		{
			name: "leaf cannot sign digitally",
			options: func(opts *testpki.LeafOptions) {
				opts.KeyUsage = x509.KeyUsageKeyEncipherment
			},
			expectedError: x509svid.ErrLeafCertMissingDigitalSignature,
		},
		{
			name: "leaf spiffe-ID has no path",
			options: func(opts *testpki.LeafOptions) {
				opts.URIs = []string{"spiffe://" + trustDomain}
			},
			expectedError: x509svid.ErrLeafSPIFFEMissingPath,
		},
		{
			name: "leaf has no URI",
			options: func(opts *testpki.LeafOptions) {
				opts.URIs = nil
			},
			expectedError: x509svid.ErrCertHasNoURI,
		},
		{
			name: "leaf has multiple URIs",
			options: func(opts *testpki.LeafOptions) {
				opts.URIs = []string{
					"spiffe://" + trustDomain + "/a",
					"spiffe://" + trustDomain + "/b",
				}
			},
			expectedError: x509svid.ErrCertHasMultipleURIs,
		},
		{
			name: "leaf URI is not a SPIFFE ID",
			options: func(opts *testpki.LeafOptions) {
				opts.URIs = []string{"https://" + trustDomain + "/path"}
			},
			expectedError: spiffeid.ErrNotSPIFFE,
		},
		{
			name: "leaf URI is in another domain",
			options: func(opts *testpki.LeafOptions) {
				opts.URIs = []string{"spiffe://another." + trustDomain + "/path"}
			},
			expectedError: nil,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				opts := newCertificateOptions()
				testCase.options(&opts)

				verifier, chain := signedLeaf(t, opts, testSkew)

				_, err := verifier.Verify(chain)
				if !errors.Is(err, testCase.expectedError) {
					t.Fatalf("expected [%v], got [%v]", testCase.expectedError, err)
				}
			},
		)
	}
}

// TestVerifierLeafAcceptsSigningCertificate covers the cases where a peer
// presents its signing CA alongside the leaf and every signing check passes. A
// CA without a URI SAN is accepted: the standard only constrains the SPIFFE ID
// of a signing certificate that carries one.
func TestVerifierLeafAcceptsSigningCertificate(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		uris []string
	}{
		{
			name: "signing cert has no URI",
			uris: nil,
		},
		{
			name: "signing cert has a path-less spiffe-ID",
			uris: []string{"spiffe://" + trustDomain},
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				issuerOpts := testpki.NewAuthorityOptions()
				issuerOpts.URIs = testCase.uris

				verifier, chain := signedByIssuer(t, issuerOpts)

				leaf, err := verifier.Verify(chain)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if leaf.ID().TrustDomain() != trustDomain {
					t.Errorf("expected [%s], got [%s]", trustDomain, leaf.ID().TrustDomain())
				}
			},
		)
	}
}

// TestVerifierLeafSigningCertificateError covers the checks applied to every
// certificate a peer presents after the leaf.
func TestVerifierLeafSigningCertificateError(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		options       func(opts *testpki.AuthorityOptions)
		expectedError error
	}{
		{
			name: "signing cert is in a different trust-domain",
			options: func(opts *testpki.AuthorityOptions) {
				opts.URIs = []string{"spiffe://another." + trustDomain}
			},
			expectedError: x509svid.ErrSigningSPIFFEInDifferentTrustDomainThanLeaf,
		},
		{
			name: "signing cert has a path",
			options: func(opts *testpki.AuthorityOptions) {
				opts.URIs = []string{"spiffe://" + trustDomain + "/path"}
			},
			expectedError: x509svid.ErrSigningSPIFFEHasPath,
		},
		{
			name: "signing cert has multiple URIs",
			options: func(opts *testpki.AuthorityOptions) {
				opts.URIs = []string{
					"spiffe://" + trustDomain,
					"spiffe://" + trustDomain + "/extra",
				}
			},
			expectedError: x509svid.ErrCertHasMultipleURIs,
		},
		{
			name: "signing cert URI is not a SPIFFE ID",
			options: func(opts *testpki.AuthorityOptions) {
				opts.URIs = []string{"https://" + trustDomain}
			},
			expectedError: spiffeid.ErrNotSPIFFE,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				issuerOpts := testpki.NewAuthorityOptions()
				testCase.options(&issuerOpts)

				verifier, chain := signedByIssuer(t, issuerOpts)

				_, err := verifier.Verify(chain)
				if !errors.Is(err, testCase.expectedError) {
					t.Fatalf("expected [%v], got [%v]", testCase.expectedError, err)
				}
			},
		)
	}
}

// TestValidateSigningCertificate covers the exported rules on their own, rather
// than through the two callers that apply them. Two things are only visible
// here.
//
// The first is the second return value. A signing certificate is not required
// to carry a SPIFFE ID at all, and a caller that adds a trust-domain rule of
// its own — as a trust bundle does — has to know whether there is an ID for it
// to apply that rule to.
//
// The second is what this function does not judge: a signing certificate in
// another trust domain is accepted here. Whose domain a certificate must be in
// is not something the standard can say, so it is left to the caller, which is
// why the case below is an accepting one.
func TestValidateSigningCertificate(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		options       func(opts *testpki.AuthorityOptions)
		expectedID    string
		expectedError error
	}{
		{
			name:          "no uri",
			options:       func(_ *testpki.AuthorityOptions) {},
			expectedID:    "",
			expectedError: nil,
		},
		{
			name: "path-less uri",
			options: func(opts *testpki.AuthorityOptions) {
				opts.URIs = []string{"spiffe://" + trustDomain}
			},
			expectedID:    "spiffe://" + trustDomain,
			expectedError: nil,
		},
		{
			name: "path-less uri in another trust domain",
			options: func(opts *testpki.AuthorityOptions) {
				opts.URIs = []string{"spiffe://another." + trustDomain}
			},
			expectedID:    "spiffe://another." + trustDomain,
			expectedError: nil,
		},
		{
			name: "not a CA",
			options: func(opts *testpki.AuthorityOptions) {
				opts.IsCA = false
				opts.KeyUsage = x509.KeyUsageDigitalSignature
			},
			expectedID:    "",
			expectedError: x509svid.ErrSigningCertIsNotCA,
		},
		{
			name: "may not sign certificates",
			options: func(opts *testpki.AuthorityOptions) {
				opts.KeyUsage = x509.KeyUsageCRLSign
			},
			expectedID:    "",
			expectedError: x509svid.ErrSigningCertMissingKeyCertSign,
		},
		{
			name: "uri carries a path",
			options: func(opts *testpki.AuthorityOptions) {
				opts.URIs = []string{"spiffe://" + trustDomain + "/ca"}
			},
			expectedID:    "",
			expectedError: x509svid.ErrSigningSPIFFEHasPath,
		},
		{
			name: "several uris",
			options: func(opts *testpki.AuthorityOptions) {
				opts.URIs = []string{
					"spiffe://" + trustDomain,
					"spiffe://" + trustDomain + "/extra",
				}
			},
			expectedID:    "",
			expectedError: x509svid.ErrCertHasMultipleURIs,
		},
		{
			name: "uri is not a spiffe id",
			options: func(opts *testpki.AuthorityOptions) {
				opts.URIs = []string{"https://" + trustDomain}
			},
			expectedID:    "",
			expectedError: spiffeid.ErrNotSPIFFE,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				opts := testpki.NewAuthorityOptions()
				testCase.options(&opts)

				authority := testpki.NewAuthority(t, opts)

				spiffeID, hasID, err := x509svid.ValidateSigningCertificate(authority.Certificate)
				if !errors.Is(err, testCase.expectedError) {
					t.Fatalf("expected [%v], got [%v]", testCase.expectedError, err)
				}

				if hasID != (testCase.expectedID != "") {
					t.Errorf(
						"expected an id present of %t, got %t",
						testCase.expectedID != "",
						hasID,
					)
				}

				if spiffeID.String() != testCase.expectedID {
					t.Errorf("expected [%s], got [%s]", testCase.expectedID, spiffeID)
				}
			},
		)
	}
}

// TestValidateSigningCertificateNil covers the nil certificate. It is reported
// rather than dereferenced, so a caller assembling a trust bundle out of
// whatever it parsed gets an error back instead of a panic.
func TestValidateSigningCertificateNil(t *testing.T) {
	t.Parallel()

	spiffeID, hasID, err := x509svid.ValidateSigningCertificate(nil)
	if !errors.Is(err, x509svid.ErrNoCertificate) {
		t.Fatalf("expected [%v], got [%v]", x509svid.ErrNoCertificate, err)
	}

	if hasID {
		t.Errorf("expected no id, got [%s]", spiffeID)
	}
}

// TestVerifierLeafRejectsUnusableExtraCertificate covers the defensive checks
// in validateSigningCertificateForLeaf. A peer may present a certificate
// alongside a chain that anchors without it, in which case crypto/x509 never
// inspects it, so the cA and keyCertSign checks are what reject it.
func TestVerifierLeafRejectsUnusableExtraCertificate(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		options       func(opts *testpki.AuthorityOptions)
		expectedError error
	}{
		{
			name: "extra certificate is not a CA",
			options: func(opts *testpki.AuthorityOptions) {
				opts.IsCA = false
				opts.KeyUsage = x509.KeyUsageDigitalSignature
			},
			expectedError: x509svid.ErrSigningCertIsNotCA,
		},
		{
			name: "extra certificate may not sign certificates",
			options: func(opts *testpki.AuthorityOptions) {
				opts.KeyUsage = x509.KeyUsageCRLSign
			},
			expectedError: x509svid.ErrSigningCertMissingKeyCertSign,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				// The leaf anchors to its own signer, so the extra certificate
				// is never needed to build the chain.
				signer := testpki.NewAuthority(t, testpki.NewAuthorityOptions())
				certificate := newCertificate(t, signer, newCertificateOptions())

				extraOpts := testpki.NewAuthorityOptions()
				testCase.options(&extraOpts)
				extra := testpki.NewAuthority(t, extraOpts)

				verifier := newVerifier(t, signer, testSkew)

				_, err := verifier.Verify(
					[]*x509.Certificate{certificate, extra.Certificate},
				)
				if !errors.Is(err, testCase.expectedError) {
					t.Fatalf("expected [%v], got [%v]", testCase.expectedError, err)
				}
			},
		)
	}
}

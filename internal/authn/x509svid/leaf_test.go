package x509svid_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/tkngch/fizzled-go/internal/authn/x509svid"
)

const trustDomain = "trustdomain.internal"

func TestNewLeaf(t *testing.T) {
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

				parent := newIssuer(t, testCase.parentURIs)
				opts := newCertificateOptions()
				certificate := newCertificate(t, &parent, opts)

				bundle := x509.NewCertPool()
				bundle.AddCert(parent.certificate)

				leaf, err := x509svid.NewLeaf(bundle, [][]byte{certificate})
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if leaf.ID().String() != opts.uris[0] {
					t.Errorf("expected [%s], got [%s]", opts.uris[0], leaf.ID().String())
				}

				expectedCertificate, err := x509.ParseCertificate(certificate)
				if err != nil {
					t.Fatalf("unexpected error in parsing a certificate: %v", err)
				}

				if !leaf.Certificate().Equal(expectedCertificate) {
					t.Errorf("certificate mismatch")
				}
			},
		)
	}
}

func TestNewLeafError(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		options       func(opts *certificateOptions)
		expectedError error
	}{
		{
			name: "leaf is a CA",
			options: func(opts *certificateOptions) {
				opts.isCA = true
			},
			expectedError: x509svid.ErrLeafCertIsCA,
		},
		{
			name: "leaf may sign certificates",
			options: func(opts *certificateOptions) {
				opts.keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
			},
			expectedError: x509svid.ErrLeafCertHasKeyCertSign,
		},
		{
			name: "leaf may sign CRLs",
			options: func(opts *certificateOptions) {
				opts.keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign
			},
			expectedError: x509svid.ErrLeafCertHasCrlSign,
		},
		{
			name: "leaf cannot sign digitally",
			options: func(opts *certificateOptions) {
				opts.keyUsage = x509.KeyUsageKeyEncipherment
			},
			expectedError: x509svid.ErrLeafCertMissingDigitalSignature,
		},
		{
			name: "leaf is not for server authentication",
			options: func(opts *certificateOptions) {
				opts.extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			},
			expectedError: x509svid.ErrLeafCertMissingServerAuth,
		},
		{
			name: "leaf is not for client authentication",
			options: func(opts *certificateOptions) {
				opts.extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			},
			expectedError: x509svid.ErrLeafCertMissingClientAuth,
		},
		{
			name: "leaf key is not ECDSA",
			options: func(opts *certificateOptions) {
				opts.useRSA = true
			},
			expectedError: x509svid.ErrLeafPublicKeyNotECDSA,
		},
		{
			name: "leaf key is not P-256",
			options: func(opts *certificateOptions) {
				opts.curve = elliptic.P384()
			},
			expectedError: x509svid.ErrLeafPublicKeyNotP256,
		},
		{
			name: "leaf spiffe-ID has no path",
			options: func(opts *certificateOptions) {
				opts.uris = []string{"spiffe://" + trustDomain}
			},
			expectedError: x509svid.ErrLeafSpiffeMissingPath,
		},
		{
			name: "leaf has no URI",
			options: func(opts *certificateOptions) {
				opts.uris = nil
			},
			expectedError: x509svid.ErrCertHasNoURI,
		},
		{
			name: "leaf has multiple URIs",
			options: func(opts *certificateOptions) {
				opts.uris = []string{
					"spiffe://" + trustDomain + "/a",
					"spiffe://" + trustDomain + "/b",
				}
			},
			expectedError: x509svid.ErrCertHasMultipleURIs,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				opts := newCertificateOptions()
				testCase.options(&opts)

				bundle, chain := signedLeaf(t, opts)

				_, err := x509svid.NewLeaf(bundle, chain)
				if !errors.Is(err, testCase.expectedError) {
					t.Fatalf("expected [%v], got [%v]", testCase.expectedError, err)
				}
			},
		)
	}
}

// TestNewLeafChainError covers the chain-level failures whose setups do not fit
// the single-leaf mutation table above.
func TestNewLeafChainError(t *testing.T) {
	t.Parallel()

	t.Run("empty chain", func(t *testing.T) {
		t.Parallel()

		_, err := x509svid.NewLeaf(x509.NewCertPool(), [][]byte{})
		if !errors.Is(err, x509svid.ErrNoCertificate) {
			t.Fatalf("expected [%v], got [%v]", x509svid.ErrNoCertificate, err)
		}
	})

	t.Run("malformed certificate", func(t *testing.T) {
		t.Parallel()

		_, err := x509svid.NewLeaf(x509.NewCertPool(), [][]byte{[]byte("not a certificate")})
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
	})

	t.Run("chain does not anchor to the bundle", func(t *testing.T) {
		t.Parallel()

		signer := newIssuer(t, nil)
		certificate := newCertificate(t, &signer, newCertificateOptions())

		other := newIssuer(t, nil)
		bundle := x509.NewCertPool()
		bundle.AddCert(other.certificate)

		_, err := x509svid.NewLeaf(bundle, [][]byte{certificate})
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
	})

	t.Run("leaf expired beyond skew", func(t *testing.T) {
		t.Parallel()

		opts := newCertificateOptions()
		opts.notBefore = time.Now().Add(-2 * time.Hour)
		opts.notAfter = time.Now().Add(-time.Hour)

		bundle, chain := signedLeaf(t, opts)

		_, err := x509svid.NewLeaf(bundle, chain)
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
	})

	t.Run("signing cert is in a different trust-domain", func(t *testing.T) {
		t.Parallel()

		bundle, chain := signedByCA(t, []string{"spiffe://another." + trustDomain})

		_, err := x509svid.NewLeaf(bundle, chain)
		if !errors.Is(err, x509svid.ErrSigningSpiffeInDifferentTrustDomainThanLeaf) {
			t.Fatalf(
				"expected [%v], got [%v]",
				x509svid.ErrSigningSpiffeInDifferentTrustDomainThanLeaf,
				err,
			)
		}
	})

	t.Run("signing cert has a path", func(t *testing.T) {
		t.Parallel()

		bundle, chain := signedByCA(t, []string{"spiffe://" + trustDomain + "/path"})

		_, err := x509svid.NewLeaf(bundle, chain)
		if !errors.Is(err, x509svid.ErrSigningSpiffeHasPath) {
			t.Fatalf("expected [%v], got [%v]", x509svid.ErrSigningSpiffeHasPath, err)
		}
	})
}

// TestNewLeafClockSkew asserts that a leaf whose validity boundary is within the
// skew tolerance still verifies.
func TestNewLeafClockSkew(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
	}{
		{
			name:      "not yet valid but within skew",
			notBefore: time.Now().Add(time.Minute),
			notAfter:  time.Now().Add(time.Hour),
		},
		{
			name:      "recently expired but within skew",
			notBefore: time.Now().Add(-time.Hour),
			notAfter:  time.Now().Add(-time.Minute),
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				opts := newCertificateOptions()
				opts.notBefore = testCase.notBefore
				opts.notAfter = testCase.notAfter

				bundle, chain := signedLeaf(t, opts)

				leaf, err := x509svid.NewLeaf(bundle, chain)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if leaf.ID().String() != opts.uris[0] {
					t.Errorf("expected [%s], got [%s]", opts.uris[0], leaf.ID().String())
				}
			},
		)
	}
}

// signedLeaf issues a leaf described by opts, signed by a fresh CA, and returns
// a bundle trusting that CA along with the presented single-certificate chain.
func signedLeaf(t *testing.T, opts certificateOptions) (*x509.CertPool, [][]byte) {
	t.Helper()

	parent := newIssuer(t, nil)
	certificate := newCertificate(t, &parent, opts)

	bundle := x509.NewCertPool()
	bundle.AddCert(parent.certificate)

	return bundle, [][]byte{certificate}
}

// signedByCA issues a valid leaf signed by a CA carrying caURIs, and returns a
// bundle trusting that CA together with a chain that also presents the CA, so
// the signing-certificate checks run.
func signedByCA(t *testing.T, caURIs []string) (*x509.CertPool, [][]byte) {
	t.Helper()

	parent := newIssuer(t, caURIs)
	certificate := newCertificate(t, &parent, newCertificateOptions())

	bundle := x509.NewCertPool()
	bundle.AddCert(parent.certificate)

	return bundle, [][]byte{certificate, parent.certificate.Raw}
}

type issuer struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
}

type certificateOptions struct {
	uris        []string
	isCA        bool
	keyUsage    x509.KeyUsage
	extKeyUsage []x509.ExtKeyUsage
	curve       elliptic.Curve
	useRSA      bool
	notBefore   time.Time
	notAfter    time.Time
}

// newIssuer generates a self-signed certificate authority (CA).
func newIssuer(t *testing.T, uris []string) issuer {
	t.Helper()

	key := ecdsaPrivateKey(t, elliptic.P256())

	template := newX509Certificate(t)
	template.Subject.CommonName = "test issuer"
	template.NotBefore = time.Now().Add(-24 * time.Hour)
	template.NotAfter = time.Now().Add(24 * time.Hour)
	template.IsCA = true
	template.BasicConstraintsValid = true
	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign

	for _, raw := range uris {
		uri, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse URI [%s]: %v", raw, err)
		}

		template.URIs = append(template.URIs, uri)
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal("new issuer: create certificate: %w", err)
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("new issuer: parse certificate: %w", err)
	}

	return issuer{certificate, key}
}

func newCertificateOptions() certificateOptions {
	return certificateOptions{
		uris:        []string{fmt.Sprintf("spiffe://%s/path", trustDomain)},
		isCA:        false,
		keyUsage:    x509.KeyUsageDigitalSignature,
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		curve:       elliptic.P256(),
		useRSA:      false,
		notBefore:   time.Now().Add(-time.Hour),
		notAfter:    time.Now().Add(time.Hour),
	}
}

func newCertificate(
	t *testing.T,
	parent *issuer,
	opts certificateOptions,
) []byte {
	t.Helper()

	template := newX509Certificate(t)
	template.NotBefore = opts.notBefore
	template.NotAfter = opts.notAfter
	template.IsCA = opts.isCA
	template.BasicConstraintsValid = true
	template.KeyUsage = opts.keyUsage
	template.ExtKeyUsage = opts.extKeyUsage

	for _, raw := range opts.uris {
		uri, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse URI [%s]: %v", raw, err)
		}

		template.URIs = append(template.URIs, uri)
	}

	var publicKey, signerKey any

	if opts.useRSA {
		key := rsaPrivateKey(t)
		publicKey = &key.PublicKey
		signerKey = key
	} else {
		key := ecdsaPrivateKey(t, opts.curve)
		publicKey = &key.PublicKey
		signerKey = key
	}

	signerCert := template

	if parent != nil {
		signerCert = parent.certificate
		signerKey = parent.key
	}

	der, err := x509.CreateCertificate(rand.Reader, template, signerCert, publicKey, signerKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	return der
}

func newX509Certificate(t *testing.T) *x509.Certificate {
	t.Helper()

	return &x509.Certificate{
		SerialNumber: randomSerialNumber(t),

		Raw:                     []byte{},
		RawTBSCertificate:       []byte{},
		RawSubjectPublicKeyInfo: []byte{},
		RawSubject:              []byte{},
		RawIssuer:               []byte{},
		Signature:               []byte{},
		SignatureAlgorithm:      x509.UnknownSignatureAlgorithm,
		PublicKeyAlgorithm:      x509.UnknownPublicKeyAlgorithm,
		PublicKey:               nil,
		Version:                 0,
		Issuer: pkix.Name{
			Country:            []string{},
			Organization:       []string{},
			OrganizationalUnit: []string{},
			Locality:           []string{},
			Province:           []string{},
			StreetAddress:      []string{},
			PostalCode:         []string{},
			SerialNumber:       "",
			CommonName:         "",
			Names:              []pkix.AttributeTypeAndValue{},
			ExtraNames:         []pkix.AttributeTypeAndValue{},
		},
		Subject: pkix.Name{
			Country:            []string{},
			Organization:       []string{},
			OrganizationalUnit: []string{},
			Locality:           []string{},
			Province:           []string{},
			StreetAddress:      []string{},
			PostalCode:         []string{},
			SerialNumber:       "",
			CommonName:         "",
			Names:              []pkix.AttributeTypeAndValue{},
			ExtraNames:         []pkix.AttributeTypeAndValue{},
		},
		NotBefore:                   time.Time{},
		NotAfter:                    time.Time{},
		KeyUsage:                    x509.KeyUsage(0),
		Extensions:                  []pkix.Extension{},
		ExtraExtensions:             []pkix.Extension{},
		UnhandledCriticalExtensions: []asn1.ObjectIdentifier{},
		ExtKeyUsage:                 []x509.ExtKeyUsage{},
		UnknownExtKeyUsage:          []asn1.ObjectIdentifier{},
		BasicConstraintsValid:       false,
		IsCA:                        false,
		MaxPathLen:                  0,
		MaxPathLenZero:              false,
		SubjectKeyId:                []byte{},
		AuthorityKeyId:              []byte{},
		OCSPServer:                  []string{},
		IssuingCertificateURL:       []string{},
		DNSNames:                    []string{},
		EmailAddresses:              []string{},
		IPAddresses:                 []net.IP{},
		URIs:                        []*url.URL{},
		PermittedDNSDomainsCritical: false,
		PermittedDNSDomains:         []string{},
		ExcludedDNSDomains:          []string{},
		PermittedIPRanges:           []*net.IPNet{},
		ExcludedIPRanges:            []*net.IPNet{},
		PermittedEmailAddresses:     []string{},
		ExcludedEmailAddresses:      []string{},
		PermittedURIDomains:         []string{},
		ExcludedURIDomains:          []string{},
		CRLDistributionPoints:       []string{},
		PolicyIdentifiers:           []asn1.ObjectIdentifier{},
		Policies:                    []x509.OID{},
		InhibitAnyPolicy:            0,
		InhibitAnyPolicyZero:        false,
		InhibitPolicyMapping:        0,
		InhibitPolicyMappingZero:    false,
		RequireExplicitPolicy:       0,
		RequireExplicitPolicyZero:   false,
		PolicyMappings:              []x509.PolicyMapping{},
	}
}

func ecdsaPrivateKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa generate key: %v", err)
	}

	return key
}

func rsaPrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	const bits = 2048

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa generate key: %v", err)
	}

	return key
}

// randomSerialNumber returns a random 128-bit serial.
func randomSerialNumber(t *testing.T) *big.Int {
	t.Helper()

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("random serial number: %v", err)
	}

	return serial
}

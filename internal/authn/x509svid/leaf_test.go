package x509svid_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

				if leaf.Certificate() != expectedCertificate {
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
		issuerURIs    []string
		options       certificateOptions
		expectedError error
	}{
		{
			name:          "parent is in a different trust-domain",
			issuerURIs:    []string{"spiffe://another." + trustDomain},
			options:       newCertificateOptions(),
			expectedError: x509svid.ErrSigningSpiffeInDifferentTrustDomainThanLeaf,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				parent := newIssuer(t, testCase.issuerURIs)
				certificate := newCertificate(t, &parent, testCase.options)

				bundle := x509.NewCertPool()
				bundle.AddCert(parent.certificate)

				_, err := x509svid.NewLeaf(bundle, [][]byte{certificate})
				if !errors.Is(err, testCase.expectedError) {
					t.Fatalf("expected [%v], got [%v]", testCase.expectedError, err)
				}
			},
		)
	}
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

	key := ecdsaPrivateKey(t, opts.curve)
	signerCert := template

	var signerKey any = key

	if parent != nil {
		signerCert = parent.certificate
		signerKey = parent.key
	}

	der, err := x509.CreateCertificate(rand.Reader, template, signerCert, &key.PublicKey, signerKey)
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

// randomSerialNumber returns a random 128-bit serial.
func randomSerialNumber(t *testing.T) *big.Int {
	t.Helper()

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("random serial number: %v", err)
	}

	return serial
}

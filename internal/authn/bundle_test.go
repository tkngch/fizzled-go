package authn_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tkngch/fizzled-go/internal/authn"
)

func TestLoadTrustBundle(t *testing.T) {
	t.Parallel()

	t.Run("valid bundle", func(t *testing.T) {
		t.Parallel()

		path := writeBundle(t, caPEM(t))

		pool, err := authn.LoadTrustBundle(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if pool == nil {
			t.Fatal("expected a non-nil pool")
		}
	})

	t.Run("empty file", func(t *testing.T) {
		t.Parallel()

		path := writeBundle(t, []byte{})

		_, err := authn.LoadTrustBundle(path)
		if !errors.Is(err, authn.ErrEmptyTrustBundle) {
			t.Fatalf("expected [%v], got [%v]", authn.ErrEmptyTrustBundle, err)
		}
	})

	t.Run("no PEM blocks", func(t *testing.T) {
		t.Parallel()

		path := writeBundle(t, []byte("not a pem file"))

		_, err := authn.LoadTrustBundle(path)
		if !errors.Is(err, authn.ErrEmptyTrustBundle) {
			t.Fatalf("expected [%v], got [%v]", authn.ErrEmptyTrustBundle, err)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "does-not-exist.pem")

		_, err := authn.LoadTrustBundle(path)
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
	})
}

func writeBundle(t *testing.T, contents []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "bundle.pem")

	err := os.WriteFile(path, contents, 0o600)
	if err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	return path
}

// newCA generates a self-signed certificate authority.
func newCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key := ecdsaKey(t)

	template := newTemplate(t)
	template.Subject.CommonName = "test ca"
	template.NotBefore = time.Now().Add(-time.Hour)
	template.NotAfter = time.Now().Add(time.Hour)
	template.IsCA = true
	template.BasicConstraintsValid = true
	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ca certificate: %v", err)
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca certificate: %v", err)
	}

	return certificate, key
}

// caPEM returns a PEM-encoded self-signed CA certificate.
func caPEM(t *testing.T) []byte {
	t.Helper()

	certificate, _ := newCA(t)

	return pem.EncodeToMemory(&pem.Block{
		Type:    "CERTIFICATE",
		Headers: map[string]string{},
		Bytes:   certificate.Raw,
	})
}

func ecdsaKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	return key
}

func newTemplate(t *testing.T) *x509.Certificate {
	t.Helper()

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("random serial number: %v", err)
	}

	return &x509.Certificate{
		SerialNumber: serialNumber,

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

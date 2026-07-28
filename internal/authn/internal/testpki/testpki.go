package testpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	// certificatePEMType is the PEM block type a certificate is written in.
	certificatePEMType = "CERTIFICATE"

	// privateKeyPEMType is the PEM block type a private key is written in.
	privateKeyPEMType = "PRIVATE KEY"

	// keyFileMode keeps a written key readable by its owner alone, as gosec
	// (G306) asks of a file that carries one.
	keyFileMode os.FileMode = 0o600

	// rsaBits is the size of the RSA key the tests reach for when they want a
	// leaf whose key is not ECDSA. It is the smallest crypto/x509 will sign
	// with, because the tests want the key rejected, not the signing to be slow.
	rsaBits = 2048

	// serialNumberBits is the size of the random serial number every issued
	// certificate carries.
	serialNumberBits = 128

	// authorityValidity is how far either side of the present an authority is
	// valid by default. It outlives the leaves it signs, as a CA should.
	authorityValidity = 24 * time.Hour

	// leafValidity is the same for a leaf, and is the shorter of the two.
	leafValidity = time.Hour
)

// Authority is a certificate authority the tests issue from, together with the
// key it signs with.
type Authority struct {
	Certificate *x509.Certificate
	Key         *ecdsa.PrivateKey
}

// AuthorityOptions describes an authority to issue.
type AuthorityOptions struct {
	URIs      []string
	IsCA      bool
	KeyUsage  x509.KeyUsage
	NotBefore time.Time
	NotAfter  time.Time
}

// NewAuthorityOptions describes an authority that can sign: a CA carrying no
// URI SAN, which the X509-SVID standard permits, valid around the present.
func NewAuthorityOptions() AuthorityOptions {
	return AuthorityOptions{
		URIs:      nil,
		IsCA:      true,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		NotBefore: time.Now().Add(-authorityValidity),
		NotAfter:  time.Now().Add(authorityValidity),
	}
}

// LeafOptions describes a leaf certificate to issue.
type LeafOptions struct {
	URIs        []string
	IsCA        bool
	KeyUsage    x509.KeyUsage
	ExtKeyUsage []x509.ExtKeyUsage
	Curve       elliptic.Curve
	UseRSA      bool
	NotBefore   time.Time
	NotAfter    time.Time
}

// NewLeafOptions describes a leaf carrying uris that satisfies the fizzled
// issuance policy: an ECDSA P-256 key, both extended key usages, and
// digitalSignature alone in the key usage.
func NewLeafOptions(uris ...string) LeafOptions {
	return LeafOptions{
		URIs:     uris,
		IsCA:     false,
		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		Curve:     elliptic.P256(),
		UseRSA:    false,
		NotBefore: time.Now().Add(-leafValidity),
		NotAfter:  time.Now().Add(leafValidity),
	}
}

// NewAuthority issues a self-signed authority described by opts.
func NewAuthority(tb testing.TB, opts AuthorityOptions) Authority {
	tb.Helper()

	return signAuthority(tb, nil, opts)
}

// NewIntermediate issues an authority described by opts and signed by parent. A
// peer must present it for a chain to reach the trust bundle through it.
func NewIntermediate(tb testing.TB, parent Authority, opts AuthorityOptions) Authority {
	tb.Helper()

	return signAuthority(tb, &parent, opts)
}

// NewLeaf issues the leaf described by opts, signed by parent, and returns it
// with the key it was issued to.
func NewLeaf(
	tb testing.TB,
	parent Authority,
	opts LeafOptions,
) (*x509.Certificate, crypto.Signer) {
	tb.Helper()

	template := newTemplate(tb)
	template.NotBefore = opts.NotBefore
	template.NotAfter = opts.NotAfter
	template.IsCA = opts.IsCA
	template.BasicConstraintsValid = true
	template.KeyUsage = opts.KeyUsage
	template.ExtKeyUsage = opts.ExtKeyUsage
	template.URIs = parseURIs(tb, opts.URIs)

	var key crypto.Signer
	if opts.UseRSA {
		key = rsaPrivateKey(tb)
	} else {
		key = ecdsaPrivateKey(tb, opts.Curve)
	}

	return sign(tb, template, parent.Certificate, key.Public(), parent.Key), key
}

// NewLeafFiles issues the leaf described by opts and writes the certificate and
// its private key to a temporary directory, as the paths a tls.Config is built
// from.
func NewLeafFiles(tb testing.TB, parent Authority, opts LeafOptions) (string, string) {
	tb.Helper()

	dir := tb.TempDir()
	certificate, key := NewLeaf(tb, parent, opts)

	return WriteCertificate(tb, dir, "certificate.crt", certificate),
		WriteKey(tb, dir, "private-key.key", key)
}

// signAuthority issues an authority, self-signed when parent is nil.
func signAuthority(tb testing.TB, parent *Authority, opts AuthorityOptions) Authority {
	tb.Helper()

	key := ecdsaPrivateKey(tb, elliptic.P256())

	template := newTemplate(tb)
	template.Subject.CommonName = "test authority"
	template.NotBefore = opts.NotBefore
	template.NotAfter = opts.NotAfter
	template.IsCA = opts.IsCA
	template.BasicConstraintsValid = true
	template.KeyUsage = opts.KeyUsage
	template.URIs = parseURIs(tb, opts.URIs)

	signerCertificate := template

	signerKey := key

	if parent != nil {
		signerCertificate = parent.Certificate
		signerKey = parent.Key
	}

	return Authority{
		Certificate: sign(tb, template, signerCertificate, &key.PublicKey, signerKey),
		Key:         key,
	}
}

// sign creates the certificate template describes and parses it back, so that
// what a test holds is a certificate as it came off the wire rather than the
// template it was asked for.
func sign(
	tb testing.TB,
	template, parent *x509.Certificate,
	publicKey crypto.PublicKey,
	signerKey crypto.Signer,
) *x509.Certificate {
	tb.Helper()

	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signerKey)
	if err != nil {
		tb.Fatalf("testpki: create certificate: %v", err)
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("testpki: parse certificate: %v", err)
	}

	return certificate
}

// CertificatePEM is the PEM encoding of a certificate, as a trust bundle or a
// certificate file carries it.
func CertificatePEM(certificate *x509.Certificate) []byte {
	block := &pem.Block{
		Type:    certificatePEMType,
		Headers: map[string]string{},
		Bytes:   certificate.Raw,
	}

	return pem.EncodeToMemory(block)
}

// WriteCertificate writes certificate to dir/name in PEM and returns the path.
func WriteCertificate(tb testing.TB, dir, name string, certificate *x509.Certificate) string {
	tb.Helper()

	return WriteFile(tb, dir, name, CertificatePEM(certificate))
}

// WriteKey writes key to dir/name in PEM and returns the path.
func WriteKey(tb testing.TB, dir, name string, key crypto.Signer) string {
	tb.Helper()

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		tb.Fatalf("testpki: marshal key: %v", err)
	}

	block := &pem.Block{
		Type:    privateKeyPEMType,
		Headers: map[string]string{},
		Bytes:   der,
	}

	return WriteFile(tb, dir, name, pem.EncodeToMemory(block))
}

// WriteFile writes data to dir/name and returns the path.
func WriteFile(tb testing.TB, dir, name string, data []byte) string {
	tb.Helper()

	path := filepath.Join(dir, name)

	err := os.WriteFile(path, data, keyFileMode)
	if err != nil {
		tb.Fatalf("testpki: write file [%s]: %v", path, err)
	}

	return path
}

func ecdsaPrivateKey(tb testing.TB, curve elliptic.Curve) *ecdsa.PrivateKey {
	tb.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		tb.Fatalf("testpki: ecdsa generate key: %v", err)
	}

	return key
}

func rsaPrivateKey(tb testing.TB) *rsa.PrivateKey {
	tb.Helper()

	key, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		tb.Fatalf("testpki: rsa generate key: %v", err)
	}

	return key
}

func parseURIs(tb testing.TB, raw []string) []*url.URL {
	tb.Helper()

	uris := make([]*url.URL, 0, len(raw))

	for _, each := range raw {
		uri, err := url.Parse(each)
		if err != nil {
			tb.Fatalf("testpki: parse uri [%s]: %v", each, err)
		}

		uris = append(uris, uri)
	}

	return uris
}

// randomSerialNumber is a random 128-bit serial.
func randomSerialNumber(tb testing.TB) *big.Int {
	tb.Helper()

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), serialNumberBits))
	if err != nil {
		tb.Fatalf("testpki: random serial number: %v", err)
	}

	return serial
}

// newTemplate is an x509.Certificate with every field at its zero value but the
// serial number, for a caller to fill in the few it cares about.
//
// The fields are spelled out because the exhaustruct linter asks for it. That
// is worth one copy of this function and not two, which is most of why this
// package exists.
func newTemplate(tb testing.TB) *x509.Certificate {
	tb.Helper()

	return &x509.Certificate{
		SerialNumber: randomSerialNumber(tb),

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
		Issuer:                  newName(),
		Subject:                 newName(),

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

// newName is an empty distinguished name, spelled out for the same reason
// newTemplate is.
func newName() pkix.Name {
	return pkix.Name{
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
	}
}

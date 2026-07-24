package x509svid

import (
	"crypto/x509"
	"fmt"

	"github.com/tkngch/fizzled-go/internal/authn/spiffeid"
)

// Leaf represents X509 leaf-certificate with SVID information.
type Leaf struct {
	spiffeID    spiffeid.ID
	certificate *x509.Certificate
}

// NewLeaf builds an ID from a chain of certificates. The first entry in the
// rawCertificates is expected to be a leaf.
func NewLeaf(bundle *x509.CertPool, rawCertificates [][]byte) (Leaf, error) {
	certificates, err := parse(rawCertificates)
	if err != nil {
		return Leaf{}, fmt.Errorf("x509svid new: %w", err)
	}

	err = verify(bundle, certificates)
	if err != nil {
		return Leaf{}, fmt.Errorf("x509svid new: %w", err)
	}

	leaf, err := validate(certificates)
	if err != nil {
		return Leaf{}, fmt.Errorf("x509svid new: %w", err)
	}

	return leaf, nil
}

// ID is the SPIFFE ID.
func (l Leaf) ID() spiffeid.ID {
	return l.spiffeID
}

// Certificate is X509 certificate.
func (l Leaf) Certificate() *x509.Certificate {
	return l.certificate
}

func parse(rawCerts [][]byte) ([]*x509.Certificate, error) {
	certificates := make([]*x509.Certificate, len(rawCerts))
	for idx, raw := range rawCerts {
		certificate, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, fmt.Errorf("parse certificate %d: %w", idx, err)
		}

		certificates[idx] = certificate
	}

	return certificates, nil
}

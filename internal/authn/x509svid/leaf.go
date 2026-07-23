package x509svid

import (
	"crypto/x509"

	"github.com/tkngch/fizzled-go/internal/authn/spiffeid"
)

// Leaf is a verified X509-SVID leaf certificate together with the SPIFFE ID
// carried in its URI SAN. Only Verifier produces a Leaf, so holding one is
// evidence that the chain it came from anchored to the trust bundle.
type Leaf struct {
	spiffeID    spiffeid.ID
	certificate *x509.Certificate
}

// ID is the SPIFFE ID carried in the certificate's URI SAN.
func (l Leaf) ID() spiffeid.ID {
	return l.spiffeID
}

// Certificate is the leaf X509 certificate. The caller must treat it as
// read-only: it is shared with the connection the leaf was read from.
func (l Leaf) Certificate() *x509.Certificate {
	return l.certificate
}

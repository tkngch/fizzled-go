package x509svid

import (
	"crypto/x509"

	"github.com/tkngch/fizzled-go/internal/authn/spiffeid"
)

type ID struct {
	spiffeID       spiffeid.ID
	certificates []x509.Certificate
}

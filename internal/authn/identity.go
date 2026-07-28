package authn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"path/filepath"
	"slices"

	"github.com/tkngch/fizzled-go/internal/authn/spiffeid"
)

// The path components of the two identities in this trust domain:
//
//	spiffe://fizzled.internal/server
//	spiffe://fizzled.internal/client/agent/<agent identifier>
//
// clientAgentID and serverIdentity are the only readers, so between them this
// block is the whole identity shape the package accepts.
const (
	pathServer = "server"
	pathClient = "client"
	pathAgent  = "agent"

	serverPathComponents = 1
	clientPathComponents = 3
)

// leafPolicy asserts the issuance policy on a leaf that x509svid has
// already verified against the trust bundle. Every SVID is issued with both the
// server-auth and client-auth EKUs and an ECDSA P-256 key, so
// the same policy applies to both sides of the connection: the server/client
// separation is carried by the URI-SAN path, not by the EKU.
//
// These checks live here rather than in x509svid because they are issuance
// policy, not requirements of the SPIFFE X509-SVID standard.
func leafPolicy(certificate *x509.Certificate) error {
	if !slices.Contains(certificate.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return fmt.Errorf("leaf policy: %w", ErrMissingServerAuth)
	}

	if !slices.Contains(certificate.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return fmt.Errorf("leaf policy: %w", ErrMissingClientAuth)
	}

	publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("leaf policy: %w", ErrKeyNotECDSA)
	}

	if publicKey.Curve != elliptic.P256() {
		return fmt.Errorf("leaf policy: %w", ErrKeyNotP256)
	}

	return nil
}

// clientAgentID asserts that spiffeID is a valid client SVID identity and
// returns the agent id from the path component.
func clientAgentID(spiffeID spiffeid.ID) (AgentID, error) {
	if spiffeID.TrustDomain() != TrustDomain {
		return "", fmt.Errorf("client agent id [%s]: %w", spiffeID, ErrWrongTrustDomain)
	}

	components := spiffeID.PathComponents()
	if len(components) != clientPathComponents ||
		components[0] != pathClient ||
		components[1] != pathAgent {
		return "", fmt.Errorf("client agent id [%s]: %w", spiffeID, ErrUnexpectedIdentity)
	}

	agentID, err := NewAgentID(components[2])
	if err != nil {
		return "", fmt.Errorf("client agent id [%s]: %w", spiffeID, err)
	}

	return agentID, nil
}

// serverIdentity asserts that spiffeID is the valid server SVID identity. It is
// the counterpart of clientAgentID: the server SVID carries no agent id, so
// there is nothing to return but the verdict.
func serverIdentity(spiffeID spiffeid.ID) error {
	if spiffeID.TrustDomain() != TrustDomain {
		return fmt.Errorf("server identity [%s]: %w", spiffeID, ErrWrongTrustDomain)
	}

	components := spiffeID.PathComponents()
	if len(components) != serverPathComponents || components[0] != pathServer {
		return fmt.Errorf("server identity [%s]: %w", spiffeID, ErrUnexpectedIdentity)
	}

	return nil
}

// loadIdentity reads the SVID at certPath/keyPath as the key pair a connection
// presents, together with the certificate chain it carries. It asserts nothing
// about either: that is clientSVID's and serverSVID's job.
//
// The chain is parsed out of the DER the key pair carries rather than read from
// tls.Certificate.Leaf, which LoadX509KeyPair populates but GODEBUG
// x509keypairleaf=0 turns back off.
func loadIdentity(certPath, keyPath string) (tls.Certificate, []*x509.Certificate, error) {
	identity, err := tls.LoadX509KeyPair(filepath.Clean(certPath), filepath.Clean(keyPath))
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("load key-pair [%s]: %w", certPath, err)
	}

	chain := make([]*x509.Certificate, 0, len(identity.Certificate))

	for _, der := range identity.Certificate {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return tls.Certificate{}, nil, fmt.Errorf("parse key-pair [%s]: %w", certPath, err)
		}

		chain = append(chain, certificate)
	}

	return identity, chain, nil
}

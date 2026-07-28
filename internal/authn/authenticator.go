package authn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"time"

	"github.com/tkngch/fizzled-go/internal/authn/x509svid"
)

const (
	// TrustDomain is the trust-domain of this app.
	TrustDomain = "fizzled.internal"

	// skew is the clock-skew tolerance applied when checking certificate validity,
	// so minor clock differences between client and server do not spuriously reject
	// otherwise-valid certificates.
	skew = 2 * time.Minute

	// serialNumberBase is the base a certificate serial number is written in.
	serialNumberBase = 16
)

// peerSide names the side of a connection an audit line is about: the peer that
// was verified, not the side doing the verifying.
type peerSide string

const (
	peerClient peerSide = "client"
	peerServer peerSide = "server"
)

// Authenticator owns the mTLS policy. It builds the tls.Config for either side
// of a connection, and resolves the authenticated agent id from an established
// one.
//
// An Authenticator is immutable after construction and safe for concurrent use.
type Authenticator struct {
	verifier *x509svid.Verifier
	logger   *slog.Logger
}

// NewAuthenticator reads the trust bundle at caPath and returns an
// Authenticator anchored to it.
//
// logger records the outcome of every connection the Authenticator verifies,
// and the bundle this one was built from. A nil logger discards them.
func NewAuthenticator(caPath string, logger *slog.Logger) (*Authenticator, error) {
	bundle, err := loadTrustBundle(caPath)
	if err != nil {
		return nil, fmt.Errorf("new authenticator: %w", err)
	}

	verifier, err := x509svid.NewVerifier(bundle.roots, skew)
	if err != nil {
		return nil, fmt.Errorf("new authenticator: %w", err)
	}

	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	authenticator := &Authenticator{verifier: verifier, logger: logger}
	authenticator.auditTrustBundle(caPath, bundle)

	return authenticator, nil
}

// ClientConfig builds the client-side mTLS configuration. It presents the
// client SVID loaded from certPath/keyPath and verifies the server SVID against
// the trust bundle. Go's hostname and built-in chain verification are skipped,
// because our SVIDs carry no DNS SAN, so the verification callback installed
// here performs the full verification instead.
//
// The SVID being presented is verified as this side's identity before the
// configuration is returned, so a client that cannot be authenticated by the
// server reports an error here rather than at the first handshake.
func (a *Authenticator) ClientConfig(certPath, keyPath string) (*tls.Config, error) {
	identity, chain, err := loadIdentity(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("client config: %w", err)
	}

	// The same call the server on the other side will make on this chain, so
	// the standard cannot drift between the two sides.
	_, _, err = a.clientSVID(chain)
	if err != nil {
		return nil, fmt.Errorf("client config: %w", err)
	}

	return newClientTLSConfig(identity, a.verifyServerPeer), nil
}

// ServerConfig builds the server-side mTLS configuration. It presents the
// server SVID loaded from certPath/keyPath and requires every client to present
// a certificate, which the verification callback installed here validates
// against the trust bundle. Go's built-in client-certificate verification is
// deliberately not used (RequireAnyClientCert, no ClientCAs): it runs at
// time.Now() and would reject a certificate inside the clock-skew window before
// verifyClientPeer ever saw it.
//
// The SVID being presented is verified as this side's identity before the
// configuration is returned, so a server that no client could accept fails at
// start-up rather than on every connection.
//
// Session tickets are disabled, so every connection is a full handshake. This
// deployment does not support resumption, and the client side keeps no session
// cache to resume from.
func (a *Authenticator) ServerConfig(certPath, keyPath string) (*tls.Config, error) {
	identity, chain, err := loadIdentity(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("server config: %w", err)
	}

	// The same call every client will make on this chain, so the standard
	// cannot drift between the two sides.
	_, err = a.serverSVID(chain)
	if err != nil {
		return nil, fmt.Errorf("server config: %w", err)
	}

	return newServerTLSConfig(identity, a.verifyClientPeer), nil
}

// Authenticate resolves the authenticated agent id from an established
// connection, for the RPC layer to hand to authz and registry.
//
// It re-verifies the peer chain against the trust bundle rather than trusting
// the handshake, so the answer is sound whatever tls.Config produced state: a
// connection that presented no certificate, a chain that does not anchor to the
// bundle, and a peer that does not have a valid client SVID all yield an error.
// The cost is one chain verification per call, which is why the RPC layer
// should call it once per stream rather than once per message.
//
// Authenticate writes no audit line: the connection it reads was already
// recorded, once, by the verification the handshake ran.
func (a *Authenticator) Authenticate(state tls.ConnectionState) (AgentID, error) {
	_, agentID, err := a.clientSVID(state.PeerCertificates)
	if err != nil {
		return "", fmt.Errorf("authenticate: %w", err)
	}

	return agentID, nil
}

// verifyClientPeer is the tls.Config.VerifyConnection callback for the server
// side. It verifies the peer's certificate chain against the trust bundle and
// asserts the peer presents a valid client SVID. VerifyConnection (rather
// than VerifyPeerCertificate) also runs on resumed sessions, so the identity
// check cannot be bypassed by session resumption.
func (a *Authenticator) verifyClientPeer(state tls.ConnectionState) error {
	leaf, agentID, err := a.clientSVID(state.PeerCertificates)
	if err != nil {
		a.auditReject(peerClient, state, err)

		return fmt.Errorf("verify client peer: %w", err)
	}

	a.auditAccept(peerClient, leaf, slog.String("agent_id", string(agentID)))

	return nil
}

// verifyServerPeer is the tls.Config.VerifyConnection callback for the client
// side. It verifies the peer's certificate chain against the trust bundle and
// asserts the peer presents the valid server SVID.
func (a *Authenticator) verifyServerPeer(state tls.ConnectionState) error {
	leaf, err := a.serverSVID(state.PeerCertificates)
	if err != nil {
		a.auditReject(peerServer, state, err)

		return fmt.Errorf("verify server peer: %w", err)
	}

	a.auditAccept(peerServer, leaf)

	return nil
}

// clientSVID verifies a certificate chain and resolves the client SVID identity
// it carries.
//
// Authenticate, the server-side verification callback, and the check
// ClientConfig runs on the SVID this process is about to present all come
// through this one call. The three cannot drift apart, and a client cannot be
// built only for the server to turn away.
func (a *Authenticator) clientSVID(chain []*x509.Certificate) (x509svid.Leaf, AgentID, error) {
	leaf, err := a.leaf(chain)
	if err != nil {
		return x509svid.Leaf{}, "", fmt.Errorf("client svid: %w", err)
	}

	agentID, err := clientAgentID(leaf.ID())
	if err != nil {
		return x509svid.Leaf{}, "", fmt.Errorf("client svid: %w", err)
	}

	return leaf, agentID, nil
}

// serverSVID verifies a certificate chain and asserts it carries the valid
// server SVID identity. It is the counterpart of clientSVID, shared by the
// client-side verification callback and by ServerConfig for the same reason;
// the server SVID carries no agent id, so there is nothing to return but the
// leaf.
func (a *Authenticator) serverSVID(chain []*x509.Certificate) (x509svid.Leaf, error) {
	leaf, err := a.leaf(chain)
	if err != nil {
		return x509svid.Leaf{}, fmt.Errorf("server svid: %w", err)
	}

	err = serverIdentity(leaf.ID())
	if err != nil {
		return x509svid.Leaf{}, fmt.Errorf("server svid: %w", err)
	}

	return leaf, nil
}

// leaf verifies a certificate chain against the trust bundle and applies the
// issuance policy to the leaf. It is the step shared by every identity.
func (a *Authenticator) leaf(certificates []*x509.Certificate) (x509svid.Leaf, error) {
	leaf, err := a.verifier.Verify(certificates)
	if err != nil {
		return x509svid.Leaf{}, fmt.Errorf("leaf: %w", err)
	}

	err = leafPolicy(leaf.Certificate())
	if err != nil {
		return x509svid.Leaf{}, fmt.Errorf("leaf: %w", err)
	}

	return leaf, nil
}

// auditTrustBundle records what this process will anchor chains to. It does not
// log certificate detail beyond a count and a date.
func (a *Authenticator) auditTrustBundle(path string, loaded loadedBundle) {
	a.logger.LogAttrs(
		context.Background(),
		slog.LevelInfo,
		"trust bundle loaded",
		slog.String("path", path),
		slog.Int("roots", len(loaded.roots)),
		slog.Time("expires", loaded.earliestExpiry),
	)
}

// auditAccept records an accepted peer. It carries the verified SPIFFE ID and
// the certificate serial number, and whatever the caller's side adds.
//
// The context is a background one because the audit runs under
// tls.Config.VerifyConnection, which does not have a context.
func (a *Authenticator) auditAccept(peer peerSide, leaf x509svid.Leaf, extra ...slog.Attr) {
	attributes := append(
		[]slog.Attr{
			slog.String("peer", string(peer)),
			slog.String("spiffe_id", leaf.ID().String()),
			slog.String("serial", serialNumber(leaf.Certificate())),
		},
		extra...,
	)

	a.logger.LogAttrs(context.Background(), slog.LevelInfo, "peer authenticated", attributes...)
}

// auditReject records a rejected peer, with the reason. The SPIFFE ID is not a
// field of its own here: on this path it is unverified, and err already names
// it when it is known at all. The serial number is the one the peer presented,
// which is enough to find the certificate it presented again.
func (a *Authenticator) auditReject(peer peerSide, state tls.ConnectionState, err error) {
	attributes := []slog.Attr{
		slog.String("peer", string(peer)),
		slog.String("error", err.Error()),
	}

	if len(state.PeerCertificates) > 0 {
		attributes = append(
			attributes,
			slog.String("presented_serial", serialNumber(state.PeerCertificates[0])),
		)
	}

	a.logger.LogAttrs(context.Background(), slog.LevelWarn, "peer rejected", attributes...)
}

// serialNumber is a certificate's serial number, as the hexadecimal an operator
// reading an audit line can match against the certificate itself.
func serialNumber(certificate *x509.Certificate) string {
	return certificate.SerialNumber.Text(serialNumberBase)
}

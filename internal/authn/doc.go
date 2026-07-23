// Package authn verifies an agent.
//
// It owns the mTLS policy for the fizzled.internal trust domain and the two
// identities in it:
//
//	spiffe://fizzled.internal/server
//	spiffe://fizzled.internal/client/agent/<agent identifier>
//
// An Authenticator reads the trust bundle once and is then the single entry
// point: ClientConfig and ServerConfig build the two sides of the connection,
// and Authenticate resolves the agent id from an established one. Because
// Authenticate re-verifies the peer chain against the same bundle, an agent id
// can only be obtained from a chain that anchors to it.
//
// A misconfiguration is reported when the Authenticator or a tls.Config is
// built, not on the connection that trips over it: the trust bundle is parsed
// block by block, and each side verifies the SVID it is about to present by the
// same standard its peer will apply to it.
//
// The Authenticator is also the audit point for authentication. Its
// verification callbacks record the outcome of every connection, accepted or
// rejected, on the logger given to NewAuthenticator.
//
// Both sides verify their peer in a tls.Config.VerifyConnection callback rather
// than through Go's built-in verification: SVIDs carry no DNS SAN to match, and
// the chain must be checked with a clock-skew tolerance that Go's
// time.Now()-based check does not allow.
//
// Every connection is a full handshake and does not support resumption.
// ServerConfig disables session tickets, and the callback is VerifyConnection
// and not VerifyPeerCertificate.
//
// The SVID a process presents is read once, when ClientConfig or ServerConfig
// builds the configuration, and the trust bundle once, when the Authenticator
// is built. Rotating either therefore takes effect at the next start-up and not
// on the running process. Because the bundle is read once, the expiry of its
// nearest root is the date this process has to be restarted by, and
// NewAuthenticator writes it to the logger.
//
// The generic SPIFFE work is delegated to the domain-free subpackages: spiffeid
// parses SPIFFE IDs, x509svid verifies X509-SVID chains. What lives here is the
// fizzled-specific part: the trust domain, the skew tolerance, the issuance
// policy in leafPolicy, the two identity shapes, and AgentID.
package authn

package authn

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tkngch/fizzled-go/internal/authn/x509svid"
)

// TrustDomain is the trust-domain of this app.
const TrustDomain = "fizzled.internal"

var (

	// ErrEmptyTrustBundle indicates that the trust bundle is empty.
	ErrEmptyTrustBundle = errors.New("empty trust bundle")

	// ErrWrongTrustDomain indicates that the trust-domain of SPIFFE ID is not
	// "fizzled.internal".
	ErrWrongTrustDomain = errors.New("wrong trust domain")

	// ErrUnexpectedIdentity indicates that the path components in SPIFFE ID do
	// not match server or client components.
	ErrUnexpectedIdentity = errors.New("unexpected identity")
)

// ClientConfig builds the client-side mTLS configuration. It presents the
// client SVID loaded from certPath/keyPath and verifies the server SVID against
// the trust bundle at caPath. InsecureSkipVerify disables Go's hostname and
// built-in chain verification -- our SVIDs carry no DNS SAN, and the chain must
// be checked with clock-skew tolerance -- so verifyServerPeer performs the full
// verification instead.
func ClientConfig(certPath, keyPath, caPath string) (*tls.Config, error) {
	bundle, err := trustBundle(caPath)
	if err != nil {
		return nil, fmt.Errorf("client config: %w", err)
	}

	config, err := newTLSConfig(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("client config: %w", err)
	}

	config.VerifyConnection = verifyServerPeer(bundle)
	config.InsecureSkipVerify = true

	return config, nil
}

// ServerConfig builds the server-side mTLS configuration. It presents the
// server SVID loaded from certPath/keyPath and requires every client to present
// a certificate, which verifyClientPeer validates against the trust bundle at
// caPath as a fizzled client SVID. Go's built-in client-certificate
// verification is deliberately not used (RequireAnyClientCert, no ClientCAs):
// it runs at time.Now() and would reject a certificate inside the clock-skew
// window before verifyClientPeer ever saw it.
func ServerConfig(certPath, keyPath, caPath string) (*tls.Config, error) {
	bundle, err := trustBundle(caPath)
	if err != nil {
		return nil, fmt.Errorf("server config: %w", err)
	}

	config, err := newTLSConfig(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("server config: %w", err)
	}

	config.VerifyConnection = verifyClientPeer(bundle)
	config.ClientAuth = tls.RequireAnyClientCert

	return config, nil
}

// verifyClientPeer returns a tls.Config.VerifyConnection callback for the server
// side. It verifies the peer's certificate chain against bundle and asserts the
// peer presents a fizzled client SVID. VerifyConnection (rather than
// VerifyPeerCertificate) also runs on resumed sessions, so the identity check
// cannot be bypassed by session resumption.
func verifyClientPeer(bundle *x509.CertPool) func(tls.ConnectionState) error {
	return func(state tls.ConnectionState) error {
		leaf, err := leafFromConnectionState(bundle, state)
		if err != nil {
			return fmt.Errorf("verify client peer: %w", err)
		}

		if leaf.ID().TrustDomain() != TrustDomain {
			return fmt.Errorf("verify client peer: %w", ErrWrongTrustDomain)
		}

		components := leaf.ID().PathComponents()
		if len(components) != 3 || components[0] != "client" || components[1] != "agent" {
			return fmt.Errorf("verify client peer: %w", ErrUnexpectedIdentity)
		}

		_, err = NewAgentID(components[2])
		if err != nil {
			return fmt.Errorf("verify client peer: %w", err)
		}

		return nil
	}
}

// verifyServerPeer returns a tls.Config.VerifyConnection callback for the client
// side. It verifies the peer's certificate chain against bundle and asserts the
// peer presents the fizzled server SVID.
func verifyServerPeer(bundle *x509.CertPool) func(tls.ConnectionState) error {
	return func(state tls.ConnectionState) error {
		leaf, err := leafFromConnectionState(bundle, state)
		if err != nil {
			return fmt.Errorf("verify server peer: %w", err)
		}

		if leaf.ID().TrustDomain() != TrustDomain {
			return fmt.Errorf("validate server peer: %w", ErrWrongTrustDomain)
		}

		components := leaf.ID().PathComponents()
		if len(components) != 1 || components[0] != "server" {
			return fmt.Errorf("validate server peer: %w", ErrUnexpectedIdentity)
		}

		return nil
	}
}

// trustBundle reads the PEM file at path and returns a pool of trusted roots.
func trustBundle(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("trust bundle [%s]: %w", path, err)
	}

	pool := x509.NewCertPool()

	ok := pool.AppendCertsFromPEM(pem)
	if !ok {
		// false == zero certs parsed
		// Note: AppendCertsFromPEM silently skips individual malformed blocks
		return nil, fmt.Errorf("trust bundle [%s]: %w", path, ErrEmptyTrustBundle)
	}

	return pool, nil
}

// leafFromConnectionState verifies the peer certificate chain from a completed
// handshake against bundle and returns the validated SVID leaf.
func leafFromConnectionState(
	bundle *x509.CertPool,
	state tls.ConnectionState,
) (x509svid.Leaf, error) {
	rawCerts := make([][]byte, len(state.PeerCertificates))
	for index, certificate := range state.PeerCertificates {
		rawCerts[index] = certificate.Raw
	}

	leaf, err := x509svid.NewLeaf(bundle, rawCerts)
	if err != nil {
		return x509svid.Leaf{}, fmt.Errorf("leaf from connection state: %w", err)
	}

	return leaf, nil
}

func newTLSConfig(certPath, keyPath string) (*tls.Config, error) {
	identity, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("new tls config: load key-pair: %w", err)
	}

	config := &tls.Config{
		// Certificates contains one or more certificate chains to present to the
		// other side of the connection. The first certificate compatible with the
		// peer's requirements is selected automatically.
		Certificates: []tls.Certificate{identity},
		// MinVersion contains the minimum TLS version that is acceptable.
		MinVersion: tls.VersionTLS12,
		// MaxVersion contains the maximum TLS version that is acceptable.
		MaxVersion: tls.VersionTLS13,
		// CipherSuites is a list of enabled TLS 1.0–1.2 cipher suites. The order of
		// the list is ignored. Note that TLS 1.3 ciphersuites are not configurable.
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
		// Renegotiation controls what types of renegotiation are supported.
		Renegotiation: tls.RenegotiateNever,
		// ClientAuth determines the server's policy for TLS Client
		// Authentication.
		ClientAuth: tls.NoClientCert,
		// VerifyConnection, if not nil, is called after normal certificate
		// verification and after VerifyPeerCertificate by either a TLS client
		// or server. If it returns a non-nil error, the handshake is aborted
		// and that error results.
		VerifyConnection: nil,
		// InsecureSkipVerify controls whether a client verifies the server's
		// certificate chain and host name. If InsecureSkipVerify is true, crypto/tls
		// accepts any certificate presented by the server and any host name in that
		// certificate. In this mode, TLS is susceptible to machine-in-the-middle
		// attacks unless custom verification is used. This should be used only for
		// testing or in combination with VerifyConnection or VerifyPeerCertificate.
		InsecureSkipVerify: false,

		Rand:                                nil,
		Time:                                nil,
		NameToCertificate:                   map[string]*tls.Certificate{},
		GetCertificate:                      nil,
		GetClientCertificate:                nil,
		GetConfigForClient:                  nil,
		VerifyPeerCertificate:               nil,
		RootCAs:                             nil,
		NextProtos:                          []string{},
		ServerName:                          "",
		ClientCAs:                           nil,
		PreferServerCipherSuites:            true, // deprecated and ignored.
		SessionTicketsDisabled:              false,
		SessionTicketKey:                    [32]byte{},
		ClientSessionCache:                  nil,
		UnwrapSession:                       nil,
		WrapSession:                         nil,
		CurvePreferences:                    []tls.CurveID{},
		DynamicRecordSizingDisabled:         false,
		KeyLogWriter:                        nil,
		EncryptedClientHelloConfigList:      []byte{},
		EncryptedClientHelloRejectionVerify: nil,
		GetEncryptedClientHelloKeys:         nil,
		EncryptedClientHelloKeys:            []tls.EncryptedClientHelloKey{},
	}

	return config, nil
}

package authn_test

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tkngch/fizzled-go/internal/authn"
	"github.com/tkngch/fizzled-go/internal/authn/internal/testpki"
	"github.com/tkngch/fizzled-go/internal/authn/spiffeid"
	"github.com/tkngch/fizzled-go/internal/authn/x509svid"
)

const (
	serverURI = "spiffe://fizzled.internal/server"
	clientURI = "spiffe://fizzled.internal/client/agent/smith"
)

// readTimeout bounds the post-handshake read in drive, so a test cannot hang on
// a peer that neither writes nor closes.
const readTimeout = 5 * time.Second

func TestNewAuthenticator(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		authority := newCertificateAuthority(t)

		authenticator, err := authn.NewAuthenticator(
			testpki.WriteCertificate(t, t.TempDir(), "ca.crt", authority.Certificate),
			nil,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if authenticator == nil {
			t.Fatal("expected an authenticator, got nil")
		}
	})

	t.Run("missing trust bundle", func(t *testing.T) {
		t.Parallel()

		_, err := authn.NewAuthenticator(filepath.Join(t.TempDir(), "absent-ca.crt"), nil)
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
	})

	t.Run("empty trust bundle", func(t *testing.T) {
		t.Parallel()

		_, err := authn.NewAuthenticator(
			testpki.WriteFile(t, t.TempDir(), "empty-ca.crt", []byte{}),
			nil,
		)
		if !errors.Is(err, authn.ErrEmptyTrustBundle) {
			t.Fatalf("expected [%v], got [%v]", authn.ErrEmptyTrustBundle, err)
		}
	})

	// A file of prose is not an empty bundle: it is a file the operator meant
	// as a bundle, and the error says which of the two it is.
	t.Run("non-pem trust bundle", func(t *testing.T) {
		t.Parallel()

		_, err := authn.NewAuthenticator(
			testpki.WriteFile(t, t.TempDir(), "garbage-ca.crt", []byte("not a pem block")),
			nil,
		)
		if !errors.Is(err, authn.ErrBundleUnexpectedData) {
			t.Fatalf("expected [%v], got [%v]", authn.ErrBundleUnexpectedData, err)
		}
	})

	t.Run("several roots", func(t *testing.T) {
		t.Parallel()

		firstCA := newCertificateAuthority(t)
		secondCA := newCertificateAuthority(t)

		bundle := testpki.WriteFile(
			t,
			t.TempDir(),
			"ca.crt",
			slices.Concat(certificatePEM(firstCA), certificatePEM(secondCA)),
		)

		authenticator, err := authn.NewAuthenticator(bundle, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// A leaf under either root authenticates: the pool holds both.
		state := connectionState(t, secondCA, testpki.NewLeafOptions(clientURI))

		agentID, err := authenticator.Authenticate(state)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if agentID != authn.AgentID("smith") {
			t.Errorf("expected [smith], got [%s]", agentID)
		}
	})
}

// TestNewAuthenticatorAudit covers what NewAuthenticator writes about the
// bundle it read.
func TestNewAuthenticatorAudit(t *testing.T) {
	t.Parallel()

	var recorded bytes.Buffer

	// The second root outlives the first, so the line naming the earlier of the
	// two is the line naming the date the process has to be restarted by.
	soonOptions := testpki.NewAuthorityOptions()
	soonOptions.NotAfter = time.Now().Add(time.Hour)

	expiringCA := testpki.NewAuthority(t, soonOptions)
	lastingCA := newCertificateAuthority(t)

	path := testpki.WriteFile(
		t,
		t.TempDir(),
		"ca.crt",
		slices.Concat(certificatePEM(lastingCA), certificatePEM(expiringCA)),
	)

	_, err := authn.NewAuthenticator(path, newAuditLogger(&recorded))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entry := onlyAuditEntry(t, &recorded)

	requireAttribute(t, entry, "level", "INFO")
	requireAttribute(t, entry, "msg", "trust bundle loaded")
	requireAttribute(t, entry, "path", path)

	// JSON has one number type, so a count decodes as a float.
	if entry["roots"] != float64(2) {
		t.Errorf("expected [2] at [roots], got [%v]", entry["roots"])
	}

	expires, ok := entry["expires"].(string)
	if !ok {
		t.Fatalf("expected an expiry at [expires], got [%v]", entry["expires"])
	}

	logged, err := time.Parse(time.RFC3339, expires)
	if err != nil {
		t.Fatalf("unable to read the logged expiry [%s]: %v", expires, err)
	}

	if !logged.Equal(expiringCA.Certificate.NotAfter) {
		t.Errorf("expected [%s], got [%s]", expiringCA.Certificate.NotAfter, logged)
	}
}

// TestNewAuthenticatorRejectsBundle covers the trust bundle checks that
// AppendCertsFromPEM would have skipped in silence.
func TestNewAuthenticatorRejectsBundle(t *testing.T) {
	t.Parallel()

	t.Run("block is not a certificate", func(t *testing.T) {
		t.Parallel()

		authority := newCertificateAuthority(t)

		_, err := authn.NewAuthenticator(
			testpki.WriteKey(t, t.TempDir(), "ca.crt", authority.Key),
			nil,
		)
		if !errors.Is(err, authn.ErrBundleNotCertificate) {
			t.Fatalf("expected [%v], got [%v]", authn.ErrBundleNotCertificate, err)
		}
	})

	t.Run("block is not a parseable certificate", func(t *testing.T) {
		t.Parallel()

		block := &pem.Block{
			Type:    "CERTIFICATE",
			Headers: map[string]string{},
			Bytes:   []byte("not a certificate"),
		}

		_, err := authn.NewAuthenticator(
			testpki.WriteFile(t, t.TempDir(), "ca.crt", pem.EncodeToMemory(block)),
			nil,
		)
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
	})

	// pem.Decode reads a block with RFC-1421 headers, and
	// AppendCertsFromPEM skips one. A root annotated this way would anchor
	// chains here and nowhere else, so it is turned away rather than quietly
	// trusted. FuzzTrustBundle is what found this.
	t.Run("block carries pem headers", func(t *testing.T) {
		t.Parallel()

		headered := withPEMHeader(certificatePEM(newCertificateAuthority(t)))

		_, err := authn.NewAuthenticator(
			testpki.WriteFile(t, t.TempDir(), "ca.crt", headered),
			nil,
		)
		if !errors.Is(err, authn.ErrBundleBlockHasHeaders) {
			t.Fatalf("expected [%v], got [%v]", authn.ErrBundleBlockHasHeaders, err)
		}
	})

	t.Run("certificate is not a CA", func(t *testing.T) {
		t.Parallel()

		authority := newCertificateAuthority(t)
		leaf, _ := testpki.NewLeaf(t, authority, testpki.NewLeafOptions(serverURI))

		_, err := authn.NewAuthenticator(
			testpki.WriteCertificate(t, t.TempDir(), "ca.crt", leaf),
			nil,
		)
		if !errors.Is(err, x509svid.ErrSigningCertIsNotCA) {
			t.Fatalf("expected [%v], got [%v]", x509svid.ErrSigningCertIsNotCA, err)
		}
	})

	t.Run("certificate is another trust domain's", func(t *testing.T) {
		t.Parallel()

		authority := newCertificateAuthorityWithURIs(t, "spiffe://other.internal")

		_, err := authn.NewAuthenticator(
			testpki.WriteCertificate(t, t.TempDir(), "ca.crt", authority.Certificate),
			nil,
		)
		if !errors.Is(err, authn.ErrWrongTrustDomain) {
			t.Fatalf("expected [%v], got [%v]", authn.ErrWrongTrustDomain, err)
		}
	})

	t.Run("certificate uri is not a spiffe id", func(t *testing.T) {
		t.Parallel()

		authority := newCertificateAuthorityWithURIs(t, "https://fizzled.internal")

		_, err := authn.NewAuthenticator(
			testpki.WriteCertificate(t, t.TempDir(), "ca.crt", authority.Certificate),
			nil,
		)
		if !errors.Is(err, spiffeid.ErrNotSPIFFE) {
			t.Fatalf("expected [%v], got [%v]", spiffeid.ErrNotSPIFFE, err)
		}
	})

	// The two cases below are the rules a root must satisfy as a signing
	// certificate. A bundle that broke either of them used to load here and
	// then abort the first handshake in which a peer presented that root
	// alongside its leaf. The sentinels are x509svid's because the fault is the
	// same one, wherever the certificate is met.
	t.Run("certificate carries several uris", func(t *testing.T) {
		t.Parallel()

		authority := newCertificateAuthorityWithURIs(
			t,
			"spiffe://"+authn.TrustDomain,
			"spiffe://"+authn.TrustDomain+"/extra",
		)

		_, err := authn.NewAuthenticator(
			testpki.WriteCertificate(t, t.TempDir(), "ca.crt", authority.Certificate),
			nil,
		)
		if !errors.Is(err, x509svid.ErrCertHasMultipleURIs) {
			t.Fatalf("expected [%v], got [%v]", x509svid.ErrCertHasMultipleURIs, err)
		}
	})

	t.Run("certificate uri carries a path", func(t *testing.T) {
		t.Parallel()

		authority := newCertificateAuthorityWithURIs(t, "spiffe://"+authn.TrustDomain+"/ca")

		_, err := authn.NewAuthenticator(
			testpki.WriteCertificate(t, t.TempDir(), "ca.crt", authority.Certificate),
			nil,
		)
		if !errors.Is(err, x509svid.ErrSigningSPIFFEHasPath) {
			t.Fatalf("expected [%v], got [%v]", x509svid.ErrSigningSPIFFEHasPath, err)
		}
	})

	// A root that may not sign certificates is the third of those rules, and
	// the one the bundle used to miss. Nothing was unsafe about that: no chain
	// can anchor to such a root, because crypto/x509 refuses to check a
	// signature made by a parent without keyCertSign. It was the diagnosis that
	// suffered. The bundle loaded, and then every handshake died with
	// "certificate signed by unknown authority" — an error that points at the
	// peer's leaf, when the fault is in the file the operator wrote. This is
	// the package's whole bargain: a misconfiguration is reported when the
	// Authenticator is built, not on the connections that trip over it.
	t.Run("certificate may not sign certificates", func(t *testing.T) {
		t.Parallel()

		authority := newCertificateAuthorityWithKeyUsage(t, x509.KeyUsageCRLSign)

		_, err := authn.NewAuthenticator(
			testpki.WriteCertificate(t, t.TempDir(), "ca.crt", authority.Certificate),
			nil,
		)
		if !errors.Is(err, x509svid.ErrSigningCertMissingKeyCertSign) {
			t.Fatalf("expected [%v], got [%v]", x509svid.ErrSigningCertMissingKeyCertSign, err)
		}
	})
}

// TestAuthenticatePresentedRoot is the other side of the agreement those cases
// pin: a root this app accepts into its bundle is one a peer may present
// alongside its leaf, and one x509svid would accept from that peer. The two
// paths run the same rules because they call the same function, and this is
// what says so — it fails if the bundle is ever tightened or loosened past what
// x509svid asks of the same certificate.
//
// The agreement runs one way only. The bundle is the stricter of the two,
// because it also knows the trust domain, which x509svid deliberately does not:
// somebody else's root is a bundle this app must refuse and a signing
// certificate the standard has no quarrel with.
func TestAuthenticatePresentedRoot(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		authority func(tb testing.TB) testpki.Authority
		accepted  bool
	}{
		{
			name:      "no uri",
			authority: newCertificateAuthority,
			accepted:  true,
		},
		{
			name: "path-less uri in this trust domain",
			authority: func(tb testing.TB) testpki.Authority {
				tb.Helper()

				return newCertificateAuthorityWithURIs(tb, "spiffe://"+authn.TrustDomain)
			},
			accepted: true,
		},
		{
			name: "uri carrying a path",
			authority: func(tb testing.TB) testpki.Authority {
				tb.Helper()

				return newCertificateAuthorityWithURIs(tb, "spiffe://"+authn.TrustDomain+"/ca")
			},
			accepted: false,
		},
		{
			name: "several uris",
			authority: func(tb testing.TB) testpki.Authority {
				tb.Helper()

				return newCertificateAuthorityWithURIs(
					tb,
					"spiffe://"+authn.TrustDomain,
					"spiffe://"+authn.TrustDomain+"/extra",
				)
			},
			accepted: false,
		},
		{
			name: "may not sign certificates",
			authority: func(tb testing.TB) testpki.Authority {
				tb.Helper()

				return newCertificateAuthorityWithKeyUsage(tb, x509.KeyUsageCRLSign)
			},
			accepted: false,
		},
		{
			// The one the bundle refuses and x509svid does not.
			name: "another trust domain",
			authority: func(tb testing.TB) testpki.Authority {
				tb.Helper()

				return newCertificateAuthorityWithURIs(tb, "spiffe://other.internal")
			},
			accepted: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				authority := testCase.authority(t)

				authenticator, err := authn.NewAuthenticator(
					testpki.WriteCertificate(t, t.TempDir(), "ca.crt", authority.Certificate),
					nil,
				)

				if !testCase.accepted {
					if err == nil {
						t.Fatal("expected the bundle to be rejected, got nil")
					}

					return
				}

				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				// A root the bundle accepted is one x509svid accepts from a
				// peer presenting the same certificate.
				_, _, signingErr := x509svid.ValidateSigningCertificate(authority.Certificate)
				if signingErr != nil {
					t.Fatalf("the bundle accepted a root x509svid rejects: %v", signingErr)
				}

				// And so a peer may present it alongside its leaf.
				certificate, _ := testpki.NewLeaf(t, authority, testpki.NewLeafOptions(clientURI))

				var state tls.ConnectionState

				state.PeerCertificates = []*x509.Certificate{certificate, authority.Certificate}

				agentID, err := authenticator.Authenticate(state)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if agentID != authn.AgentID("smith") {
					t.Errorf("expected [smith], got [%s]", agentID)
				}
			},
		)
	}
}

// TestNewAuthenticatorRejectsBundleFile covers the shape of the file rather
// than the certificates in it. Each case writes a bundle carrying bytes that
// are not part of a block this app read, and each would otherwise load as the
// roots around it: pem.Decode scans forward for the next block it can read and
// drops whatever it passed over on the way. The root that went missing would
// then surface at a handshake rather than as the start-up error it is.
//
// The position of the damage is the point of the table. A check on what is left
// after the last block catches only the last of these.
func TestNewAuthenticatorRejectsBundleFile(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		bundle        func(t *testing.T) []byte
		expectedError error
	}{
		{
			name: "trailing data",
			bundle: func(t *testing.T) []byte {
				t.Helper()

				return slices.Concat(
					certificatePEM(newCertificateAuthority(t)),
					[]byte("trailing garbage\n"),
				)
			},
			expectedError: authn.ErrBundleUnexpectedData,
		},
		{
			name: "leading data",
			bundle: func(t *testing.T) []byte {
				t.Helper()

				return slices.Concat(
					[]byte("leading garbage\n"),
					certificatePEM(newCertificateAuthority(t)),
				)
			},
			expectedError: authn.ErrBundleUnexpectedData,
		},
		{
			name: "data between blocks",
			bundle: func(t *testing.T) []byte {
				t.Helper()

				return slices.Concat(
					certificatePEM(newCertificateAuthority(t)),
					[]byte("garbage between blocks\n"),
					certificatePEM(newCertificateAuthority(t)),
				)
			},
			expectedError: authn.ErrBundleUnexpectedData,
		},
		{
			name: "corrupted last block",
			bundle: func(t *testing.T) []byte {
				t.Helper()

				return slices.Concat(
					certificatePEM(newCertificateAuthority(t)),
					corruptFraming(certificatePEM(newCertificateAuthority(t))),
				)
			},
			expectedError: authn.ErrBundleUnexpectedData,
		},
		{
			name: "corrupted first block",
			bundle: func(t *testing.T) []byte {
				t.Helper()

				return slices.Concat(
					corruptFraming(certificatePEM(newCertificateAuthority(t))),
					certificatePEM(newCertificateAuthority(t)),
				)
			},
			expectedError: authn.ErrBundleUnexpectedData,
		},
		{
			// The framing is intact and the body is not, so pem.Decode drops
			// this block from inside the file: it leaves behind neither a
			// remainder nor a broken frame. Counting the begin markers is what
			// finds it.
			name: "block with a corrupted body",
			bundle: func(t *testing.T) []byte {
				t.Helper()

				return slices.Concat(
					corruptBody(t, certificatePEM(newCertificateAuthority(t))),
					certificatePEM(newCertificateAuthority(t)),
				)
			},
			expectedError: authn.ErrBundleBlockDropped,
		},
		{
			// Cut short mid-block: the frame opens and never closes, so
			// pem.Decode reads no block at all where one plainly begins.
			name: "truncated block",
			bundle: func(t *testing.T) []byte {
				t.Helper()

				truncated, _, _ := bytes.Cut(
					certificatePEM(newCertificateAuthority(t)),
					[]byte("-----END "),
				)

				return truncated
			},
			expectedError: authn.ErrBundleBlockDropped,
		},
		{
			name: "duplicated block",
			bundle: func(t *testing.T) []byte {
				t.Helper()
				encoded := certificatePEM(newCertificateAuthority(t))

				return slices.Concat(encoded, encoded)
			},
			expectedError: authn.ErrBundleDuplicateCertificate,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				_, err := authn.NewAuthenticator(
					testpki.WriteFile(t, t.TempDir(), "ca.crt", testCase.bundle(t)),
					nil,
				)
				if !errors.Is(err, testCase.expectedError) {
					t.Fatalf("expected [%v], got [%v]", testCase.expectedError, err)
				}
			},
		)
	}
}

// corruptFraming takes a dash off a PEM block's begin line, so that pem.Decode
// no longer reads it as a block at all.
func corruptFraming(encoded []byte) []byte {
	return bytes.Replace(encoded, []byte("-----BEGIN "), []byte("----BEGIN "), 1)
}

// corruptBody replaces the first byte of a PEM block's base64 body with one
// that is not base64, so that the block's framing survives and its content does
// not.
func corruptBody(tb testing.TB, encoded []byte) []byte {
	tb.Helper()

	_, body, found := bytes.Cut(encoded, []byte("-----\n"))
	if !found || len(body) == 0 {
		tb.Fatalf("corrupt body: no base64 body in [%s]", encoded)
	}

	corrupted := bytes.Clone(encoded)
	corrupted[len(encoded)-len(body)] = '!'

	return corrupted
}

// withPEMHeader adds an RFC-1421 header to a PEM block, leaving its framing and
// body intact. pem.Decode reads the block; AppendCertsFromPEM skips it.
func withPEMHeader(encoded []byte) []byte {
	return bytes.Replace(encoded, []byte("-----\n"), []byte("-----\nX-Test: 1\n"), 1)
}

func TestServerConfig(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		authority := newCertificateAuthority(t)
		authenticator := newAuthenticator(t, authority)
		cert, key := testpki.NewLeafFiles(t, authority, testpki.NewLeafOptions(serverURI))

		config, err := authenticator.ServerConfig(cert, key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if config.VerifyConnection == nil {
			t.Error("expected VerifyConnection to be set")
		}

		if config.ClientAuth != tls.RequireAnyClientCert {
			t.Errorf("expected RequireAnyClientCert, got [%v]", config.ClientAuth)
		}

		// The server verifies its peer in the callback above, so it has no use
		// for skipping a verification it never asked Go to make.
		if config.InsecureSkipVerify {
			t.Error("expected InsecureSkipVerify to be false")
		}

		// The server is the side that issues tickets, so it is the side that
		// decides there is no resumption.
		if !config.SessionTicketsDisabled {
			t.Error("expected SessionTicketsDisabled to be true")
		}

		requireTransportPolicy(t, config)
	})

	t.Run("missing key pair", func(t *testing.T) {
		t.Parallel()

		authority := newCertificateAuthority(t)
		authenticator := newAuthenticator(t, authority)
		dir := t.TempDir()

		_, err := authenticator.ServerConfig(
			filepath.Join(dir, "absent.crt"),
			filepath.Join(dir, "absent.key"),
		)
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
	})

	t.Run("client svid", func(t *testing.T) {
		t.Parallel()

		authority := newCertificateAuthority(t)
		authenticator := newAuthenticator(t, authority)
		cert, key := testpki.NewLeafFiles(t, authority, testpki.NewLeafOptions(clientURI))

		_, err := authenticator.ServerConfig(cert, key)
		if !errors.Is(err, authn.ErrUnexpectedIdentity) {
			t.Fatalf("expected [%v], got [%v]", authn.ErrUnexpectedIdentity, err)
		}
	})

	// The server identity is exactly one path component. A trailing one is the
	// only way past every other check in the shape, so it is what exercises the
	// count rather than the names.
	t.Run("server svid with a trailing path component", func(t *testing.T) {
		t.Parallel()

		authority := newCertificateAuthority(t)
		authenticator := newAuthenticator(t, authority)
		cert, key := testpki.NewLeafFiles(
			t,
			authority,
			testpki.NewLeafOptions(serverURI+"/extra"),
		)

		_, err := authenticator.ServerConfig(cert, key)
		if !errors.Is(err, authn.ErrUnexpectedIdentity) {
			t.Fatalf("expected [%v], got [%v]", authn.ErrUnexpectedIdentity, err)
		}
	})
}

// TestConfigRejectsOwnSVID covers the check each side runs on the SVID it is
// about to present. Without it these misconfigurations would start a process
// that no peer can talk to, and say so only on the first connection.
func TestConfigRejectsOwnSVID(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		options func(opts *testpki.LeafOptions)
	}{
		{
			name: "expired beyond the skew",
			options: func(opts *testpki.LeafOptions) {
				opts.NotBefore = time.Now().Add(-2 * time.Hour)
				opts.NotAfter = time.Now().Add(-time.Hour)
			},
		},
		{
			name: "key off the P-256 curve",
			options: func(opts *testpki.LeafOptions) {
				opts.Curve = elliptic.P384()
			},
		},
		{
			name: "missing the client-auth EKU",
			options: func(opts *testpki.LeafOptions) {
				opts.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			},
		},
	}

	// Both constructors run the same check on the SVID they are handed, and
	// differ only in the identity shape they expect of it, so each case is put
	// to both. A method expression names the constructor under test.
	sides := []struct {
		name   string
		uri    string
		config func(*authn.Authenticator, string, string) (*tls.Config, error)
	}{
		{name: "server", uri: serverURI, config: (*authn.Authenticator).ServerConfig},
		{name: "client", uri: clientURI, config: (*authn.Authenticator).ClientConfig},
	}

	for _, side := range sides {
		for _, testCase := range testCases {
			t.Run(
				side.name+": "+testCase.name,
				func(t *testing.T) {
					t.Parallel()

					authority := newCertificateAuthority(t)
					authenticator := newAuthenticator(t, authority)

					opts := testpki.NewLeafOptions(side.uri)
					testCase.options(&opts)

					cert, key := testpki.NewLeafFiles(t, authority, opts)

					_, err := side.config(authenticator, cert, key)
					if err == nil {
						t.Fatal("expected an error, got nil")
					}
				},
			)
		}
	}

	t.Run("issued by another ca", func(t *testing.T) {
		t.Parallel()

		authority := newCertificateAuthority(t)
		authenticator := newAuthenticator(t, authority)

		otherCA := newCertificateAuthority(t)
		cert, key := testpki.NewLeafFiles(t, otherCA, testpki.NewLeafOptions(serverURI))

		_, err := authenticator.ServerConfig(cert, key)

		_, ok := errors.AsType[x509.UnknownAuthorityError](err)
		if !ok {
			t.Fatalf("expected an unknown-authority error, got [%v]", err)
		}
	})

	// LoadX509KeyPair parses only the leaf of the chain it reads, so a
	// certificate file can load with an intermediate that is not a certificate
	// at all. Parsing the whole chain is what catches it.
	t.Run("chain carries an unparseable certificate", func(t *testing.T) {
		t.Parallel()

		authority := newCertificateAuthority(t)
		authenticator := newAuthenticator(t, authority)

		leaf, key := testpki.NewLeaf(t, authority, testpki.NewLeafOptions(serverURI))

		garbage := &pem.Block{
			Type:    "CERTIFICATE",
			Headers: map[string]string{},
			Bytes:   []byte("not a certificate"),
		}

		dir := t.TempDir()

		certFile := testpki.WriteFile(
			t,
			dir,
			"certificate.crt",
			slices.Concat(testpki.CertificatePEM(leaf), pem.EncodeToMemory(garbage)),
		)

		_, err := authenticator.ServerConfig(
			certFile,
			testpki.WriteKey(t, dir, "private-key.key", key),
		)
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
	})
}

func TestClientConfig(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		authority := newCertificateAuthority(t)
		authenticator := newAuthenticator(t, authority)
		cert, key := testpki.NewLeafFiles(t, authority, testpki.NewLeafOptions(clientURI))

		config, err := authenticator.ClientConfig(cert, key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if config.VerifyConnection == nil {
			t.Error("expected VerifyConnection to be set")
		}

		if !config.InsecureSkipVerify {
			t.Error("expected InsecureSkipVerify to be true")
		}

		requireTransportPolicy(t, config)
	})

	t.Run("missing key pair", func(t *testing.T) {
		t.Parallel()

		authority := newCertificateAuthority(t)
		authenticator := newAuthenticator(t, authority)
		dir := t.TempDir()

		_, err := authenticator.ClientConfig(
			filepath.Join(dir, "absent.crt"),
			filepath.Join(dir, "absent.key"),
		)
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
	})

	t.Run("server svid", func(t *testing.T) {
		t.Parallel()

		authority := newCertificateAuthority(t)
		authenticator := newAuthenticator(t, authority)
		cert, key := testpki.NewLeafFiles(t, authority, testpki.NewLeafOptions(serverURI))

		_, err := authenticator.ClientConfig(cert, key)
		if !errors.Is(err, authn.ErrUnexpectedIdentity) {
			t.Fatalf("expected [%v], got [%v]", authn.ErrUnexpectedIdentity, err)
		}
	})
}

func TestAuthenticate(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		uris          []string
		expectedID    authn.AgentID
		expectedError error
	}{
		{
			name:          "valid client svid",
			uris:          []string{clientURI},
			expectedID:    "smith",
			expectedError: nil,
		},
		{
			name:          "wrong trust domain",
			uris:          []string{"spiffe://other.internal/client/agent/smith"},
			expectedID:    "",
			expectedError: authn.ErrWrongTrustDomain,
		},
		{
			name:          "server identity",
			uris:          []string{serverURI},
			expectedID:    "",
			expectedError: authn.ErrUnexpectedIdentity,
		},
		{
			name:          "too few path components",
			uris:          []string{"spiffe://fizzled.internal/client/agent"},
			expectedID:    "",
			expectedError: authn.ErrUnexpectedIdentity,
		},
		{
			name:          "wrong second component",
			uris:          []string{"spiffe://fizzled.internal/client/worker/smith"},
			expectedID:    "",
			expectedError: authn.ErrUnexpectedIdentity,
		},
		{
			name:          "invalid agent id",
			uris:          []string{"spiffe://fizzled.internal/client/agent/smith.jones"},
			expectedID:    "",
			expectedError: authn.ErrInvalidAgentID,
		},
		{
			name:          "no uri",
			uris:          nil,
			expectedID:    "",
			expectedError: x509svid.ErrCertHasNoURI,
		},
		{
			name: "multiple uris",
			uris: []string{
				clientURI,
				"spiffe://fizzled.internal/client/agent/jones",
			},
			expectedID:    "",
			expectedError: x509svid.ErrCertHasMultipleURIs,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				authority := newCertificateAuthority(t)
				authenticator := newAuthenticator(t, authority)

				opts := testpki.NewLeafOptions(testCase.uris...)
				state := connectionState(t, authority, opts)

				agentID, err := authenticator.Authenticate(state)
				if !errors.Is(err, testCase.expectedError) {
					t.Fatalf("expected [%v], got [%v]", testCase.expectedError, err)
				}

				if agentID != testCase.expectedID {
					t.Errorf("expected [%s], got [%s]", testCase.expectedID, agentID)
				}
			},
		)
	}
}

// TestAuthenticateRejectsIssuancePolicyViolation covers leafPolicy: the checks
// that are fizzled issuance policy rather than X509-SVID requirements.
func TestAuthenticateRejectsIssuancePolicyViolation(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		options       func(opts *testpki.LeafOptions)
		expectedError error
	}{
		{
			name: "leaf is not for server authentication",
			options: func(opts *testpki.LeafOptions) {
				opts.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			},
			expectedError: authn.ErrMissingServerAuth,
		},
		{
			name: "leaf is not for client authentication",
			options: func(opts *testpki.LeafOptions) {
				opts.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			},
			expectedError: authn.ErrMissingClientAuth,
		},
		{
			name: "leaf key is not ECDSA",
			options: func(opts *testpki.LeafOptions) {
				opts.UseRSA = true
			},
			expectedError: authn.ErrKeyNotECDSA,
		},
		{
			name: "leaf key is not P-256",
			options: func(opts *testpki.LeafOptions) {
				opts.Curve = elliptic.P384()
			},
			expectedError: authn.ErrKeyNotP256,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				authority := newCertificateAuthority(t)
				authenticator := newAuthenticator(t, authority)

				opts := testpki.NewLeafOptions(clientURI)
				testCase.options(&opts)

				state := connectionState(t, authority, opts)

				_, err := authenticator.Authenticate(state)
				if !errors.Is(err, testCase.expectedError) {
					t.Fatalf("expected [%v], got [%v]", testCase.expectedError, err)
				}
			},
		)
	}
}

func TestAuthenticateNoCertificate(t *testing.T) {
	t.Parallel()

	authority := newCertificateAuthority(t)
	authenticator := newAuthenticator(t, authority)

	var state tls.ConnectionState

	_, err := authenticator.Authenticate(state)
	if !errors.Is(err, x509svid.ErrNoCertificate) {
		t.Fatalf("expected [%v], got [%v]", x509svid.ErrNoCertificate, err)
	}
}

// TestAuthenticateRejectsUntrustedChain proves that Authenticate re-verifies the
// peer chain rather than reading the identity out of whatever the connection
// happens to carry: a well-formed client SVID from an untrusted CA is rejected.
func TestAuthenticateRejectsUntrustedChain(t *testing.T) {
	t.Parallel()

	authority := newCertificateAuthority(t)
	authenticator := newAuthenticator(t, authority)

	otherCA := newCertificateAuthority(t)
	state := connectionState(t, otherCA, testpki.NewLeafOptions(clientURI))

	_, err := authenticator.Authenticate(state)

	_, ok := errors.AsType[x509.UnknownAuthorityError](err)
	if !ok {
		t.Fatalf("expected an unknown-authority error, got [%v]", err)
	}
}

// TestHandshake proves that ServerConfig and ClientConfig interoperate over a
// real TLS handshake and that the server can recover the client's agent id.
func TestHandshake(t *testing.T) {
	t.Parallel()

	authority := newCertificateAuthority(t)
	authenticator := newAuthenticator(t, authority)

	serverConfig, clientConfig := mtlsPair(t, authority, authenticator, authenticator)

	result := drive(t, serverConfig, clientConfig)
	if result.clientErr != nil {
		t.Fatalf("client handshake: %v", result.clientErr)
	}

	if result.serverErr != nil {
		t.Fatalf("server handshake: %v", result.serverErr)
	}

	agentID, err := authenticator.Authenticate(result.serverState)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	if agentID != authn.AgentID("smith") {
		t.Errorf("expected [smith], got [%s]", agentID)
	}
}

// TestHandshakeRejectsBadClient proves the server aborts the handshake when the
// client presents a certificate that is not an acceptable fizzled client SVID.
func TestHandshakeRejectsBadClient(t *testing.T) {
	t.Parallel()

	for _, testCase := range badPeerCases() {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				authority := newCertificateAuthority(t)
				authenticator := newAuthenticator(t, authority)

				serverConfig, clientConfig := mtlsPair(
					t,
					authority,
					authenticator,
					authenticator,
				)

				opts := testpki.NewLeafOptions(clientURI)
				testCase.options(&opts)

				badCert, badKey := testpki.NewLeafFiles(t, authority, opts)

				result := drive(t, serverConfig, rogue(t, clientConfig, badCert, badKey))
				if !errors.Is(result.serverErr, testCase.expectedError) {
					t.Fatalf(
						"expected server to reject with [%v], got [%v]",
						testCase.expectedError,
						result.serverErr,
					)
				}
			},
		)
	}
}

// TestHandshakeRejectsBadServer proves the client aborts the handshake when the
// server presents a certificate that is not the acceptable fizzled server SVID.
func TestHandshakeRejectsBadServer(t *testing.T) {
	t.Parallel()

	for _, testCase := range badPeerCases() {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				authority := newCertificateAuthority(t)
				authenticator := newAuthenticator(t, authority)

				serverConfig, clientConfig := mtlsPair(
					t,
					authority,
					authenticator,
					authenticator,
				)

				opts := testpki.NewLeafOptions(serverURI)
				testCase.options(&opts)

				badCert, badKey := testpki.NewLeafFiles(t, authority, opts)

				result := drive(t, rogue(t, serverConfig, badCert, badKey), clientConfig)
				if !errors.Is(result.clientErr, testCase.expectedError) {
					t.Fatalf(
						"expected client to reject with [%v], got [%v]",
						testCase.expectedError,
						result.clientErr,
					)
				}
			},
		)
	}
}

// TestHandshakeRejectsUntrustedPeer proves each side rejects a peer whose chain
// does not anchor to the trust bundle, however well-formed its SVID is.
func TestHandshakeRejectsUntrustedPeer(t *testing.T) {
	t.Parallel()

	t.Run("client chain does not anchor", func(t *testing.T) {
		t.Parallel()

		authority := newCertificateAuthority(t)
		authenticator := newAuthenticator(t, authority)

		serverConfig, clientConfig := mtlsPair(t, authority, authenticator, authenticator)

		otherCA := newCertificateAuthority(t)
		badCert, badKey := testpki.NewLeafFiles(t, otherCA, testpki.NewLeafOptions(clientURI))

		result := drive(t, serverConfig, rogue(t, clientConfig, badCert, badKey))

		_, ok := errors.AsType[x509.UnknownAuthorityError](result.serverErr)
		if !ok {
			t.Fatalf("expected an unknown-authority error, got [%v]", result.serverErr)
		}
	})

	t.Run("server chain does not anchor", func(t *testing.T) {
		t.Parallel()

		authority := newCertificateAuthority(t)
		authenticator := newAuthenticator(t, authority)

		serverConfig, clientConfig := mtlsPair(t, authority, authenticator, authenticator)

		otherCA := newCertificateAuthority(t)
		badCert, badKey := testpki.NewLeafFiles(t, otherCA, testpki.NewLeafOptions(serverURI))

		result := drive(t, rogue(t, serverConfig, badCert, badKey), clientConfig)

		_, ok := errors.AsType[x509.UnknownAuthorityError](result.clientErr)
		if !ok {
			t.Fatalf("expected an unknown-authority error, got [%v]", result.clientErr)
		}
	})
}

// rogue turns a configuration into a peer that presents the SVID at
// certFile/keyFile and applies none of the fizzled checks of its own, so the
// side under test is the only one doing any rejecting. A peer presenting an
// unacceptable SVID cannot be built by ClientConfig or ServerConfig any more,
// which is the point of the check those two now run, and it is not how an
// unwelcome peer would be built in the first place.
func rogue(t *testing.T, config *tls.Config, certFile, keyFile string) *tls.Config {
	t.Helper()

	identity, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("rogue: load key-pair: %v", err)
	}

	config.Certificates = []tls.Certificate{identity}
	config.VerifyConnection = nil

	return config
}

// TestHandshakeDoesNotResume covers the session-ticket policy: ServerConfig
// declines to issue them, so every connection is a full handshake.
//
// Its counterpart is TestHandshakeResumptionIsVerified, which reaches the same
// path with tickets on. The two share a client configuration, so neither can
// pass by failing to resume for some reason of its own.
func TestHandshakeDoesNotResume(t *testing.T) {
	t.Parallel()

	authority := newCertificateAuthority(t)
	authenticator := newAuthenticator(t, authority)

	serverConfig, clientConfig := mtlsPair(t, authority, authenticator, authenticator)
	resumableClient(clientConfig)

	first := drive(t, serverConfig, clientConfig)
	if first.serverErr != nil || first.clientErr != nil {
		t.Fatalf("first handshake: server [%v], client [%v]", first.serverErr, first.clientErr)
	}

	second := drive(t, serverConfig, clientConfig)
	if second.serverErr != nil || second.clientErr != nil {
		t.Fatalf("second handshake: server [%v], client [%v]", second.serverErr, second.clientErr)
	}

	if second.serverState.DidResume {
		t.Fatal("expected a full handshake, got a resumed one")
	}
}

// TestHandshakeResumptionIsVerified asserts the verification with
// VerifyConnection and not with VerifyPeerCertificate. The check runs again on
// a resumed session, which carries the peer certificates of the session it
// resumes, so resumption is not a way past the identity check.
func TestHandshakeResumptionIsVerified(t *testing.T) {
	t.Parallel()

	authority := newCertificateAuthority(t)

	var recorded bytes.Buffer

	serverSide := newAuditedAuthenticator(t, authority, &recorded)
	clientSide := newAuthenticator(t, authority)

	serverConfig, clientConfig := mtlsPair(t, authority, serverSide, clientSide)
	serverConfig.SessionTicketsDisabled = false

	resumableClient(clientConfig)

	first := drive(t, serverConfig, clientConfig)
	if first.serverErr != nil || first.clientErr != nil {
		t.Fatalf("first handshake: server [%v], client [%v]", first.serverErr, first.clientErr)
	}

	second := drive(t, serverConfig, clientConfig)
	if second.serverErr != nil || second.clientErr != nil {
		t.Fatalf("second handshake: server [%v], client [%v]", second.serverErr, second.clientErr)
	}

	if first.serverState.DidResume || !second.serverState.DidResume {
		t.Fatal("expected a full handshake and then a resumed one")
	}

	agentID, err := serverSide.Authenticate(second.serverState)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	if agentID != authn.AgentID("smith") {
		t.Errorf("expected [smith], got [%s]", agentID)
	}

	// Two connections, two audit lines: the resumed one was verified as well,
	// which is what the certificates surviving into it are worth.
	entries := auditEntries(t, &recorded)
	if len(entries) != 2 {
		t.Fatalf("expected an audit line per connection, got %d", len(entries))
	}
}

// resumableClient gives a client configuration everything it needs to resume a
// session, so that a connection which does not resume is the server's doing.
//
// A session is cached under the server name when there is one, and under the
// address otherwise. Each connection gets a fresh listener on its own port, so
// without a server name the second would look up a key the first never wrote.
func resumableClient(config *tls.Config) {
	config.ClientSessionCache = tls.NewLRUClientSessionCache(1)
	config.ServerName = "fizzled-test"
}

// TestHandshakeRejectsOldTLS proves the server refuses a client that offers
// nothing above TLS 1.1 (README Authentication).
func TestHandshakeRejectsOldTLS(t *testing.T) {
	t.Parallel()

	authority := newCertificateAuthority(t)
	authenticator := newAuthenticator(t, authority)

	serverConfig, clientConfig := mtlsPair(t, authority, authenticator, authenticator)

	// crypto/tls offers TLS 1.0 and 1.1 only to a config that asks for them by
	// name, which is what keeps this a real negotiation rather than a no-op.
	clientConfig.MinVersion = tls.VersionTLS10
	clientConfig.MaxVersion = tls.VersionTLS11

	result := drive(t, serverConfig, clientConfig)
	if result.serverErr == nil {
		t.Fatal("expected the server to reject the handshake, got nil")
	}

	if !strings.Contains(result.serverErr.Error(), "unsupported versions") {
		t.Errorf("expected a rejection on the TLS version, got [%v]", result.serverErr)
	}
}

// TestHandshakeAudit covers the audit line the README asks for: the outcome of
// each connection, carrying the peer's SPIFFE ID and serial number and nothing
// that came out of a key.
func TestHandshakeAudit(t *testing.T) {
	t.Parallel()

	t.Run("accepted", func(t *testing.T) {
		t.Parallel()

		authority := newCertificateAuthority(t)

		// One recorder per side. The two verifications run on different
		// goroutines here, as they would in different processes.
		var serverRecord, clientRecord bytes.Buffer

		serverSide := newAuditedAuthenticator(t, authority, &serverRecord)
		clientSide := newAuditedAuthenticator(t, authority, &clientRecord)

		serverConfig, clientConfig := mtlsPair(t, authority, serverSide, clientSide)

		result := drive(t, serverConfig, clientConfig)
		if result.serverErr != nil || result.clientErr != nil {
			t.Fatalf("handshake: server [%v], client [%v]", result.serverErr, result.clientErr)
		}

		accepted := onlyAuditEntry(t, &serverRecord)
		requireAttribute(t, accepted, "level", "INFO")
		requireAttribute(t, accepted, "msg", "peer authenticated")
		requireAttribute(t, accepted, "peer", "client")
		requireAttribute(t, accepted, "spiffe_id", clientURI)
		requireAttribute(t, accepted, "agent_id", "smith")

		serial, _ := accepted["serial"].(string)
		if serial == "" {
			t.Error("expected the accepted line to carry a serial number")
		}

		// The client records the peer it verified, which is the server: the
		// server SVID carries no agent, so that line carries no agent id.
		fromClient := onlyAuditEntry(t, &clientRecord)
		requireAttribute(t, fromClient, "peer", "server")
		requireAttribute(t, fromClient, "spiffe_id", serverURI)

		_, hasAgent := fromClient["agent_id"]
		if hasAgent {
			t.Error("expected no agent id on the server peer line")
		}

		if strings.Contains(serverRecord.String(), "-----BEGIN") {
			t.Error("audit log carries PEM")
		}
	})

	t.Run("rejected", func(t *testing.T) {
		t.Parallel()

		authority := newCertificateAuthority(t)

		var recorded bytes.Buffer

		serverSide := newAuditedAuthenticator(t, authority, &recorded)
		clientSide := newAuthenticator(t, authority)

		serverConfig, clientConfig := mtlsPair(t, authority, serverSide, clientSide)

		// A client presenting the server's identity shape: well-formed, issued
		// by the same CA, and not a client SVID.
		badCert, badKey := testpki.NewLeafFiles(t, authority, testpki.NewLeafOptions(serverURI))

		result := drive(t, serverConfig, rogue(t, clientConfig, badCert, badKey))
		if !errors.Is(result.serverErr, authn.ErrUnexpectedIdentity) {
			t.Fatalf("expected [%v], got [%v]", authn.ErrUnexpectedIdentity, result.serverErr)
		}

		rejected := onlyAuditEntry(t, &recorded)
		requireAttribute(t, rejected, "level", "WARN")
		requireAttribute(t, rejected, "msg", "peer rejected")
		requireAttribute(t, rejected, "peer", "client")

		reason, _ := rejected["error"].(string)
		if !strings.Contains(reason, authn.ErrUnexpectedIdentity.Error()) {
			t.Errorf("expected the reason in the audit line, got [%s]", reason)
		}

		serial, _ := rejected["presented_serial"].(string)
		if serial == "" {
			t.Error("expected the rejected line to carry the presented serial number")
		}
	})
}

// newAuditLogger records the audit log as one JSON object per line.
func newAuditLogger(recorded *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(recorded, nil))
}

// onlyAuditEntry is the single audit line expected of a connection.
func onlyAuditEntry(t *testing.T, recorded *bytes.Buffer) map[string]any {
	t.Helper()

	entries := auditEntries(t, recorded)
	if len(entries) != 1 {
		t.Fatalf("expected one audit line, got %d", len(entries))
	}

	return entries[0]
}

func auditEntries(t *testing.T, recorded *bytes.Buffer) []map[string]any {
	t.Helper()

	entries := []map[string]any{}

	for line := range strings.SplitSeq(recorded.String(), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}

		entry := map[string]any{}

		err := json.Unmarshal([]byte(line), &entry)
		if err != nil {
			t.Fatalf("decode audit line [%s]: %v", line, err)
		}

		entries = append(entries, entry)
	}

	return entries
}

func requireAttribute(t *testing.T, entry map[string]any, key, expected string) {
	t.Helper()

	actual, ok := entry[key].(string)
	if !ok || actual != expected {
		t.Errorf("expected [%s] at [%s], got [%v]", expected, key, entry[key])
	}
}

// badPeerCase mutates an otherwise-valid SVID for the side under test into one
// its peer must reject during the handshake.
type badPeerCase struct {
	name          string
	options       func(opts *testpki.LeafOptions)
	expectedError error
}

// badPeerCases are the rejections that both sides of the connection share: the
// identity checks and the issuance policy apply symmetrically, so the same table
// drives the client-rejects-server and server-rejects-client tests. The URI each
// case starts from is the one valid for the side being mutated, so swapping it
// for the peer's shape is what makes it unexpected.
func badPeerCases() []badPeerCase {
	return []badPeerCase{
		{
			name: "the peer's identity shape",
			options: func(opts *testpki.LeafOptions) {
				if opts.URIs[0] == serverURI {
					opts.URIs = []string{clientURI}
				} else {
					opts.URIs = []string{serverURI}
				}
			},
			expectedError: authn.ErrUnexpectedIdentity,
		},
		{
			name: "another trust domain",
			options: func(opts *testpki.LeafOptions) {
				opts.URIs = []string{
					strings.Replace(opts.URIs[0], authn.TrustDomain, "other.internal", 1),
				}
			},
			expectedError: authn.ErrWrongTrustDomain,
		},
		{
			// One component too many for either side: four for the client
			// shape, two for the server's.
			name: "a trailing path component",
			options: func(opts *testpki.LeafOptions) {
				opts.URIs = []string{opts.URIs[0] + "/extra"}
			},
			expectedError: authn.ErrUnexpectedIdentity,
		},
		{
			name: "missing the server-auth EKU",
			options: func(opts *testpki.LeafOptions) {
				opts.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			},
			expectedError: authn.ErrMissingServerAuth,
		},
		{
			name: "a key off the P-256 curve",
			options: func(opts *testpki.LeafOptions) {
				opts.Curve = elliptic.P384()
			},
			expectedError: authn.ErrKeyNotP256,
		},
	}
}

// handshakeResult carries the outcome of a driven TLS handshake.
type handshakeResult struct {
	serverState tls.ConnectionState
	serverErr   error
	clientErr   error
}

// drive runs a client and server handshake against each other over a loopback
// TCP connection and returns the server-side connection state and both handshake
// errors. A real socket (rather than net.Pipe) is used so the reject path, where
// a side aborts by writing a TLS alert, does not deadlock.
func drive(t *testing.T, serverConfig, clientConfig *tls.Config) handshakeResult {
	t.Helper()

	// serverOutcome carries the server side of a driven handshake.
	type serverOutcome struct {
		state tls.ConnectionState
		err   error
	}

	var listenConfig net.ListenConfig

	listener, err := listenConfig.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	defer func() { _ = listener.Close() }()

	serverCh := make(chan serverOutcome, 1)

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			var zero tls.ConnectionState

			serverCh <- serverOutcome{state: zero, err: acceptErr}

			return
		}

		defer func() { _ = conn.Close() }()

		server := tls.Server(conn, serverConfig)

		handshakeErr := server.HandshakeContext(context.Background())
		if handshakeErr == nil {
			_, _ = server.Write([]byte{0})
		}

		serverCh <- serverOutcome{state: server.ConnectionState(), err: handshakeErr}
	}()

	var dialer net.Dialer

	clientConn, err := dialer.DialContext(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	client := tls.Client(clientConn, clientConfig)
	clientErr := client.HandshakeContext(context.Background())

	// Read the byte the server writes after a completed handshake. The read is
	// what makes the client take in the session ticket that follows a TLS 1.3
	// handshake, so a later connection can resume with it. A server that went on
	// to reject the client closes instead of writing, which the deadline and the
	// discarded error cover.
	if clientErr == nil {
		_ = clientConn.SetReadDeadline(time.Now().Add(readTimeout))
		_, _ = client.Read(make([]byte, 1))
	}

	// Close the client side as soon as it is done, so a server still blocked
	// reading (for example when the client aborted) unblocks with EOF instead of
	// deadlocking.
	_ = clientConn.Close()

	outcome := <-serverCh

	return handshakeResult{
		serverState: outcome.state,
		serverErr:   outcome.err,
		clientErr:   clientErr,
	}
}

// newAuthenticator writes authority's certificate to a temporary file and
// returns an Authenticator trusting it, with its audit log discarded.
func newAuthenticator(t *testing.T, authority testpki.Authority) *authn.Authenticator {
	t.Helper()

	return newAuthenticatorWithLogger(t, authority, nil)
}

// newAuditedAuthenticator is newAuthenticator with the audit log kept.
func newAuditedAuthenticator(
	t *testing.T,
	authority testpki.Authority,
	recorded *bytes.Buffer,
) *authn.Authenticator {
	t.Helper()

	authenticator := newAuthenticatorWithLogger(t, authority, newAuditLogger(recorded))
	recorded.Reset()

	return authenticator
}

// newAuthenticatorWithLogger anchors an Authenticator to authority, recording on
// logger.
func newAuthenticatorWithLogger(
	t *testing.T,
	authority testpki.Authority,
	logger *slog.Logger,
) *authn.Authenticator {
	t.Helper()

	authenticator, err := authn.NewAuthenticator(
		testpki.WriteCertificate(t, t.TempDir(), "ca.crt", authority.Certificate),
		logger,
	)
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}

	return authenticator
}

// newCertificateAuthority issues a self-signed authority without a URI SAN,
// which the X509-SVID standard permits.
func newCertificateAuthority(tb testing.TB) testpki.Authority {
	tb.Helper()

	return testpki.NewAuthority(tb, testpki.NewAuthorityOptions())
}

// newCertificateAuthorityWithURIs issues one carrying uris as its URI SANs,
// which is how a bundle belonging to somebody else's deployment is written.
func newCertificateAuthorityWithURIs(tb testing.TB, uris ...string) testpki.Authority {
	tb.Helper()

	opts := testpki.NewAuthorityOptions()
	opts.URIs = uris

	return testpki.NewAuthority(tb, opts)
}

// newCertificateAuthorityWithKeyUsage issues one whose key usage is keyUsage
// and nothing else, which is how a root that cannot sign the chain it anchors
// is written.
func newCertificateAuthorityWithKeyUsage(tb testing.TB, keyUsage x509.KeyUsage) testpki.Authority {
	tb.Helper()

	opts := testpki.NewAuthorityOptions()
	opts.KeyUsage = keyUsage

	return testpki.NewAuthority(tb, opts)
}

// requireTransportPolicy asserts the parts of the transport policy that are the
// same on both sides of a connection (README Authentication). They are settings
// rather than behaviour, so nothing else would notice them going wrong.
func requireTransportPolicy(t *testing.T, config *tls.Config) {
	t.Helper()

	if config.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected minimum TLS 1.2, got [%d]", config.MinVersion)
	}

	if config.MaxVersion != tls.VersionTLS13 {
		t.Errorf("expected maximum TLS 1.3, got [%d]", config.MaxVersion)
	}

	if config.Renegotiation != tls.RenegotiateNever {
		t.Errorf("expected renegotiation to be refused, got [%v]", config.Renegotiation)
	}

	// ECDSA-only, matching the ECDSA P-256 issuance policy: an _RSA_ suite
	// could never be negotiated with these leaves anyway.
	expectedSuites := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	}
	if !slices.Equal(config.CipherSuites, expectedSuites) {
		t.Errorf("expected [%v] cipher suites, got [%v]", expectedSuites, config.CipherSuites)
	}
}

// certificatePEM is the PEM encoding of an authority's certificate, as a trust
// bundle carries it.
func certificatePEM(authority testpki.Authority) []byte {
	return testpki.CertificatePEM(authority.Certificate)
}

// mtlsPair builds the two sides of a connection between peers that trust the
// same CA: the server configuration from serverSide and the client one from
// clientSide, each presenting an SVID that CA issued.
func mtlsPair(
	t *testing.T,
	authority testpki.Authority,
	serverSide, clientSide *authn.Authenticator,
) (*tls.Config, *tls.Config) {
	t.Helper()

	serverCert, serverKey := testpki.NewLeafFiles(t, authority, testpki.NewLeafOptions(serverURI))

	serverConfig, err := serverSide.ServerConfig(serverCert, serverKey)
	if err != nil {
		t.Fatalf("server config: %v", err)
	}

	clientCert, clientKey := testpki.NewLeafFiles(t, authority, testpki.NewLeafOptions(clientURI))

	clientConfig, err := clientSide.ClientConfig(clientCert, clientKey)
	if err != nil {
		t.Fatalf("client config: %v", err)
	}

	return serverConfig, clientConfig
}

// connectionState issues a leaf described by opts, signed by authority, and presents it
// as the peer chain of a connection state.
func connectionState(
	t *testing.T,
	authority testpki.Authority,
	opts testpki.LeafOptions,
) tls.ConnectionState {
	t.Helper()

	certificate, _ := testpki.NewLeaf(t, authority, opts)

	var state tls.ConnectionState

	state.PeerCertificates = []*x509.Certificate{certificate}

	return state
}

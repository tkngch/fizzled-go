package x509svid_test

import (
	"crypto/x509"
	"net/url"
	"testing"

	"github.com/tkngch/fizzled-go/internal/authn/internal/testpki"
	"github.com/tkngch/fizzled-go/internal/authn/spiffeid"
	"github.com/tkngch/fizzled-go/internal/authn/x509svid"
)

// FuzzVerifyLeafURI holds Verify to the properties the authentication layer
// reads a verified leaf by. Its input is the path of the URI SAN of a leaf
// certificate, which is whatever a certificate authority was willing to sign,
// and the seam between the certificate and the identity is where an agent could
// come to answer to a name that is not the one it was issued.
//
// The table tests pin the cases a reader thought of. This pins the properties,
// over the paths nobody did — and in particular over the ones net/url rewrites
// on the way through a certificate, which is the part no reader can enumerate
// by hand.
//
// Only the path is fuzzed, and the trust domain is held at a valid one. That is
// a scoping decision rather than an oversight: a certificate carrying an
// unparseable authority is one crypto/x509 refuses to hand back, so it can no
// more reach Verify here than it could reach it from a handshake, and predicting
// which those are would mean keeping a second copy of crypto/x509's rules. The
// trust domain as a string is FuzzParse's to cover, and does. What is left, and
// what only this test is positioned to reach, is the path — which is the part
// authn reads an agent id out of.
//
// The input is the path with its leading separator supplied here rather than by
// the fuzzer. Without it an input is glued onto the trust domain instead, which
// is how the authority stays the fixed valid one the paragraph above relies on.
// The cost is that the path-less ID is out of reach of this target;
// TestVerifierLeafValidationError covers it.
func FuzzVerifyLeafURI(f *testing.F) {
	for _, seed := range leafPathSeeds() {
		f.Add(seed)
	}

	// One authority for the whole run. It signs whatever it is handed, so
	// nothing about it varies with the input, and minting a fresh one per
	// iteration would spend the run generating keys.
	authority := testpki.NewAuthority(f, testpki.NewAuthorityOptions())

	verifier, err := x509svid.NewVerifier([]*x509.Certificate{authority.Certificate}, testSkew)
	if err != nil {
		f.Fatalf("new verifier: %v", err)
	}

	f.Fuzz(func(t *testing.T, path string) {
		uri := "spiffe://" + trustDomain + "/" + path

		minted, ok := mintableURI(uri)
		if !ok {
			// A URI the certificate could not carry says nothing about Verify.
			// Returning rather than skipping keeps these out of the corpus
			// without reporting them as anything.
			return
		}

		certificate := newCertificate(t, authority, testpki.NewLeafOptions(uri))
		chain := []*x509.Certificate{certificate}

		leaf, err := verifier.Verify(chain)
		if err != nil {
			// A rejected chain carries nothing. The zero Leaf is what every
			// caller discards along with the error, so anything else here
			// would be a half-verified identity left within reach.
			if leaf != (x509svid.Leaf{}) {
				t.Fatalf("expected the zero leaf alongside an error, got [%s]", leaf.ID())
			}

			return
		}

		requireLeafIsTheCertificate(t, leaf, certificate)
		requireLeafIDIsTheURISAN(t, leaf, minted)
	})
}

// mintableURI reports whether a certificate can carry uri as a URI SAN at all,
// and returns the URI as it stands after net/url has read it, which is the text
// that goes into the certificate. The rejections below are net/url's and
// crypto/x509's, not this package's: testpki fails the test rather than
// returning an error, so an input that cannot be signed has to be turned away
// before it is handed over.
func mintableURI(uri string) (string, bool) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return "", false
	}

	minted := parsed.String()

	// A URI SAN is marshalled as an IA5String, so crypto/x509 refuses to sign
	// one carrying a byte outside it.
	for _, b := range []byte(minted) {
		if b >= 0x80 {
			return "", false
		}
	}

	return minted, true
}

// requireLeafIsTheCertificate asserts that the Leaf describes the certificate
// the chain was headed by, and not some other entry in it.
func requireLeafIsTheCertificate(t *testing.T, leaf x509svid.Leaf, certificate *x509.Certificate) {
	t.Helper()

	if leaf.Certificate() != certificate {
		t.Fatalf("expected the leaf of the presented chain, got a different certificate")
	}
}

// requireLeafIDIsTheURISAN asserts that the identity is the URI the certificate
// was issued for, byte for byte, and that it is one spiffeid accepts and
// x509svid requires: parseable, unchanged by a round trip, and carrying a path.
//
// minted is the URI as it went in, held from before the certificate was signed;
// comparing against certificate.URIs[0] instead would compare the identity with
// the text it was parsed from and could not fail. Between the two lie the DER
// encoding and crypto/x509 handing the SAN back as a *url.URL whose String
// re-serialises rather than returns what it was given, and an identity that
// came back altered there would be one agent authenticating as another.
func requireLeafIDIsTheURISAN(t *testing.T, leaf x509svid.Leaf, minted string) {
	t.Helper()

	if leaf.ID().String() != minted {
		t.Fatalf("expected the identity [%s], got [%s]", minted, leaf.ID())
	}

	reparsed, err := spiffeid.Parse(minted)
	if err != nil {
		t.Fatalf("accepted a leaf whose URI SAN [%s] is not a spiffe id: %v", minted, err)
	}

	// ID is comparable, so this asserts on the whole value, not just a field.
	if reparsed != leaf.ID() {
		t.Fatalf("expected [%s] to re-parse to itself, got [%s]", leaf.ID(), reparsed)
	}

	// The X509-SVID standard asks a leaf for a path.
	if len(leaf.ID().PathComponents()) == 0 {
		t.Fatalf("accepted a leaf whose identity [%s] carries no path", leaf.ID())
	}
}

// leafPathSeeds are the path shapes worth starting from.
func leafPathSeeds() []string {
	return []string{
		"path",
		"client/agent/smith",
		"",
		"/path",
		"./path",
		"../path",
		"sm%69th",
		"smith%2Fjones",
		"path?query=1",
		"path#fragment",
		"path/",
		"PathComponent",
		"ß",
		"smith jones",
		"smith\x00jones",
	}
}

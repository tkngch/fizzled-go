package spiffeid_test

import (
	"strings"
	"testing"

	"github.com/tkngch/fizzled-go/internal/authn/spiffeid"
)

// uriScheme is the scheme a SPIFFE ID is written in, spelled out here because
// the tests read the package from the outside.
const uriScheme = "spiffe://"

// FuzzParse holds Parse to the properties the rest of the authentication layer
// reads it by. Its input is a URI SAN out of a peer certificate, which is
// whatever a certificate authority was willing to sign, and Parse is the whole
// of what stands between that and the identity checks in authn.
func FuzzParse(f *testing.F) {
	seeds := []string{
		"spiffe://fizzled.internal/server",
		"spiffe://fizzled.internal/client/agent/smith",
		"spiffe://trustdomain",
		"spiffe://trustdomain/path/subpath",
		"spiffe://trustdomain/",
		"spiffe://trustdomain//path",
		"spiffe://trustdomain/./path",
		"spiffe://trustdomain/../path",
		"spiffe://trustdomain/%21%23%24",
		"spiffe://TrustDomain",
		"spiffe://user@trustdomain/path",
		"spiffe://trustdomain:8080/path",
		"spiffe://trustdomain/path?query=1",
		"spiffe://trustdomain/path#fragment",
		"https://trustdomain/path",
		"spiffe://",
		"s",
		"",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, uri string) {
		spiffeID, err := spiffeid.Parse(uri)
		if err != nil {
			// A rejected ID carries nothing. The zero value is what every
			// caller in the tree discards along with the error, so anything
			// else here would be a half-parsed identity left within reach.
			if spiffeID != (spiffeid.ID{}) {
				t.Fatalf("expected the zero ID alongside an error, got [%s]", spiffeID)
			}

			return
		}

		requireRoundTrip(t, uri, spiffeID)
		requireWholeIDReadable(t, uri, spiffeID)
		requireUsablePathComponents(t, spiffeID)
	})
}

// requireRoundTrip asserts that an accepted ID is the string it was parsed
// from, and that the string parses again to the same value. The first is what
// makes an audit line carry what the certificate carried; the second keeps
// String a form Parse accepts, rather than one only this package can read.
func requireRoundTrip(t *testing.T, uri string, spiffeID spiffeid.ID) {
	t.Helper()

	if spiffeID.String() != uri {
		t.Fatalf("expected [%s], got [%s]", uri, spiffeID.String())
	}

	reparsed, err := spiffeid.Parse(spiffeID.String())
	if err != nil {
		t.Fatalf("re-parse [%s]: %v", spiffeID, err)
	}

	// ID is comparable, so this is the whole value and not a field of it.
	if reparsed != spiffeID {
		t.Fatalf("expected [%s] to re-parse to itself, got [%s]", spiffeID, reparsed)
	}
}

// requireWholeIDReadable asserts that the trust domain and the path account for
// the whole ID. authn reads the two separately, so anything that fell between
// them would be read by neither: an identity could then differ from every other
// in a part no check ever sees.
func requireWholeIDReadable(t *testing.T, uri string, spiffeID spiffeid.ID) {
	t.Helper()

	if spiffeID.TrustDomain() == "" {
		t.Fatalf("expected a trust domain in [%s]", spiffeID)
	}

	rebuilt := uriScheme + spiffeID.TrustDomain() + spiffeID.Path()
	if rebuilt != uri {
		t.Fatalf("expected [%s], got [%s]", uri, rebuilt)
	}
}

// requireUsablePathComponents asserts what authn relies on when it reads an
// agent id out of a path: the components are what the path splits into, and
// none of them is empty, a separator, or a relative modifier.
func requireUsablePathComponents(t *testing.T, spiffeID spiffeid.ID) {
	t.Helper()

	path := spiffeID.Path()
	if path != "" && !strings.HasPrefix(path, "/") {
		t.Fatalf("expected [%s] to keep its leading separator", path)
	}

	components := spiffeID.PathComponents()
	if (path == "") != (len(components) == 0) {
		t.Fatalf("expected path [%s] and %d components to agree", path, len(components))
	}

	for _, component := range components {
		if component == "" || component == "." || component == ".." ||
			strings.Contains(component, "/") {
			t.Fatalf("unusable path component [%s] in [%s]", component, spiffeID)
		}
	}
}

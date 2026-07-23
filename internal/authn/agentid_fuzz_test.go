package authn_test

import (
	"strings"
	"testing"

	"github.com/tkngch/fizzled-go/internal/authn"
	"github.com/tkngch/fizzled-go/internal/authn/spiffeid"
)

// maxAgentIDLength is the bound an identifier is held to, spelled out here
// because the tests read the package from the outside.
const maxAgentIDLength = 64

// clientPathPrefix is the client SVID path an agent id is the last component
// of, as authn reads it back out of a certificate.
const clientPathPrefix = "/client/agent/"

// FuzzAgentID holds AgentID to what the rest of the authentication layer reads
// it by. An identifier arrives as a path component of a peer's SPIFFE ID and
// goes on to be a map key in authz, a field in an audit line, and the answer
// Authenticate hands the RPC layer.
//
// TestAgentIDValidate pins the cases a reader thought of. This pins the
// property, over the identifiers nobody did.
func FuzzAgentID(f *testing.F) {
	for _, seed := range agentIDSeeds() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		agentID, err := authn.NewAgentID(input)
		if err != nil {
			// A rejected identifier carries nothing. The zero value is what
			// every caller in the tree discards along with the error, so
			// anything else here would be a half-accepted agent left within
			// reach.
			if agentID != authn.AgentID("") {
				t.Fatalf("expected the empty agent id alongside an error, got [%s]", agentID)
			}

			return
		}

		requireAgentIDBounds(t, input, agentID)
		requireSPIFFEPathComponent(t, agentID)
	})
}

// requireAgentIDBounds asserts that an accepted identifier is the string it was
// built from and stays inside the bounds agentid.go documents.
func requireAgentIDBounds(t *testing.T, input string, agentID authn.AgentID) {
	t.Helper()

	if string(agentID) != input {
		t.Fatalf("expected [%s], got [%s]", input, agentID)
	}

	if len(agentID) == 0 || len(agentID) > maxAgentIDLength {
		t.Fatalf("expected 1 to %d bytes, got %d in [%s]", maxAgentIDLength, len(agentID), agentID)
	}

	for _, forbidden := range []string{"/", ".", " ", "\t", "\n", "\r", "\v", "\f"} {
		if strings.Contains(string(agentID), forbidden) {
			t.Fatalf("accepted [%q] in [%s]", forbidden, agentID)
		}
	}
}

// requireSPIFFEPathComponent asserts the property that makes an AgentID sound:
// it survives the round trip through the client SVID URI it is embedded in.
func requireSPIFFEPathComponent(t *testing.T, agentID authn.AgentID) {
	t.Helper()

	uri := "spiffe://" + authn.TrustDomain + clientPathPrefix + string(agentID)

	spiffeID, err := spiffeid.Parse(uri)
	if err != nil {
		t.Fatalf("accepted an agent id that does not survive [%s]: %v", uri, err)
	}

	if spiffeID.String() != uri {
		t.Fatalf("expected [%s], got [%s]", uri, spiffeID.String())
	}

	if spiffeID.TrustDomain() != authn.TrustDomain {
		t.Fatalf("expected [%s], got [%s]", authn.TrustDomain, spiffeID.TrustDomain())
	}

	components := spiffeID.PathComponents()
	if len(components) != 3 {
		t.Fatalf("expected 3 path components in [%s], got %d", uri, len(components))
	}

	if components[0] != "client" || components[1] != "agent" {
		t.Fatalf("expected a client agent path, got [%s]", spiffeID.Path())
	}

	if components[2] != string(agentID) {
		t.Fatalf("expected [%s] back out of [%s], got [%s]", agentID, uri, components[2])
	}
}

// agentIDSeeds are the identifiers a reader thought of, so that the fuzzer can
// spend its time on the ones nobody did. The accepted ones matter as much as
// the rejected: they are what the properties above have anything to say about.
func agentIDSeeds() []string {
	return []string{
		"smith",
		"jones",
		"smith-jr",
		"smith_jr",
		"Smith2",
		"",
		" ",
		"smith.jones",
		"smith@agent",
		"a/b",
		".",
		"..",
		" smith ",
		"smith\njones",
		"smith\x00jones",
		"sm%2Fith",
		"ß",
		"агент",
		strings.Repeat("a", maxAgentIDLength),
		strings.Repeat("a", maxAgentIDLength+1),
	}
}

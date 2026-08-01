package testpki

import (
	"encoding/json"
	"testing"

	"github.com/tkngch/fizzled-go/internal/authn"
	"github.com/tkngch/fizzled-go/internal/authz"
)

// WriteRoles writes a roles file granting USER to each of agents, and returns
// its path.
func WriteRoles(tb testing.TB, agents ...authn.AgentID) string {
	tb.Helper()

	roles := make(map[string]string, len(agents))
	for _, agent := range agents {
		roles[string(agent)] = string(authz.RoleUser)
	}

	encoded, err := json.Marshal(roles)
	if err != nil {
		tb.Fatalf("marshal roles: %v", err)
	}

	return WriteFile(tb, tb.TempDir(), "roles.json", encoded)
}

package authz

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"github.com/tkngch/fizzled-go/internal/authn"
)

// ErrActionUnauthorized indicates that the user's role does not allow the
// user to take requested action.
var ErrActionUnauthorized = errors.New("action unauthorized")

// ErrEmptyRoles indicates that no role is defined for any user/agent, and so,
// none of user/agent is authorized to take any action. Thus the service is
// practically unusable and should not be started.
var ErrEmptyRoles = errors.New("empty roles")

// Authorizer judges which agent has what role and has permission to take which
// action.
//
// An Authorizer is read-only once loaded, so one instance is safe for
// concurrent use by any number of goroutines.
type Authorizer struct {
	roles map[authn.AgentID]Role
}

// Load reads the JSON file at path and constructs an Authorizer from it.
//
// Load decodes the entries one at a time, rather than straight into a
// map[AgentID]Role, so that a rejected entry is reported along with the agent
// it belongs to. An operator then learns which entry of the file is at fault.
//
// One misconfiguration stays silent: an agent identifier repeated in the file
// resolves to the last of its entries, because the decoded map collapses the
// two.
func Load(path string) (*Authorizer, error) {
	// Clean the path to satisfy gosec G304. The path is not a constant, but it
	// comes from the operator who starts the service, not from an agent.
	content, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("load [%s]: %w", path, err)
	}

	var entries map[authn.AgentID]json.RawMessage

	err = json.Unmarshal(content, &entries)
	if err != nil {
		return nil, fmt.Errorf("load [%s]: %w", path, err)
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("load [%s]: %w", path, ErrEmptyRoles)
	}

	roles := make(map[authn.AgentID]Role, len(entries))

	// Walk the identifiers in a fixed order. By default, ranging over the map
	// would iterate entries in a random order.
	for _, agentID := range slices.Sorted(maps.Keys(entries)) {
		rawRole := entries[agentID]

		err = agentID.Validate()
		if err != nil {
			return nil, fmt.Errorf("load [%s] agent [%s]: %w", path, agentID, err)
		}

		var role Role

		err = json.Unmarshal(rawRole, &role)
		if err != nil {
			return nil, fmt.Errorf("load [%s] agent [%s]: %w", path, agentID, err)
		}

		roles[agentID] = role
	}

	return &Authorizer{roles: roles}, nil
}

// Authorize returns nil when agent has permission to carry out action.
//
// The error names the agent and the action, so that the denied decision can be
// recorded in the audit log. It is written for the operator reading that log,
// not for the agent: a caller turning it into a gRPC status reports
// PERMISSION_DENIED without echoing the message back to the agent.
func (a *Authorizer) Authorize(agent authn.AgentID, action Action) error {
	role, isFound := a.roles[agent]
	if !isFound || !role.isAuthorizedTo(action) {
		return fmt.Errorf(
			"authorize [agent %s action %s]: %w",
			agent,
			action,
			ErrActionUnauthorized,
		)
	}

	return nil
}

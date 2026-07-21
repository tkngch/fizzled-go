package authz

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

// Role describes the user/agent's role. UnmarshalJSON takes a pointer receiver
// to populate the role in place, while the predicates take a value receiver, so
// the mixed receivers are deliberate.
type Role string //nolint:recvcheck // UnmarshalJSON needs a pointer receiver.

const (
	// RoleUser is a user role.
	RoleUser Role = "USER"
)

// ErrUnknownRole indicates that a role in JSON file does not match any of
// known roles.
var ErrUnknownRole = errors.New("unknown role")

// UnmarshalJSON validates the input against the known roles.
func (r *Role) UnmarshalJSON(data []byte) error {
	var input string

	err := json.Unmarshal(data, &input)
	if err != nil {
		return fmt.Errorf("unmarshal role: %w", err)
	}

	role := Role(input)
	if !role.isKnown() {
		// Report the raw JSON rather than the decoded string. A JSON null
		// decodes into an empty string, which would otherwise be reported as an
		// empty pair of brackets and read as if nothing were wrong with it.
		return fmt.Errorf("unmarshal role [%s]: %w", data, ErrUnknownRole)
	}

	*r = role

	return nil
}

// actions returns the actions that the role grants, and nil when the role is
// not one of the known ones. It is the single source of truth for both
// predicates below, so adding a role is one edit, not two.
func (r Role) actions() []Action {
	switch r {
	case RoleUser:
		return []Action{ActionStart, ActionStop, ActionGetStatus, ActionStreamOutput}
	default:
		return nil
	}
}

func (r Role) isKnown() bool {
	return r.actions() != nil
}

func (r Role) isAuthorizedTo(action Action) bool {
	return slices.Contains(r.actions(), action)
}

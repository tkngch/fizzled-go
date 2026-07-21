package authz

import (
	"errors"
	"fmt"
	"strings"
)

// AgentID identifies an agent/user.
type AgentID string

// ErrInvalidAgentID indicates that an identifier is blank or carries a
// character that it must not.
var ErrInvalidAgentID = errors.New("invalid agent id")

// validate returns an error if the identifier is not acceptable by the
// authentication layer. The Authentication section of the README is where the
// rule comes from: an identifier is a single path component of a SPIFFE ID, so
// it should not carry a separator or a relative modifier.
func (a AgentID) validate() error {
	if strings.TrimSpace(string(a)) == "" {
		return fmt.Errorf("empty string: %w", ErrInvalidAgentID)
	}

	if strings.ContainsAny(string(a), "/.") {
		return fmt.Errorf("contains '/' or '.': %w", ErrInvalidAgentID)
	}

	return nil
}

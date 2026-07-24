package authn

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// AgentID identifies an agent/user.
type AgentID string

// ErrInvalidAgentID indicates that an identifier is blank or carries a
// character that it must not.
var ErrInvalidAgentID = errors.New("invalid agent id")

// validAgentIDPattern is deliberately stricter than a SPIFFE path component. An
// AgentID is a single path component of a SPIFFE ID, but the fizzled domain
// additionally forbids the dot, so an identifier is limited to alphanumerics,
// the hyphen, and the underscore.
var validAgentIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// NewAgentID builds AgentID from string and validates it.
func NewAgentID(input string) (AgentID, error) {
	agentID := AgentID(input)

	err := agentID.Validate()
	if err != nil {
		return "", fmt.Errorf("new agentID: %w", err)
	}

	return agentID, nil
}

// Validate returns an error if the identifier is not acceptable by the
// authentication layer. An identifier is a single path component of a SPIFFE
// ID, so it must not carry a separator or a relative modifier. Agent ID is
// stricter than the SPIFFE standard: it also rejects the dot and any
// whitespace.
func (a AgentID) Validate() error {
	if strings.TrimSpace(string(a)) == "" {
		return fmt.Errorf("validate: empty string: %w", ErrInvalidAgentID)
	}

	if !validAgentIDPattern.MatchString(string(a)) {
		return fmt.Errorf(
			"validate: contains a character that is not allowed: %w",
			ErrInvalidAgentID,
		)
	}

	return nil
}

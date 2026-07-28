package authn

import (
	"fmt"
	"regexp"
)

// AgentID identifies an agent or a user.
type AgentID string

// maxAgentIDLength is deliberately shorter than what a SPIFFE path component is
// allowed.
const maxAgentIDLength = 64

// validAgentIDPattern is deliberately stricter than a SPIFFE path component. An
// AgentID is a single path component of a SPIFFE ID, but the fizzled domain
// only permits alphanumerics, the hyphen, and the underscore.
var validAgentIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// NewAgentID builds an AgentID from string and validates it.
func NewAgentID(input string) (AgentID, error) {
	agentID := AgentID(input)

	err := agentID.Validate()
	if err != nil {
		return "", fmt.Errorf("new agent id: %w", err)
	}

	return agentID, nil
}

// Validate returns an error if the agent ID is in an unacceptable format. An
// agent ID is a single path component of a SPIFFE ID, so it must not carry a
// separator or a relative modifier. An agent ID is also at least one and at
// most maxAgentIDLength bytes, each an ASCII letter, digit, hyphen, or
// underscore: everything else is rejected.
func (a AgentID) Validate() error {
	// The pattern below already rejects a blank identifier. This check is kept
	// only so that the common mistake reports itself as such.
	if a == "" {
		return fmt.Errorf("validate: empty string: %w", ErrInvalidAgentID)
	}

	// Checked before the pattern, so that a long id is turned away without
	// regex-matching.
	if len(a) > maxAgentIDLength {
		return fmt.Errorf(
			"validate: longer than %d bytes: %w",
			maxAgentIDLength,
			ErrInvalidAgentID,
		)
	}

	if !validAgentIDPattern.MatchString(string(a)) {
		return fmt.Errorf(
			"validate: contains a character that is not allowed: %w",
			ErrInvalidAgentID,
		)
	}

	return nil
}

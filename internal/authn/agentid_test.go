package authn_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/tkngch/fizzled-go/internal/authn"
)

func TestAgentIDValidate(t *testing.T) {
	t.Parallel()

	// An identifier of exactly maxAgentIDLength is permitted, so the two cases
	// below pin both sides of the check.
	testCases := []struct {
		name           string
		input          string
		expectedOutput error
	}{
		{
			name:           "valid agent id",
			input:          "smith",
			expectedOutput: nil,
		},
		{
			name:           "empty agent id",
			input:          "",
			expectedOutput: authn.ErrInvalidAgentID,
		},
		{
			name:           "blank agent id",
			input:          " ",
			expectedOutput: authn.ErrInvalidAgentID,
		},
		{
			name:           "agent id with a slash",
			input:          "a/b",
			expectedOutput: authn.ErrInvalidAgentID,
		},
		{
			name:           "whitespaces",
			input:          " smith ",
			expectedOutput: authn.ErrInvalidAgentID,
		},
		{
			name:           "dot",
			input:          "smith.jones",
			expectedOutput: authn.ErrInvalidAgentID,
		},
		{
			name:           "at-sign",
			input:          "smith@agent",
			expectedOutput: authn.ErrInvalidAgentID,
		},
		{
			name:           "relative modifier",
			input:          ".",
			expectedOutput: authn.ErrInvalidAgentID,
		},
		{
			name:           "parent modifier",
			input:          "..",
			expectedOutput: authn.ErrInvalidAgentID,
		},
		{
			name:           "hyphen",
			input:          "smith-jr",
			expectedOutput: nil,
		},
		{
			name:           "underscore",
			input:          "smith_jr",
			expectedOutput: nil,
		},
		{
			name:           "uppercase",
			input:          "Smith",
			expectedOutput: nil,
		},
		{
			name:           "longest permitted agent id",
			input:          strings.Repeat("a", maxAgentIDLength),
			expectedOutput: nil,
		},
		{
			name:           "agent id too long",
			input:          strings.Repeat("a", maxAgentIDLength+1),
			expectedOutput: authn.ErrInvalidAgentID,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				agentID := authn.AgentID(testCase.input)
				err := agentID.Validate()

				if !errors.Is(err, testCase.expectedOutput) {
					t.Fatalf("expected [%v], got [%v]", testCase.expectedOutput, err)
				}
			},
		)
	}
}

func TestNewAgentID(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		agentID, err := authn.NewAgentID("smith")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if agentID != authn.AgentID("smith") {
			t.Errorf("expected [smith], got [%s]", agentID)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		t.Parallel()

		agentID, err := authn.NewAgentID("smith.jones")
		if !errors.Is(err, authn.ErrInvalidAgentID) {
			t.Fatalf("expected [%v], got [%v]", authn.ErrInvalidAgentID, err)
		}

		if agentID != authn.AgentID("") {
			t.Errorf("expected an empty agent id, got [%s]", agentID)
		}
	})

	t.Run("case sensitive", func(t *testing.T) {
		t.Parallel()

		lower, err := authn.NewAgentID("smith")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		upper, err := authn.NewAgentID("Smith")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if lower == upper {
			t.Fatalf("expected [%s] and [%s] to be distinct agents", lower, upper)
		}
	})
}

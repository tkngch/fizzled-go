package authn_test

import (
	"errors"
	"testing"

	"github.com/tkngch/fizzled-go/internal/authn"
)

func TestValidate(t *testing.T) {
	t.Parallel()

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
			name:           "agent id with dots",
			input:          "../x",
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

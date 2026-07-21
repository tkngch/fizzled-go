package authz_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/tkngch/fizzled-go/internal/authz"
)

func TestRoleUnmarshalJSON(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		input         json.RawMessage
		expectedRole  authz.Role
		expectedError error
	}{
		{[]byte(`"USER"`), authz.RoleUser, nil},
		{[]byte(`"INVALID"`), "", authz.ErrUnknownRole},
		{[]byte(`""`), "", authz.ErrUnknownRole},
		{[]byte(`null`), "", authz.ErrUnknownRole},
	}

	for _, testCase := range testCases {
		t.Run(
			fmt.Sprintf("unmarshal %s", testCase.input),
			func(t *testing.T) {
				t.Parallel()

				var role authz.Role

				err := json.Unmarshal(testCase.input, &role)
				if !errors.Is(err, testCase.expectedError) {
					t.Fatalf("expected [%v], got [%v]", testCase.expectedError, err)
				}

				if testCase.expectedRole != role {
					t.Errorf("expected [%s], got [%s]", testCase.expectedRole, role)
				}
			},
		)
	}
}

// TestRoleUnmarshalJSONMalformed covers the inputs that are not JSON strings.
// They are rejected before any role is recognised, so they carry no
// ErrUnknownRole.
func TestRoleUnmarshalJSONMalformed(t *testing.T) {
	t.Parallel()

	testCases := []json.RawMessage{
		[]byte(`123`),
		[]byte(`{}`),
		[]byte(`[]`),
		[]byte(``),
	}

	for _, testCase := range testCases {
		t.Run(
			fmt.Sprintf("unmarshal %s", testCase),
			func(t *testing.T) {
				t.Parallel()

				var role authz.Role

				err := json.Unmarshal(testCase, &role)
				if err == nil {
					t.Fatal("expected an error, got nil")
				}

				if role != "" {
					t.Errorf("expected the role left untouched, got [%s]", role)
				}
			},
		)
	}
}

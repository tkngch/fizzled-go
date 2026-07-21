package authz_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tkngch/fizzled-go/internal/authz"
)

const (
	agentUser    = authz.AgentID("user")
	agentNonUser = authz.AgentID("non-user")
)

func TestAuthorize(t *testing.T) {
	t.Parallel()

	path := writeRolesFile(t, []byte(`{"user": "USER"}`))

	authorizer, err := authz.Load(path)
	if err != nil {
		t.Fatalf("test-authorize: %v", err)
	}

	testCases := []struct {
		agentID       authz.AgentID
		action        authz.Action
		expectedError error
	}{
		{agentUser, authz.ActionStart, nil},
		{agentUser, authz.ActionStop, nil},
		{agentUser, authz.ActionGetStatus, nil},
		{agentUser, authz.ActionStreamOutput, nil},
		{agentUser, authz.Action("Unknown"), authz.ErrActionUnauthorized},
		{agentNonUser, authz.ActionStart, authz.ErrActionUnauthorized},
		{agentNonUser, authz.ActionStop, authz.ErrActionUnauthorized},
		{agentNonUser, authz.ActionGetStatus, authz.ErrActionUnauthorized},
		{agentNonUser, authz.ActionStreamOutput, authz.ErrActionUnauthorized},
	}

	for _, testCase := range testCases {
		t.Run(
			fmt.Sprintf("%s - %s", testCase.agentID, testCase.action),
			func(t *testing.T) {
				t.Parallel()

				err := authorizer.Authorize(testCase.agentID, testCase.action)
				if !errors.Is(err, testCase.expectedError) {
					t.Errorf("expected [%v], got [%v]", testCase.expectedError, err)
				}
			},
		)
	}
}

func TestLoad(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                string
		json                json.RawMessage
		expectedPermissions map[authz.AgentID][]authz.Action
	}{
		{
			name: "one agent",
			json: []byte(`{"user":"USER"}`),
			expectedPermissions: map[authz.AgentID][]authz.Action{
				authz.AgentID("user"): {
					authz.ActionStart,
					authz.ActionStop,
					authz.ActionGetStatus,
					authz.ActionStreamOutput,
				},
			},
		},
		{
			// The two agents that Secrets issues certificates for.
			name: "two agents",
			json: []byte(`{"smith":"USER","jones":"USER"}`),
			expectedPermissions: map[authz.AgentID][]authz.Action{
				authz.AgentID("smith"): {authz.ActionStart, authz.ActionStop},
				authz.AgentID("jones"): {authz.ActionStart, authz.ActionStop},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				path := writeRolesFile(t, testCase.json)

				authorizer, err := authz.Load(path)
				if err != nil {
					t.Fatalf("expected no error, got [%v]", err)
				}

				for agentID, actions := range testCase.expectedPermissions {
					for _, action := range actions {
						err = authorizer.Authorize(agentID, action)
						if err != nil {
							t.Errorf(
								"expected permission [agent %s action %s], got %v",
								agentID,
								action,
								err,
							)
						}
					}
				}
			},
		)
	}
}

// TestLoadRejects covers the roles files that Load refuses with a sentinel
// error.
func TestLoadRejects(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		json          json.RawMessage
		expectedError error
	}{
		{
			name:          "empty object",
			json:          []byte("{}"),
			expectedError: authz.ErrEmptyRoles,
		},
		{
			name:          "json null",
			json:          []byte("null"),
			expectedError: authz.ErrEmptyRoles,
		},
		{
			name:          "unknown role",
			json:          []byte(`{"user":"invalid-role"}`),
			expectedError: authz.ErrUnknownRole,
		},
		{
			name:          "null role",
			json:          []byte(`{"user":null}`),
			expectedError: authz.ErrUnknownRole,
		},
		{
			name:          "empty agent id",
			json:          []byte(`{"":"USER"}`),
			expectedError: authz.ErrInvalidAgentID,
		},
		{
			name:          "blank agent id",
			json:          []byte(`{"  ":"USER"}`),
			expectedError: authz.ErrInvalidAgentID,
		},
		{
			name:          "agent id with a slash",
			json:          []byte(`{"a/b":"USER"}`),
			expectedError: authz.ErrInvalidAgentID,
		},
		{
			name:          "agent id with dots",
			json:          []byte(`{"../x":"USER"}`),
			expectedError: authz.ErrInvalidAgentID,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				path := writeRolesFile(t, testCase.json)

				authorizer, err := authz.Load(path)
				if !errors.Is(err, testCase.expectedError) {
					t.Fatalf("expected [%v], got [%v]", testCase.expectedError, err)
				}

				if authorizer != nil {
					t.Fatal("expected no authorizer alongside an error, got one")
				}
			},
		)
	}
}

// TestLoadErrors covers the failures that carry no sentinel of this package,
// because the file is unreadable or is not the JSON object that Load expects.
func TestLoadErrors(t *testing.T) {
	t.Parallel()

	t.Run("nonexistent file", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "does-not-exist.json")

		_, err := authz.Load(path)
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected [%v], got [%v]", os.ErrNotExist, err)
		}
	})

	testCases := []struct {
		name string
		json json.RawMessage
	}{
		{name: "malformed json", json: []byte("{")},
		{name: "json array", json: []byte("[]")},
		{name: "json string", json: []byte(`"USER"`)},
		{name: "trailing content", json: []byte(`{"user":"USER"} trailing`)},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				path := writeRolesFile(t, testCase.json)

				authorizer, err := authz.Load(path)
				if err == nil {
					t.Fatal("expected an error, got nil")
				}

				if authorizer != nil {
					t.Fatal("expected no authorizer alongside an error, got one")
				}
			},
		)
	}
}

// TestLoadErrorNamesEntry checks that a rejected entry is reported along with
// the agent it belongs to and the role as it is written in the file.
func TestLoadErrorNamesEntry(t *testing.T) {
	t.Parallel()

	path := writeRolesFile(t, []byte(`{"smith":"USER","jones":null}`))

	_, err := authz.Load(path)
	if !errors.Is(err, authz.ErrUnknownRole) {
		t.Fatalf("expected [%v], got [%v]", authz.ErrUnknownRole, err)
	}

	if !strings.Contains(err.Error(), "jones") {
		t.Errorf("expected the error to name the agent jones, got [%v]", err)
	}

	if !strings.Contains(err.Error(), "null") {
		t.Errorf("expected the error to report the role as written, got [%v]", err)
	}
}

// TestLoadErrorNamesPath checks that every failure names the file, including the
// empty-roles one.
func TestLoadErrorNamesPath(t *testing.T) {
	t.Parallel()

	path := writeRolesFile(t, []byte("{}"))

	_, err := authz.Load(path)
	if !errors.Is(err, authz.ErrEmptyRoles) {
		t.Fatalf("expected [%v], got [%v]", authz.ErrEmptyRoles, err)
	}

	if !strings.Contains(err.Error(), path) {
		t.Errorf("expected the error to name the file [%s], got [%v]", path, err)
	}
}

// writeRolesFile writes input to a file in a temporary directory, and returns
// the path to it.
func writeRolesFile(t *testing.T, input json.RawMessage) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "roles.json")

	err := os.WriteFile(path, input, 0o600)
	if err != nil {
		t.Fatalf("unable to write to a file [%s]: %v", path, err)
	}

	return path
}

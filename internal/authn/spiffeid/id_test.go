package spiffeid_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/tkngch/fizzled-go/internal/authn/spiffeid"
)

func TestNew(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                   string
		input                  string
		expectedTrustDomain    string
		expectedPathComponents []string
	}{
		{
			name:                   "empty path",
			input:                  "spiffe://trustdomain",
			expectedTrustDomain:    "trustdomain",
			expectedPathComponents: []string{},
		},
		{
			name:                   "single path component",
			input:                  "spiffe://trustdomain/path",
			expectedTrustDomain:    "trustdomain",
			expectedPathComponents: []string{"path"},
		},
		{
			name:                   "two path components",
			input:                  "spiffe://trustdomain/path/subpath",
			expectedTrustDomain:    "trustdomain",
			expectedPathComponents: []string{"path", "subpath"},
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				sid, err := spiffeid.New(testCase.input)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if sid.TrustDomain() != testCase.expectedTrustDomain {
					t.Errorf(
						"expected [%s] trust-domain, got [%s]",
						testCase.expectedTrustDomain,
						sid.TrustDomain(),
					)
				}

				if !slices.Equal(sid.PathComponents(), testCase.expectedPathComponents) {
					t.Errorf(
						"expected [%s] path-components, got [%s]",
						strings.Join(testCase.expectedPathComponents, ", "),
						strings.Join(sid.PathComponents(), ", "),
					)
				}
			},
		)
	}
}

func TestNewError(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		input         string
		expectedError error
	}{
		{
			name:          "not spiffe",
			input:         "s",
			expectedError: spiffeid.ErrNotSPIFFE,
		},
		{
			name:          "uppercase in schema",
			input:         "Spiffe://",
			expectedError: spiffeid.ErrNotSPIFFE,
		},
		{
			name:          "empty trust domain",
			input:         "spiffe://",
			expectedError: spiffeid.ErrInvalidTrustDomain,
		},
		{
			name:          "uppercase in trust domain",
			input:         "spiffe://TrustDomain",
			expectedError: spiffeid.ErrInvalidTrustDomain,
		},
		{
			name:          "invalid character in trust domain",
			input:         "spiffe://$",
			expectedError: spiffeid.ErrInvalidTrustDomain,
		},
		{
			name:          "percent-encoded characters in trust domain",
			input:         "spiffe://%21%23%24/path/",
			expectedError: spiffeid.ErrInvalidTrustDomain,
		},
		{
			name:          "percent-encoded characters in path",
			input:         "spiffe://trustdomain/%21%23%24",
			expectedError: spiffeid.ErrInvalidPathComponent,
		},
		{
			name:          "empty component in path",
			input:         "spiffe://trustdomain//path",
			expectedError: spiffeid.ErrInvalidPathComponent,
		},
		{
			name:          "path modifier, `.`, in path component",
			input:         "spiffe://trustdomain/./path",
			expectedError: spiffeid.ErrInvalidPathComponent,
		},
		{
			name:          "path modifier, `..`, in path component",
			input:         "spiffe://trustdomain/../path",
			expectedError: spiffeid.ErrInvalidPathComponent,
		},
		{
			name:          "a trailing slash",
			input:         "spiffe://trustdomain/path/",
			expectedError: spiffeid.ErrInvalidPathComponent,
		},
		{
			name:          "invalid character in path",
			input:         "spiffe://trustdomain/path/$/other",
			expectedError: spiffeid.ErrInvalidPathComponent,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				sid, err := spiffeid.New(testCase.input)
				if !errors.Is(err, testCase.expectedError) {
					t.Fatalf("expected [%v], got [%v]: %v", testCase.expectedError, err, sid)
				}
			},
		)
	}
}

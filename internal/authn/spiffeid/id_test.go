package spiffeid_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/tkngch/fizzled-go/internal/authn/spiffeid"
)

// The SPIFFE size limits.
const (
	maxIDLength          = 2048
	maxTrustDomainLength = 255
)

func TestParse(t *testing.T) {
	t.Parallel()

	longestPath := strings.Repeat("a", maxIDLength-len("spiffe://trustdomain/"))
	longestTrustDomain := strings.Repeat("a", maxTrustDomainLength)

	testCases := []struct {
		name                   string
		input                  string
		expectedTrustDomain    string
		expectedPath           string
		expectedPathComponents []string
	}{
		{
			name:                   "empty path",
			input:                  "spiffe://trustdomain",
			expectedTrustDomain:    "trustdomain",
			expectedPath:           "",
			expectedPathComponents: []string{},
		},
		{
			name:                   "single path component",
			input:                  "spiffe://trustdomain/path",
			expectedTrustDomain:    "trustdomain",
			expectedPath:           "/path",
			expectedPathComponents: []string{"path"},
		},
		{
			name:                   "two path components",
			input:                  "spiffe://trustdomain/path/subpath",
			expectedTrustDomain:    "trustdomain",
			expectedPath:           "/path/subpath",
			expectedPathComponents: []string{"path", "subpath"},
		},
		{
			name:                   "uppercase path component",
			input:                  "spiffe://trustdomain/PathComponent",
			expectedTrustDomain:    "trustdomain",
			expectedPath:           "/PathComponent",
			expectedPathComponents: []string{"PathComponent"},
		},
		{
			name:                   "longest permitted id",
			input:                  "spiffe://trustdomain/" + longestPath,
			expectedTrustDomain:    "trustdomain",
			expectedPath:           "/" + longestPath,
			expectedPathComponents: []string{longestPath},
		},
		{
			name:                   "longest permitted trust domain",
			input:                  "spiffe://" + longestTrustDomain,
			expectedTrustDomain:    longestTrustDomain,
			expectedPath:           "",
			expectedPathComponents: []string{},
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				spiffeID, err := spiffeid.Parse(testCase.input)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if spiffeID.String() != testCase.input {
					t.Errorf("expected [%s], got [%s]", testCase.input, spiffeID.String())
				}

				if spiffeID.TrustDomain() != testCase.expectedTrustDomain {
					t.Errorf(
						"expected [%s] trust-domain, got [%s]",
						testCase.expectedTrustDomain,
						spiffeID.TrustDomain(),
					)
				}

				// Path keeps its leading separator, so that a bare trailing
				// slash stays distinguishable from a path-less ID.
				if spiffeID.Path() != testCase.expectedPath {
					t.Errorf(
						"expected [%s] path, got [%s]",
						testCase.expectedPath,
						spiffeID.Path(),
					)
				}

				if !slices.Equal(spiffeID.PathComponents(), testCase.expectedPathComponents) {
					t.Errorf(
						"expected [%s] path-components, got [%s]",
						strings.Join(testCase.expectedPathComponents, ", "),
						strings.Join(spiffeID.PathComponents(), ", "),
					)
				}
			},
		)
	}
}

func TestParseError(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		input         string
		expectedError error
	}{
		{
			name:          "empty",
			input:         "",
			expectedError: spiffeid.ErrNotSPIFFE,
		},
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
			name:          "a bare trailing slash",
			input:         "spiffe://trustdomain/",
			expectedError: spiffeid.ErrInvalidPathComponent,
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
		{
			name:          "trust domain too long",
			input:         "spiffe://" + strings.Repeat("a", maxTrustDomainLength+1),
			expectedError: spiffeid.ErrTrustDomainTooLong,
		},
		{
			// A trust domain over the limit is too long whatever else is wrong
			// with it, so the length is the error reported.
			name:          "trust domain too long and invalid",
			input:         "spiffe://" + strings.Repeat("$", maxTrustDomainLength+1),
			expectedError: spiffeid.ErrTrustDomainTooLong,
		},
		{
			name:          "spiffe id too long",
			input:         "spiffe://trustdomain/" + strings.Repeat("a", maxIDLength+1),
			expectedError: spiffeid.ErrIDTooLong,
		},
		{
			name:          "userinfo",
			input:         "spiffe://user@trustdomain/path",
			expectedError: spiffeid.ErrInvalidTrustDomain,
		},
		{
			name:          "port",
			input:         "spiffe://trustdomain:8080/path",
			expectedError: spiffeid.ErrInvalidTrustDomain,
		},
		{
			name:          "query",
			input:         "spiffe://trustdomain/path?query=1",
			expectedError: spiffeid.ErrInvalidPathComponent,
		},
		{
			name:          "fragment",
			input:         "spiffe://trustdomain/path#fragment",
			expectedError: spiffeid.ErrInvalidPathComponent,
		},
		{
			// The anchors in the patterns are ^ and $, and in most regexp
			// engines $ also matches just before a trailing newline, which would
			// let a newline ride along on an otherwise valid id. Go's $ is \z
			// and does not.
			name:          "trailing newline after a path",
			input:         "spiffe://trustdomain/path\n",
			expectedError: spiffeid.ErrInvalidPathComponent,
		},
		{
			name:          "trailing newline after a trust domain",
			input:         "spiffe://trustdomain\n",
			expectedError: spiffeid.ErrInvalidTrustDomain,
		},
		{
			name:          "newline inside a path component",
			input:         "spiffe://trustdomain/pa\nth",
			expectedError: spiffeid.ErrInvalidPathComponent,
		},
		{
			// The character classes are ASCII, so anything above it is out
			// whether or not it is well-formed UTF-8. Go's regexp reads an
			// invalid byte as U+FFFD, which matches neither class either.
			name:          "non-ascii in trust domain",
			input:         "spiffe://trustdomäin/path",
			expectedError: spiffeid.ErrInvalidTrustDomain,
		},
		{
			name:          "non-ascii in path",
			input:         "spiffe://trustdomain/päth",
			expectedError: spiffeid.ErrInvalidPathComponent,
		},
		{
			name:          "invalid utf-8 in trust domain",
			input:         "spiffe://trustdomain\xff",
			expectedError: spiffeid.ErrInvalidTrustDomain,
		},
		{
			name:          "invalid utf-8 in path",
			input:         "spiffe://trustdomain/path\xff",
			expectedError: spiffeid.ErrInvalidPathComponent,
		},
		{
			name:          "null byte in path",
			input:         "spiffe://trustdomain/pa\x00th",
			expectedError: spiffeid.ErrInvalidPathComponent,
		},
	}

	for _, testCase := range testCases {
		t.Run(
			testCase.name,
			func(t *testing.T) {
				t.Parallel()

				spiffeID, err := spiffeid.Parse(testCase.input)
				if !errors.Is(err, testCase.expectedError) {
					t.Fatalf("expected [%v], got [%v]: %v", testCase.expectedError, err, spiffeID)
				}
			},
		)
	}
}

// TestZeroID covers the ID that never went through Parse. It is what every
// caller in the tree discards along with an error, so it has to read as an
// identity that carries nothing rather than as one that carries something
// unset.
func TestZeroID(t *testing.T) {
	t.Parallel()

	var spiffeID spiffeid.ID

	if spiffeID.String() != "" {
		t.Errorf("expected the empty string, got [%s]", spiffeID.String())
	}

	if spiffeID.TrustDomain() != "" {
		t.Errorf("expected no trust domain, got [%s]", spiffeID.TrustDomain())
	}

	if spiffeID.Path() != "" {
		t.Errorf("expected no path, got [%s]", spiffeID.Path())
	}

	if len(spiffeID.PathComponents()) != 0 {
		t.Errorf("expected no path components, got %v", spiffeID.PathComponents())
	}
}

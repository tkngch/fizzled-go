package spiffeid

import (
	"fmt"
	"regexp"
	"strings"
)

// ID represents a SPIFFE ID. It is an immutable value: the zero ID is the empty
// ID, every field is set once by Parse, and the type is comparable, so an ID
// can be compared with == and used as a map key.
type ID struct {
	uri         string
	trustDomain string
	path        string
}

const (
	uriScheme       = "spiffe://"
	uriSchemeLength = len(uriScheme)

	// maxIDLength and maxTrustDomainLength are the SPIFFE-ID size limits: a
	// SPIFFE ID is at most 2048 bytes, and a trust domain at most 255 bytes.
	// https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#2-spiffe-identity
	maxIDLength          = 2048
	maxTrustDomainLength = 255
)

var (
	validTrustDomainPattern   = regexp.MustCompile(`^[a-z0-9._-]+$`)
	validPathComponentPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
)

// Parse parses a SPIFFE ID from a string. It rejects anything that does not
// follow the SPIFFE standard, including percent-encoding, a port, userinfo, a
// query, a fragment, and an empty path component.
func Parse(uri string) (ID, error) {
	if !strings.HasPrefix(uri, uriScheme) {
		return ID{}, fmt.Errorf("parse spiffeid: %w", ErrNotSPIFFE)
	}

	if len(uri) > maxIDLength {
		return ID{}, fmt.Errorf("parse spiffeid: %w", ErrIDTooLong)
	}

	trustDomain, _, _ := strings.Cut(uri[uriSchemeLength:], "/")

	// The path keeps its leading separator, so that a bare trailing slash
	// (e.g., "spiffe://trustdomain/") stays distinguishable from a path-less
	// ID.
	path := uri[uriSchemeLength+len(trustDomain):]

	err := validateTrustDomain(trustDomain)
	if err != nil {
		return ID{}, fmt.Errorf("parse spiffeid: %w", err)
	}

	err = validatePath(path)
	if err != nil {
		return ID{}, fmt.Errorf("parse spiffeid: %w", err)
	}

	return ID{uri: uri, trustDomain: trustDomain, path: path}, nil
}

// TrustDomain is the trust-domain of the SPIFFE ID.
func (i ID) TrustDomain() string {
	return i.trustDomain
}

// Path is the path of the SPIFFE ID, keeping its leading separator, or the
// empty string when the ID carries no path.
func (i ID) Path() string {
	return i.path
}

// PathComponents is the path of the SPIFFE ID, split on the separator. It
// returns an empty slice when the ID carries no path.
func (i ID) PathComponents() []string {
	if i.path == "" {
		return []string{}
	}

	return strings.Split(i.path[1:], "/")
}

// String is the SPIFFE ID as the URI it was parsed from.
func (i ID) String() string {
	return i.uri
}

// validateTrustDomain validates that the trust domain follows the SPIFFE
// standard:
// https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#21-trust-domain
func validateTrustDomain(trustDomain string) error {
	if len(trustDomain) > maxTrustDomainLength {
		return fmt.Errorf(
			"validate trust-domain (%d bytes): %w",
			len(trustDomain),
			ErrTrustDomainTooLong,
		)
	}

	if !validTrustDomainPattern.MatchString(trustDomain) {
		return fmt.Errorf("validate trust-domain [%s]: %w", trustDomain, ErrInvalidTrustDomain)
	}

	return nil
}

// validatePath validates that each component follows the SPIFFE standard:
// https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#22-path
func validatePath(path string) error {
	if path == "" {
		return nil
	}

	components := strings.SplitSeq(path[1:], "/")
	for component := range components {
		if !validPathComponentPattern.MatchString(component) || component == "." ||
			component == ".." {
			return fmt.Errorf(
				"validate path-component [%s]: %w",
				component,
				ErrInvalidPathComponent,
			)
		}
	}

	return nil
}

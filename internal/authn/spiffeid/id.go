package spiffeid

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ID represents SPIFFE ID.
type ID struct {
	uri            string
	trustDomain    string
	pathComponents []string
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
	// ErrNotSPIFFE indicates that id does not have spiffe scheme.
	ErrNotSPIFFE = errors.New("not spiffe scheme")

	// ErrIDTooLong indicates that the SPIFFE ID exceeds the maximum length.
	ErrIDTooLong = errors.New("spiffe id too long")

	// ErrInvalidTrustDomain indicates that the trust domain does not follow the
	// SPIFFE standard.
	ErrInvalidTrustDomain = errors.New("invalid trust domain")

	// ErrInvalidPathComponent indicates that a path component does not follow
	// the SPIFFE standard.
	ErrInvalidPathComponent = errors.New("invalid path component")

	validTrustDomainPattern   = regexp.MustCompile(`^[a-z0-9\.\-\_]+$`)
	validPathComponentPattern = regexp.MustCompile(`^[a-zA-Z0-9\.\-\_]+$`)
)

// New parses SPIFFEID from string.
func New(uri string) (ID, error) {
	if !strings.HasPrefix(uri, uriScheme) {
		return ID{}, fmt.Errorf("new spiffeid: %w", ErrNotSPIFFE)
	}

	if len(uri) > maxIDLength {
		return ID{}, fmt.Errorf("new spiffeid: %w", ErrIDTooLong)
	}

	parts := strings.Split(uri[uriSchemeLength:], "/")

	trustDomain := ""
	if len(parts) > 0 {
		trustDomain = parts[0]
	}

	pathComponents := []string{}
	if len(parts) > 1 {
		pathComponents = parts[1:]
	}

	spiffeid := ID{
		uri:            uri,
		trustDomain:    trustDomain,
		pathComponents: pathComponents,
	}

	err := spiffeid.validateTrustDomain()
	if err != nil {
		return ID{}, fmt.Errorf("new spiffeid: %w", err)
	}

	err = spiffeid.validatePathComponents()
	if err != nil {
		return ID{}, fmt.Errorf("new spiffeid: %w", err)
	}

	return spiffeid, nil
}

// TrustDomain is the trust-domain of SPIFFE ID.
func (i ID) TrustDomain() string {
	return i.trustDomain
}

// PathComponents is the path-components of SPIFFE ID.
func (i ID) PathComponents() []string {
	return i.pathComponents
}

func (i ID) String() string {
	return i.uri
}

// validateTrustDomain validates that the authority string follows the SPIFFE standard:
// https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#21-trust-domain
func (i ID) validateTrustDomain() error {
	if len(i.trustDomain) > maxTrustDomainLength {
		return fmt.Errorf(
			"validate authority: too long (%d bytes): %w",
			len(i.trustDomain),
			ErrInvalidTrustDomain,
		)
	}

	if !validTrustDomainPattern.MatchString(i.trustDomain) {
		return fmt.Errorf("validate authority [%s]: %w", i.trustDomain, ErrInvalidTrustDomain)
	}

	return nil
}

// validatePathComponents validates that each component follows the SPIFFE standard:
// https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md#22-path
func (i ID) validatePathComponents() error {
	for _, component := range i.pathComponents {
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

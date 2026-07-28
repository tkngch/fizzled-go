package spiffeid

import "errors"

var (
	// ErrNotSPIFFE indicates that an id does not have the spiffe scheme.
	ErrNotSPIFFE = errors.New("not spiffe scheme")

	// ErrIDTooLong indicates that the SPIFFE ID exceeds the maximum length.
	ErrIDTooLong = errors.New("spiffe id too long")

	// ErrTrustDomainTooLong indicates that the trust domain exceeds the maximum
	// length.
	ErrTrustDomainTooLong = errors.New("trust domain too long")

	// ErrInvalidTrustDomain indicates that the trust domain carries a character
	// that the SPIFFE standard does not allow, or is empty.
	ErrInvalidTrustDomain = errors.New("invalid trust domain")

	// ErrInvalidPathComponent indicates that a path component does not follow
	// the SPIFFE standard.
	ErrInvalidPathComponent = errors.New("invalid path component")
)

// Package spiffeid parses and validates a URI as a SPIFFE ID. This package is
// intentionally domain-free.
//
// Parse provides a way to build a valid ID, and it is deliberately stricter
// than a URI parser: it reads the text using strings.Cut and two regexp
// patterns, rather than through net/url, so nothing is normalised on the way
// in. It rejects anything outside the character classes the SPIFFE standard
// allows for a trust domain and a path component: including percent-encoding,
// userinfo, a port, a query, a fragment, an empty path component, and the
// relative modifiers "." and "..".
package spiffeid

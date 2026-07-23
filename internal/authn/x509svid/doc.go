// Package x509svid validates a parsed X.509-SVID leaf certificate and its
// signing chain against the SPIFFE X509-SVID standard, and extracts the SPIFFE
// ID from the leaf's URI SAN. It operates on already-parsed certificates and
// performs no cryptographic chain verification. This package is intentionally
// domain-free.
package x509svid

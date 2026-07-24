// Package x509svid parses certificates, cryptographically verifies them,
// validates a leaf certificate and its signing chain against the SPIFFE
// X509-SVID standard, and extracts the SPIFFE ID from the leaf's URI SAN. This
// package is intentionally domain-free.
package x509svid

// Package x509svid verifies X509-SVID certificate chains.
//
// A Verifier binds a set of trust roots and a clock-skew tolerance, then turns
// a peer chain into a Leaf: it verifies the chain cryptographically, validates
// the leaf and its signing certificates against the SPIFFE X509-SVID standard,
// and extracts the SPIFFE ID from the leaf's URI SAN.
//
// ValidateSigningCertificate is the one rule set exported on its own, because a
// root is the same certificate seen twice: an anchor a caller installs into a
// trust bundle, and a signing certificate validated during a handshake. A
// caller assembling a bundle can hold a root to the standard the handshake will
// apply to it, instead of to a second copy of the rules that is free to drift.
//
// This package is intentionally domain-free. It asserts what the standard
// requires and nothing more, so issuance policy such as a required key
// algorithm, a required extended key usage, the trust domain a leaf is expected
// to be in, or the size of the skew tolerance stays with the caller.
//
// Revocation is out of scope: there is no CRL and no OCSP check here. SPIFFE
// answers a compromised key with an SVID short-lived enough that waiting it out
// is the remedy, so what bounds the damage is the validity window a chain is
// checked against, and the expiry of the roots in the bundle.
package x509svid

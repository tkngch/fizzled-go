// Package testpki issues the certificates the authentication tests are written
// against: a self-signed authority, an intermediate under it, and the leaves
// either one signs.
//
// This package provides the common plumbing (keys, templates, signing, PEM
// files) for the tests of authn and of x509svid. Each package is expected to
// provide the fizzled identities or the SPIFFE shapes, to suite individual
// tests.
//
// Every constructor takes a testing.TB and fails the test rather than returning
// an error: a certificate that cannot be issued is a broken test, not a case
// under test. TB rather than *testing.T so that a fuzz target can build its
// seed corpus from the same helpers. The package is under
// internal/authn/internal so that nothing outside the authentication layer can
// build a certificate with it.
package testpki

// Package client calls the gRPC contract in proto/fizzled/v1 over mTLS.
//
// The package is the mirror of server. The generated types and the gRPC
// packages stop here too: what a caller receives is a string, a Status, or a
// line of JSON, and the depguard rules in .golangci.yml keep it that way.
//
// Two things follow from being that edge:
//
//   - Every failure leaves as one of this package's sentinels, so a caller
//     can map failures onto exit codes without importing gRPC.
//
//   - New reads every path in its Config once, at construction, so a
//     misconfigured client fails before it dials rather than on its first RPC.
//
// The four methods mirror the four RPCs one for one. The policy of what to do
// with what they return, such as whether a terminal status is worth reporting,
// belongs to the caller and not to this package.
package client

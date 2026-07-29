// Package server serves the gRPC contract in proto/fizzled/v1 over mTLS.
//
// The package is the edge of the application. The generated types and the gRPC
// packages stop here: everything inside works in the domain types of worker and
// registry, and the depguard rules in .golangci.yml keep it that way.
//
// Three things live here, layered:
//
//   - Server owns a listener, the transport and the shutdown sequence. It reads
//     every path in its Config once, at construction, so a misconfigured server
//     fails at start-up rather than on its first connection.
//
//   - Interceptor authenticates the peer and authorizes the action behind an
//     RPC, before any handler runs. It resolves the agent id once per RPC and
//     puts it in the context.
//
//   - Service implements the handlers. Every one of them takes authentication
//     and authorization as already done and reads the agent id the Interceptor
//     resolved.
//
// A handler reports a failure as a gRPC status and never as a field on a
// response.
package server

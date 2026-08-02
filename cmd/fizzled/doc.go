// Package main is fizzled, the server.
//
// The program is a thin shell around internal/server, which is where the
// transport, the interceptors and the countdowns live and are tested. What is
// left here is only what a service manager needs and a library caller does not:
// a flag set, a place to log to, and an exit code.
//
// The defaults are the paths that `make secrets` writes, so a stock working
// copy runs fizzled with no flags at all.
package main

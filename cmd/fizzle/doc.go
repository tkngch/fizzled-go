// Package main is fizzle, the command-line client of the fizzled service.
//
// The command is a thin shell around internal/client, which is where the RPCs,
// the mTLS and the failure vocabulary live and are tested. What is left here is
// only what a shell needs and a library caller does not: an argument grammar, a
// place to print to, and an exit code.
package main

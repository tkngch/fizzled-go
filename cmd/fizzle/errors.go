package main

import (
	"errors"

	"github.com/tkngch/fizzled-go/internal/client"
)

// errUsage indicates a failure to execute a command. For example, a command
// does not exist, and a flag is unknown.
var errUsage = errors.New("invalid usage")

const (
	// exitSuccess reports that the command did what it was asked.
	exitSuccess = 0

	// exitFailure reports a failure in the server or the wire.
	exitFailure = 1

	// exitUsage reports an error in an invocation or a configuration.
	exitUsage = 2
)

// exitCodeFor is the code that err leaves the process with.
func exitCodeFor(err error) int {
	if err == nil {
		return exitSuccess
	}

	if errors.Is(err, errUsage) ||
		errors.Is(err, client.ErrInvalidArgument) ||
		errors.Is(err, client.ErrConfig) {
		return exitUsage
	}

	return exitFailure
}

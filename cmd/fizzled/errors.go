package main

import "errors"

var (
	// errUsage indicates that the command line could not be read: for example,
	// an invalid flag was set.
	errUsage = errors.New("invalid usage")

	// errConfig indicates that a server could not be started with the named
	// flags: for example, a trust bundle or an SVID could not be read, a roles
	// file grants nothing, or an address could not be listened on.
	errConfig = errors.New("invalid configuration")
)

const (
	// exitSuccess reports a shutdown that drained every stream.
	exitSuccess = 0

	// exitFailure reports a failure while serving, including a shutdown that
	// ran out of grace with streams still open.
	exitFailure = 1

	// exitUsage reports a failure to start the server.
	exitUsage = 2
)

// exitCodeFor returns the exit code for err.
func exitCodeFor(err error) int {
	if err == nil {
		return exitSuccess
	}

	if errors.Is(err, errUsage) || errors.Is(err, errConfig) {
		return exitUsage
	}

	return exitFailure
}

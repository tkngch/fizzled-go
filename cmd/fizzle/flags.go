package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/tkngch/fizzled-go/internal/client"
)

const (
	defaultAddress  = "localhost:8443"
	defaultCAPath   = ".secrets/ca.crt"
	defaultCertPath = ".secrets/agent-smith.crt"
	defaultKeyPath  = ".secrets/agent-smith-private.key"
)

// usage is the whole of what -h prints, and what accompanies a usage error.
const usage = `fizzle runs stochastic countdowns on a fizzled server.

Usage:
  fizzle <command> [flags] <argument>

Commands:
  start <count>    start a job, and print its job id
  stop <id>        request a stop, whether or not it is still running
  status <id>      print RUNNING, COMPLETED, STOPPED or FAILED
  outputs <id>     print every tick as one line of JSON, until the stream ends

Flags:
  --server <address>   the server to dial (default "localhost:8443")
  --ca <path>          the trust bundle the server is verified against
                       (default ".secrets/ca.crt")
  --cert <path>        the certificate this client presents
                       (default ".secrets/agent-smith.crt")
  --key <path>         the private key for that certificate
                       (default ".secrets/agent-smith-private.key")

Exit codes:
  0   the command succeeded
  1   the command failed at the server, never reached it, or was interrupted
  2   the command line, or the files it named, could not be used
`

// invocation is one command that is read but not yet acted on.
type invocation struct {
	// name is the subcommand, and argument the single operand it takes.
	name     string
	argument string

	// config is what the flags ask the client to be built from.
	config client.Config
}

// parse resolves args into the invocation it describes.
//
// args excludes the program name, so args[0] names the subcommand and whatever
// follows is that subcommand's flags.
func parse(args []string) (invocation, error) {
	// Declared rather than composed, so that every failure below returns the
	// same zero value without restating its fields.
	var parsed invocation

	if len(args) == 0 {
		return parsed, fmt.Errorf("parse: no command given: %w", errUsage)
	}

	parsed.name = args[0]

	if isHelpRequest(parsed.name) {
		return parsed, fmt.Errorf("parse: %w", flag.ErrHelp)
	}

	// An unknown command is rejected before its flags are read, so that a
	// misspelt command is reported as such.
	switch parsed.name {
	case commandStart, commandStop, commandStatus, commandOutputs:
	default:
		return parsed, fmt.Errorf("parse: unknown command [%s]: %w", parsed.name, errUsage)
	}

	flags := newFlagSet(parsed.name, &parsed.config)

	err := flags.Parse(args[1:])

	// ErrHelp is a request rather than a mistake, so it is unwrapped by
	// errUsage.
	if errors.Is(err, flag.ErrHelp) {
		return parsed, fmt.Errorf("parse [%s]: %w", parsed.name, err)
	}

	if err != nil {
		return parsed, fmt.Errorf("parse [%s]: %w: %w", parsed.name, errUsage, err)
	}

	positionalArguments := flags.Args()
	if len(positionalArguments) != 1 {
		return parsed, fmt.Errorf(
			"parse [%s]: expected one positional argument, got %d: %w",
			parsed.name,
			len(positionalArguments),
			errUsage,
		)
	}

	parsed.argument = positionalArguments[0]

	return parsed, nil
}

// newFlagSet is the flag set. All four subcommands take the same four flags, so
// there is one of these rather than four.
//
// The descriptions below are never rendered: the output is discarded so that -h
// reaches stdout, and usage above is what is printed in its place. They are
// kept as documentation, and any wording meant for a reader belongs in usage.
func newFlagSet(name string, config *client.Config) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	flags.StringVar(&config.Address, "server", defaultAddress, "the server to dial")
	flags.StringVar(&config.CAPath, "ca", defaultCAPath, "the trust bundle to verify against")
	flags.StringVar(
		&config.CertPath,
		"cert",
		defaultCertPath,
		"the certificate this client presents",
	)
	flags.StringVar(&config.KeyPath, "key", defaultKeyPath, "the private key for that certificate")

	return flags
}

// isHelpRequest reports whether arg asks for the usage. The flag package takes
// -h, -help and --help alike, and this is the one place they are read before a
// flag set exists to read them.
func isHelpRequest(arg string) bool {
	switch arg {
	case "-h", "-help", "--help":
		return true

	default:
		return false
	}
}

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/tkngch/fizzled-go/internal/server"
)

// The defaults are the paths that `make secrets` writes.
const (
	defaultAddress   = "localhost:8443"
	defaultCAPath    = ".secrets/ca.crt"
	defaultCertPath  = ".secrets/server.crt"
	defaultKeyPath   = ".secrets/server-private.key"
	defaultRolesPath = ".secrets/roles.json"
)

// usage is the whole of what -h prints.
const usage = `fizzled serves stochastic countdowns over mTLS.

Usage:
  fizzled [flags]

Flags:
  --server <address>   the address to listen on (default "localhost:8443")
  --ca <path>          the trust bundle every client is verified against
                       (default ".secrets/ca.crt")
  --cert <path>        the certificate this server presents
                       (default ".secrets/server.crt")
  --key <path>         the private key for that certificate
                       (default ".secrets/server-private.key")
  --roles <path>       the agent-to-role mapping to authorize from
                       (default ".secrets/roles.json")

The defaults are what "make secrets" writes, so a working copy needs no flags.
fizzled logs to stderr as JSON, and serves until it is sent SIGINT or SIGTERM.

Exit codes:
  0   the shutdown drained every open stream
  1   serving failed, or the shutdown ran out of grace with streams still open
  2   the flags or the files could not be used
`

// parse resolves args into the configuration to serve from.
//
// args excludes the program name.
func parse(args []string) (server.Config, error) {
	var config server.Config

	flags := flag.NewFlagSet("fizzled", flag.ContinueOnError)
	// Silence the flag package, so `-h` is directed to stdout.
	flags.SetOutput(io.Discard)

	flags.StringVar(&config.Address, "server", defaultAddress, "the address to listen on")
	flags.StringVar(&config.CAPath, "ca", defaultCAPath, "the trust bundle to verify against")
	flags.StringVar(&config.CertPath, "cert", defaultCertPath, "the certificate to present")
	flags.StringVar(&config.KeyPath, "key", defaultKeyPath, "the private key for it")
	flags.StringVar(&config.RolesPath, "roles", defaultRolesPath, "the agent-to-role mapping")

	err := flags.Parse(args)

	// ErrHelp is a request rather than a mistake, so it is deliberately left
	// unwrapped by errUsage.
	if errors.Is(err, flag.ErrHelp) {
		return config, fmt.Errorf("parse: %w", err)
	}

	if err != nil {
		return config, fmt.Errorf("parse: %w: %w", errUsage, err)
	}

	if flags.NArg() != 0 {
		return config, fmt.Errorf(
			"parse: expected no positional arguments, got %d: %w",
			flags.NArg(),
			errUsage,
		)
	}

	return config, nil
}

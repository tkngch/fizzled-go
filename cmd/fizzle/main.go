package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/tkngch/fizzled-go/internal/client"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	// os.Args[1:], because the program name is not one of the arguments a
	// command takes.
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)

	// Called rather than deferred, because os.Exit below would skip a deferred
	// call.
	stop()

	os.Exit(code)
}

// run carries out the command that args names, and returns the code the process
// should exit with.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	err := execute(ctx, args, stdout)
	if err == nil {
		return exitSuccess
	}

	// Print the usage on stdout, if it is requested.
	if errors.Is(err, flag.ErrHelp) {
		_, _ = fmt.Fprint(stdout, usage)

		return exitSuccess
	}

	if errors.Is(err, errUsage) {
		_, _ = fmt.Fprint(stderr, usage)
	}

	_, _ = fmt.Fprintf(stderr, "fizzle: %v\n", err)

	return exitCodeFor(err)
}

// execute resolves args into a command, and executes it.
func execute(ctx context.Context, args []string, stdout io.Writer) error {
	parsed, err := parse(args)
	if err != nil {
		return err
	}

	cmd, err := newCommand(parsed.name, parsed.argument)
	if err != nil {
		return err
	}

	// No logger is provided, because the outputs are written to stdout, and
	// there is no flag that would ask for more.
	//
	//nolint:contextcheck // authn.NewAuthenticator audits under its own context.
	fizzle, err := client.New(parsed.config, nil)
	if err != nil {
		// Deliberately not wrapped by errUsage: client.ErrConfig already exits
		// 2, and the usage answers a question an unreadable file did not ask.
		return fmt.Errorf("execute [%s]: %w", parsed.name, err)
	}

	defer func() { _ = fizzle.Close() }()

	return cmd.execute(ctx, fizzle, stdout)
}

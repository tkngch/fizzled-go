package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/tkngch/fizzled-go/internal/server"
)

func main() {
	// The server is shutdown when the context is cancelled, which is triggered
	// by SIGINT or SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	exitCode := run(ctx, os.Args[1:], os.Stdout, os.Stderr)

	// Called rather than deferred, because os.Exit below would skip a deferred
	// call.
	stop()

	os.Exit(exitCode)
}

// run serves until ctx is done, and returns the code the process should exit
// with.
//
// args excludes the program name.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	config, err := parse(args)

	// Print the usage on stdout, if it is requested.
	if errors.Is(err, flag.ErrHelp) {
		_, _ = fmt.Fprint(stdout, usage)

		return exitSuccess
	}

	if err != nil {
		// Failure to parse the flags. Print the usage with the diagnostic on
		// stdout and then exit.
		_, _ = fmt.Fprint(stderr, usage)
		_, _ = fmt.Fprintf(stderr, "fizzled: %v\n", err)

		return exitCodeFor(err)
	}

	logger := slog.New(slog.NewJSONHandler(stderr, nil))

	err = serve(ctx, config, logger)

	// WithoutCancel, because the context that ended the serve is the one these
	// lines would otherwise be recorded through, and a handler is free to drop
	// a record whose context is already done.
	stopped := context.WithoutCancel(ctx)

	if err != nil {
		logger.LogAttrs(
			stopped,
			slog.LevelError,
			"fizzled stopped",
			slog.String("error", err.Error()),
		)

		return exitCodeFor(err)
	}

	logger.LogAttrs(stopped, slog.LevelInfo, "fizzled stopped")

	return exitSuccess
}

// serve stands a server up from config and serves until ctx is done.
func serve(ctx context.Context, config server.Config, logger *slog.Logger) error {
	fizzled, err := server.New(ctx, config, logger)
	if err != nil {
		return fmt.Errorf("serve: %w: %w", errConfig, err)
	}

	// Log the bound address, because it may not be clear from the
	// configuration. For example, the configuration may have had a port of
	// zero, which resolves to a free port.
	logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		"fizzled is listening",
		slog.String("address", fizzled.Addr().String()),
	)

	err = fizzled.Serve(ctx)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}

	return nil
}

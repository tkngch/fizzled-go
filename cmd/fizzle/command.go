package main

import (
	"context"
	"fmt"
	"io"
	"strconv"

	"github.com/tkngch/fizzled-go/internal/client"
	"github.com/tkngch/fizzled-go/internal/worker"
)

const (
	commandStart   = "start"
	commandStop    = "stop"
	commandStatus  = "status"
	commandOutputs = "outputs"
)

// command represents one invocation, ready to run against a client.
//
// The client is a parameter rather than a field, so that whoever opens the
// connection is also the one that closes it.
type command interface {
	execute(ctx context.Context, fizzle *client.Client, stdout io.Writer) error
}

type startCommand struct {
	count int
}

type stopCommand struct {
	jobID worker.JobID
}

type statusCommand struct {
	jobID worker.JobID
}

type outputsCommand struct {
	jobID worker.JobID
}

// newCommand resolves name and argument into the command they name.
//
// It reads nothing but its arguments, so a command line that cannot be read is
// reported before anything is opened on the strength of it.
//
//nolint:ireturn // newCommand's whole job is to pick an implementation.
func newCommand(name, argument string) (command, error) {
	switch name {
	case commandStart:
		count, err := strconv.Atoi(argument)
		if err != nil {
			return nil, fmt.Errorf("new command [%s]: %w: %w", name, errUsage, err)
		}

		return startCommand{count: count}, nil

	case commandStop:
		return stopCommand{jobID: worker.JobID(argument)}, nil

	case commandStatus:
		return statusCommand{jobID: worker.JobID(argument)}, nil

	case commandOutputs:
		return outputsCommand{jobID: worker.JobID(argument)}, nil

	default:
		// Defensive: parse rejects an unknown command before it reaches here.
		return nil, fmt.Errorf("new command: unknown name [%s]: %w", name, errUsage)
	}
}

func (s startCommand) execute(ctx context.Context, fizzle *client.Client, stdout io.Writer) error {
	jobID, err := fizzle.Start(ctx, s.count)
	if err != nil {
		return fmt.Errorf("start execute [%d]: %w", s.count, err)
	}

	return writeLine(stdout, string(jobID))
}

func (s stopCommand) execute(ctx context.Context, fizzle *client.Client, _ io.Writer) error {
	_, err := fizzle.Stop(ctx, s.jobID)
	if err != nil {
		return fmt.Errorf("stop execute [%s]: %w", s.jobID, err)
	}

	return nil
}

func (s statusCommand) execute(ctx context.Context, fizzle *client.Client, stdout io.Writer) error {
	status, err := fizzle.GetStatus(ctx, s.jobID)
	if err != nil {
		return fmt.Errorf("status execute [%s]: %w", s.jobID, err)
	}

	return writeLine(stdout, string(status))
}

func (o outputsCommand) execute(
	ctx context.Context,
	fizzle *client.Client,
	stdout io.Writer,
) error {
	for tick, err := range fizzle.StreamOutput(ctx, o.jobID) {
		if err != nil {
			return fmt.Errorf("outputs [%s]: %w", o.jobID, err)
		}

		err = writeLine(stdout, string(tick))
		if err != nil {
			return fmt.Errorf("outputs [%s]: %w", o.jobID, err)
		}
	}

	return nil
}

// writeLine writes line, and a newline after it, to out.
//
// The error is returned rather than dropped: a command whose answer went
// nowhere did not succeed, however well the RPC behind it went.
func writeLine(out io.Writer, line string) error {
	_, err := fmt.Fprintln(out, line)
	if err != nil {
		return fmt.Errorf("write line: %w", err)
	}

	return nil
}

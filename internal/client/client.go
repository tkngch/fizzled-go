package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"math"

	"github.com/tkngch/fizzled-go/internal/authn"
	fizzledv1 "github.com/tkngch/fizzled-go/internal/gen/fizzled/v1"
	"github.com/tkngch/fizzled-go/internal/worker"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// Config is what a caller supplies to build a client.
type Config struct {
	// Address is the address that the server listens to, such as
	// "localhost:8443".
	Address string

	// CAPath is the trust bundle the server's SVID is verified against.
	CAPath string

	// CertPath and KeyPath are the client's own SVID, which it presents to the
	// server.
	CertPath string
	KeyPath  string
}

// Client calls the fizzled contract as the agent named by the SVID it presents.
//
// A Client is safe for concurrent use, and holds one connection however many
// calls are made through it. Close releases that connection.
type Client struct {
	connection *grpc.ClientConn
	fizzle     fizzledv1.FizzledServiceClient
}

// New builds a client from config.
//
// It takes no context: the connection is lazy, so nothing here dials and
// nothing here blocks. It reads the trust bundle and the SVID, and verifies the
// SVID using the same code the server will use. Thus a client which the server
// could never accept fails here.
//
// logger records the trust bundle that was loaded and the outcome of verifying
// the server on every connection. A nil logger discards them.
func New(config Config, logger *slog.Logger) (*Client, error) {
	if config.Address == "" {
		return nil, fmt.Errorf("new client: empty address: %w", ErrConfig)
	}

	authenticator, err := authn.NewAuthenticator(config.CAPath, logger)
	if err != nil {
		return nil, fmt.Errorf("new client: %w: %w", ErrConfig, err)
	}

	tlsConfig, err := authenticator.ClientConfig(config.CertPath, config.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("new client: %w: %w", ErrConfig, err)
	}

	connection, err := grpc.NewClient(
		config.Address,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	)
	if err != nil {
		return nil, fmt.Errorf("new client [%s]: %w: %w", config.Address, ErrConfig, err)
	}

	return &Client{
		connection: connection,
		fizzle:     fizzledv1.NewFizzledServiceClient(connection),
	}, nil
}

// Close releases the connection New opened.
func (c *Client) Close() error {
	err := c.connection.Close()
	// Ignore the error on already-closed connection.
	if err != nil && status.Code(err) != codes.Canceled {
		return fmt.Errorf("close: %w", err)
	}

	return nil
}

// Start starts a job and returns its id. The job is queryable, streamable and
// stoppable the instant the id comes back.
func (c *Client) Start(ctx context.Context, count int) (worker.JobID, error) {
	// The wire carries a 32-bit count.
	if count < math.MinInt32 || count > math.MaxInt32 {
		return "", fmt.Errorf("start [%d]: %w", count, ErrInvalidArgument)
	}

	request := &fizzledv1.StartRequest{Count: int32(count)}

	response, err := c.fizzle.Start(ctx, request)
	if err != nil {
		return "", errorFrom(fmt.Sprintf("start [%d]", count), err)
	}

	return worker.JobID(response.GetJobId()), nil
}

// Stop requests a stop and reports the status of the job. Stopping a job that
// has already ended is not an error.
//
// It reports ErrNotFound when the agent owns no job under jobID.
func (c *Client) Stop(ctx context.Context, jobID worker.JobID) (worker.Status, error) {
	request := &fizzledv1.StopRequest{JobId: string(jobID)}

	response, err := c.fizzle.Stop(ctx, request)
	if err != nil {
		return "", errorFrom(fmt.Sprintf("stop [%s]", jobID), err)
	}

	jobStatus, err := statusFrom(response.GetStatus())
	if err != nil {
		return "", fmt.Errorf("stop [%s]: %w", jobID, err)
	}

	return jobStatus, nil
}

// GetStatus reports the current status of a job.
//
// It reports ErrNotFound when the agent owns no job under jobID.
func (c *Client) GetStatus(ctx context.Context, jobID worker.JobID) (worker.Status, error) {
	request := &fizzledv1.GetStatusRequest{JobId: string(jobID)}

	response, err := c.fizzle.GetStatus(ctx, request)
	if err != nil {
		return "", errorFrom(fmt.Sprintf("get status [%s]", jobID), err)
	}

	jobStatus, err := statusFrom(response.GetStatus())
	if err != nil {
		return "", fmt.Errorf("get status [%s]: %w", jobID, err)
	}

	return jobStatus, nil
}

// StreamOutput yields the job's output, one canonical protobuf JSON encoding of
// a tick per element, replayed from the start of the job and then followed
// live.
//
// The sequence ends when the server closes the stream, once it has delivered
// the terminal tick. A failure yields one (nil, error) and then ends the
// sequence: a stream that has failed has nothing further to give. The stream is
// torn down whenever the sequence ends, so a consumer that stops early leaves
// nothing open.
func (c *Client) StreamOutput(ctx context.Context, jobID worker.JobID) iter.Seq2[[]byte, error] {
	operation := fmt.Sprintf("stream output [%s]", jobID)

	return func(yield func([]byte, error) bool) {
		// A context of this iterator's own, so that breaking out of the range
		// cancels the RPC. The caller's ctx would outlive it and hold the stream
		// open until the countdown ended.
		streamCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		request := &fizzledv1.StreamOutputRequest{JobId: string(jobID)}

		stream, err := c.fizzle.StreamOutput(streamCtx, request)
		if err != nil {
			yield(nil, errorFrom(operation, err))

			return
		}

		for {
			response, err := stream.Recv()

			// io.EOF is the server closing the stream behind its terminal tick.
			// That is how a countdown's output ends, not a failure.
			if errors.Is(err, io.EOF) {
				return
			}

			if err != nil {
				yield(nil, errorFrom(operation, err))

				return
			}

			encoded, err := tickJSON(response.GetTick())
			if err != nil {
				yield(nil, fmt.Errorf("%s: %w", operation, err))

				return
			}

			if !yield(encoded, nil) {
				return
			}
		}
	}
}

// statusFrom converts the status the wire carries into the one this package
// reports.
//
// STATUS_UNSPECIFIED is an error rather than a fifth constant: a registered
// job always has a status, so the server never sends it.
func statusFrom(wire fizzledv1.Status) (worker.Status, error) {
	switch wire {
	case fizzledv1.Status_STATUS_RUNNING:
		return worker.StatusRunning, nil

	case fizzledv1.Status_STATUS_COMPLETED:
		return worker.StatusCompleted, nil

	case fizzledv1.Status_STATUS_STOPPED:
		return worker.StatusStopped, nil

	case fizzledv1.Status_STATUS_FAILED:
		return worker.StatusFailed, nil

	case fizzledv1.Status_STATUS_UNSPECIFIED:
		return "", fmt.Errorf("status [%s]: %w", wire, ErrUnknownStatus)

	default:
		return "", fmt.Errorf("status [%s]: %w", wire, ErrUnknownStatus)
	}
}

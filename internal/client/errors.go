package client

import (
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The failures an RPC can leave as. They stand in for the gRPC status codes the
// server answers with, so that classifying a failure needs nothing but
// errors.Is.
var (
	// ErrInvalidArgument indicates that the server rejected an argument, such as
	// a count outside the range a countdown accepts.
	ErrInvalidArgument = errors.New("invalid argument")

	// ErrNotFound indicates that the agent owns no job under the requested id.
	// A job owned by another agent is reported this way too, so this error says
	// nothing about whether the id exists.
	ErrNotFound = errors.New("not found")

	// ErrPermissionDenied indicates that the agent holds no role granting the
	// action.
	ErrPermissionDenied = errors.New("permission denied")

	// ErrUnauthenticated indicates that the server did not accept the identity
	// this client presented.
	ErrUnauthenticated = errors.New("unauthenticated")

	// ErrUnavailable indicates that the RPC never reached a handler. A refused
	// mTLS handshake arrives here rather than at ErrUnauthenticated.
	ErrUnavailable = errors.New("unavailable")

	// ErrCanceled indicates that the call ended before the server answered,
	// because the caller's context did.
	ErrCanceled = errors.New("canceled")

	// ErrDeadlineExceeded indicates that the call ran out of time before the
	// server answered.
	ErrDeadlineExceeded = errors.New("deadline exceeded")

	// ErrRPC indicates a failure this package does not classify further.
	ErrRPC = errors.New("rpc failed")
)

var (
	// ErrConfig indicates that a Config is invalid: for example, a trust bundle
	// or an identity that could not be read.
	ErrConfig = errors.New("invalid configuration")

	// ErrUnknownStatus indicates that the server reported a status this package
	// does not know.
	ErrUnknownStatus = errors.New("unknown status")
)

// errorFrom turns the error an RPC returned into one of this package's
// sentinels, wrapped behind operation and the original status.
func errorFrom(operation string, err error) error {
	if err == nil {
		return nil
	}

	sentinel := ErrRPC

	switch status.Code(err) {
	case codes.InvalidArgument:
		sentinel = ErrInvalidArgument
	case codes.NotFound:
		sentinel = ErrNotFound
	case codes.PermissionDenied:
		sentinel = ErrPermissionDenied
	case codes.Unauthenticated:
		sentinel = ErrUnauthenticated
	case codes.Unavailable:
		sentinel = ErrUnavailable
	case codes.Canceled:
		sentinel = ErrCanceled
	case codes.DeadlineExceeded:
		sentinel = ErrDeadlineExceeded
	case codes.OK,
		codes.Unknown,
		codes.AlreadyExists,
		codes.ResourceExhausted,
		codes.FailedPrecondition,
		codes.Aborted,
		codes.OutOfRange,
		codes.Unimplemented,
		codes.Internal,
		codes.DataLoss:
		sentinel = ErrRPC
	}

	return fmt.Errorf("%s: %w: %w", operation, sentinel, err)
}

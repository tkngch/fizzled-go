package client_test

import (
	"errors"
	"io"
	"testing"

	"github.com/tkngch/fizzled-go/internal/client"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestErrorFrom(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		err      error
		expected error
	}{
		{
			name:     "CANCELLED",
			err:      status.Error(codes.Canceled, "answered"),
			expected: client.ErrCanceled,
		},
		{
			name:     "DEADLINE_EXCEEDED",
			err:      status.Error(codes.DeadlineExceeded, "answered"),
			expected: client.ErrDeadlineExceeded,
		},
		{
			name:     "UNKNOWN",
			err:      status.Error(codes.Unknown, "answered"),
			expected: client.ErrRPC,
		},
		{
			name:     "INVALID_ARGUMENT",
			err:      status.Error(codes.InvalidArgument, "answered"),
			expected: client.ErrInvalidArgument,
		},
		{
			name:     "NOT_FOUND",
			err:      status.Error(codes.NotFound, "answered"),
			expected: client.ErrNotFound,
		},
		{
			name:     "ALREADY_EXISTS",
			err:      status.Error(codes.AlreadyExists, "answered"),
			expected: client.ErrRPC,
		},
		{
			name:     "PERMISSION_DENIED",
			err:      status.Error(codes.PermissionDenied, "answered"),
			expected: client.ErrPermissionDenied,
		},
		{
			name:     "RESOURCE_EXHAUSTED",
			err:      status.Error(codes.ResourceExhausted, "answered"),
			expected: client.ErrRPC,
		},
		{
			name:     "FAILED_PRECONDITION",
			err:      status.Error(codes.FailedPrecondition, "answered"),
			expected: client.ErrRPC,
		},
		{
			name:     "ABORTED",
			err:      status.Error(codes.Aborted, "answered"),
			expected: client.ErrRPC,
		},
		{
			name:     "OUT_OF_RANGE",
			err:      status.Error(codes.OutOfRange, "answered"),
			expected: client.ErrRPC,
		},
		{
			name:     "UNIMPLEMENTED",
			err:      status.Error(codes.Unimplemented, "answered"),
			expected: client.ErrRPC,
		},
		{
			name:     "INTERNAL",
			err:      status.Error(codes.Internal, "answered"),
			expected: client.ErrRPC,
		},
		{
			name:     "UNAVAILABLE",
			err:      status.Error(codes.Unavailable, "answered"),
			expected: client.ErrUnavailable,
		},
		{
			name:     "DATA_LOSS",
			err:      status.Error(codes.DataLoss, "answered"),
			expected: client.ErrRPC,
		},
		{
			name:     "UNAUTHENTICATED",
			err:      status.Error(codes.Unauthenticated, "answered"),
			expected: client.ErrUnauthenticated,
		},
		{
			// An error that carries no gRPC status at all, which is what a
			// transport failure below gRPC looks like. It is unclassified
			// rather than mistaken for one of the codes.
			name:     "no gRPC status",
			err:      io.ErrUnexpectedEOF,
			expected: client.ErrRPC,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := client.ErrorFrom("dummy operation", testCase.err)

			if !errors.Is(got, testCase.expected) {
				t.Errorf("expected [%v], got [%v]", testCase.expected, got)
			}

			// The status the server answered with survives the classification,
			// so a caller that wants the detail can still reach it.
			if !errors.Is(got, testCase.err) {
				t.Errorf("expected [%v] to carry [%v]", got, testCase.err)
			}
		})
	}
}

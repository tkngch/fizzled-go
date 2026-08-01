package server_test

import (
	"context"
	"sync"
	"testing"

	"github.com/tkngch/fizzled-go/internal/authn"
	fizzledv1 "github.com/tkngch/fizzled-go/internal/gen/fizzled/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The agents every test in this package acts as. What each one may do is a
// question for whichever test writes a roles file; a handler test knows them
// only as the owners of jobs.
const (
	smith authn.AgentID = "smith"
	jones authn.AgentID = "jones"
)

// The SVIDs the agents above present. A handler test needs none of these: it is
// the interceptor that reads an agent id off a certificate.
const (
	serverURI = "spiffe://fizzled.internal/server"
	smithURI  = "spiffe://fizzled.internal/client/agent/smith"
	jonesURI  = "spiffe://fizzled.internal/client/agent/jones"
)

// assertErrorCode asserts that err carries the gRPC status code expected.
func assertErrorCode(tb testing.TB, err error, expected codes.Code) {
	tb.Helper()

	if err == nil {
		tb.Fatalf("expected %s, got no error", expected)
	}

	found, isStatus := status.FromError(err)
	if !isStatus {
		tb.Fatalf("expected a gRPC status, got [%v]", err)
	}

	if found.Code() != expected {
		tb.Errorf("expected %s, got %s [%s]", expected, found.Code(), found.Message())
	}
}

// recordingStream collects what a streaming handler sends, standing in for the
// stream the transport would otherwise provide. The embedded ServerStream is
// nil: the handler reads the context and sends, and nothing else.
type recordingStream struct {
	grpc.ServerStream

	//nolint:containedctx // ServerStream exposes its context through a method.
	ctx context.Context

	// sendErr, when set, is what Send fails with, standing in for the client
	// that has gone away. It is the only way to reach the handler's send-failure
	// path, which a stream that always accepts cannot show.
	sendErr error

	mutex    sync.Mutex
	received []*fizzledv1.StreamOutputResponse
}

func newRecordingStream(ctx context.Context) *recordingStream {
	return &recordingStream{
		ctx:          ctx,
		ServerStream: nil,
		sendErr:      nil,
		mutex:        sync.Mutex{},
		received:     nil,
	}
}

func (s *recordingStream) Context() context.Context {
	return s.ctx
}

func (s *recordingStream) Send(response *fizzledv1.StreamOutputResponse) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.sendErr != nil {
		return s.sendErr
	}

	s.received = append(s.received, response)

	return nil
}

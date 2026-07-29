package server_test

import (
	"context"
	"testing"

	"github.com/tkngch/fizzled-go/internal/authn"
	fizzledv1 "github.com/tkngch/fizzled-go/internal/gen/fizzled/v1"
	"github.com/tkngch/fizzled-go/internal/server"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestServiceJobCompletion(t *testing.T) {
	t.Parallel()

	service := server.NewService(nil)
	t.Cleanup(service.Shutdown)

	ctx := contextFor(t, smith)

	// Start a job
	started := ensureJobStart(ctx, t, service, 1)

	// GetStatus
	assertJobStatus(ctx, t, service, started, fizzledv1.Status_STATUS_RUNNING)

	// StreamOutput
	outputs := drainStreamOutput(ctx, t, service, started)

	for idx, output := range outputs {
		if output.GetTick().GetProgress() == nil {
			t.Fatalf("expected a progress for tick %d, got %v", idx, output)
		}
	}

	// GetStatus
	assertJobStatus(ctx, t, service, started, fizzledv1.Status_STATUS_COMPLETED)
}

func TestServiceJobStop(t *testing.T) {
	t.Parallel()

	service := server.NewService(nil)
	t.Cleanup(service.Shutdown)

	ctx := contextFor(t, smith)

	// Start a job
	started := ensureJobStart(ctx, t, service, 1)

	// GetStatus
	assertJobStatus(ctx, t, service, started, fizzledv1.Status_STATUS_RUNNING)

	for range 2 {
		// Stop. The second Stop is a no-op.
		assertJobStop(ctx, t, service, started)
	}

	// StreamOutput
	outputs := drainStreamOutput(ctx, t, service, started)

	if outputs[0].GetTick().GetProgress() == nil {
		t.Fatalf("expected a progress tick, got %v", outputs[0])
	}

	if outputs[len(outputs)-1].GetTick().GetStopped() == nil {
		t.Errorf(
			"expected the stream to close on a stopped tick, got %v",
			outputs[len(outputs)-1],
		)
	}

	// GetStatus
	assertJobStatus(ctx, t, service, started, fizzledv1.Status_STATUS_STOPPED)
}

func TestServiceStartInvalidArgument(t *testing.T) {
	t.Parallel()

	service := server.NewService(nil)
	t.Cleanup(service.Shutdown)

	_, err := service.Start(contextFor(t, smith), &fizzledv1.StartRequest{Count: -1})
	assertErrorCode(t, err, codes.InvalidArgument)
}

func TestServiceNotOwnerAgent(t *testing.T) {
	t.Parallel()

	service := server.NewService(nil)
	t.Cleanup(service.Shutdown)

	ctx := contextFor(t, jones)

	// Start a job as another agent
	started, err := service.Start(contextFor(t, smith), &fizzledv1.StartRequest{Count: 10})
	if err != nil {
		t.Fatalf("unexpected error from Start(): %v", err)
	}

	// GetStatus
	_, err = service.GetStatus(ctx, &fizzledv1.GetStatusRequest{JobId: started.GetJobId()})
	assertErrorCode(t, err, codes.NotFound)

	// Stop
	_, err = service.Stop(ctx, &fizzledv1.StopRequest{JobId: started.GetJobId()})
	assertErrorCode(t, err, codes.NotFound)

	// StreamOutput
	stream := newRecordingStream(ctx)
	err = service.StreamOutput(&fizzledv1.StreamOutputRequest{JobId: started.GetJobId()}, stream)
	assertErrorCode(t, err, codes.NotFound)
}

func TestServiceNoAgentIDInContext(t *testing.T) {
	t.Parallel()

	service := server.NewService(nil)
	t.Cleanup(service.Shutdown)

	ctx := t.Context()

	// Start a job
	started, err := service.Start(ctx, &fizzledv1.StartRequest{Count: 10})
	assertErrorCode(t, err, codes.Internal)

	// GetStatus
	_, err = service.GetStatus(ctx, &fizzledv1.GetStatusRequest{JobId: started.GetJobId()})
	assertErrorCode(t, err, codes.Internal)

	// Stop
	_, err = service.Stop(ctx, &fizzledv1.StopRequest{JobId: started.GetJobId()})
	assertErrorCode(t, err, codes.Internal)

	// StreamOutput
	stream := newRecordingStream(ctx)
	err = service.StreamOutput(&fizzledv1.StreamOutputRequest{JobId: started.GetJobId()}, stream)
	assertErrorCode(t, err, codes.Internal)
}

func TestStreamOutput(t *testing.T) {
	t.Parallel()

	t.Run("gives up when the client has gone", func(t *testing.T) {
		t.Parallel()

		service := server.NewService(nil)
		t.Cleanup(service.Shutdown)

		ctx := contextFor(t, smith)

		started, err := service.Start(ctx, &fizzledv1.StartRequest{Count: 100})
		if err != nil {
			t.Fatalf("unexpected error from Start(): %v", err)
		}

		jobID := started.GetJobId()

		stream := newRecordingStream(ctx)
		stream.sendErr = status.Error(codes.Unavailable, "transport is closing")

		err = service.StreamOutput(&fizzledv1.StreamOutputRequest{JobId: jobID}, stream)
		if err == nil {
			t.Fatalf("expected the failed send to be reported, got no error")
		}

		assertErrorCode(t, err, codes.Unavailable)
	})
}

// TestServiceShutdown covers what Shutdown promises whatever is shutting the
// process down: the jobs the Service holds are stopped, and no further job is
// taken on.
func TestServiceShutdown(t *testing.T) {
	t.Parallel()

	t.Run("stops the jobs it holds", func(t *testing.T) {
		t.Parallel()

		service := server.NewService(nil)
		t.Cleanup(service.Shutdown)

		ctx := contextFor(t, smith)
		started := ensureJobStart(ctx, t, service, 100)

		service.Shutdown()

		// Shutdown stops the jobs without discarding them, so the one above is
		// still there to be asked.
		assertJobStatus(ctx, t, service, started, fizzledv1.Status_STATUS_STOPPED)
	})

	t.Run("refuses a job once it has shut down", func(t *testing.T) {
		t.Parallel()

		service := server.NewService(nil)
		service.Shutdown()

		_, err := service.Start(contextFor(t, smith), &fizzledv1.StartRequest{Count: 1})
		assertErrorCode(t, err, codes.Unavailable)
	})
}

func ensureJobStart(
	ctx context.Context,
	t *testing.T,
	service *server.Service,
	count int32,
) *fizzledv1.StartResponse {
	t.Helper()

	started, err := service.Start(ctx, &fizzledv1.StartRequest{Count: count})
	if err != nil {
		t.Fatalf("unexpected error from Start(): %v", err)
	}

	return started
}

func assertJobStop(
	ctx context.Context,
	t *testing.T,
	service *server.Service,
	started *fizzledv1.StartResponse,
) {
	t.Helper()

	request := &fizzledv1.StopRequest{JobId: started.GetJobId()}

	stopped, err := service.Stop(ctx, request)
	if err != nil {
		t.Fatalf("unexpected error from Stop(): %v", err)
	}

	if stopped.GetStatus() != fizzledv1.Status_STATUS_STOPPED {
		t.Errorf("expected STATUS_STOPPED, got %s", stopped.GetStatus())
	}
}

func assertJobStatus(
	ctx context.Context,
	t *testing.T,
	service *server.Service,
	started *fizzledv1.StartResponse,
	expected fizzledv1.Status,
) {
	t.Helper()

	request := &fizzledv1.GetStatusRequest{JobId: started.GetJobId()}

	status, err := service.GetStatus(ctx, request)
	if err != nil {
		t.Fatalf("unexpected error from GetStatus(): %v", err)
	}

	if status.GetStatus() != expected {
		t.Errorf("expected %s, got %s", expected, status.GetStatus())
	}
}

func drainStreamOutput(
	ctx context.Context,
	t *testing.T,
	service *server.Service,
	started *fizzledv1.StartResponse,
) []*fizzledv1.StreamOutputResponse {
	t.Helper()

	stream := newRecordingStream(ctx)
	request := &fizzledv1.StreamOutputRequest{JobId: started.GetJobId()}

	err := service.StreamOutput(request, stream) //nolint:contextcheck // context is in stream
	if err != nil {
		t.Fatalf("unexpected error from StreamOutput(): %v", err)
	}

	if len(stream.received) < 2 {
		t.Fatalf("expected a progress tick and a terminal tick, got %d", len(stream.received))
	}

	if stream.received[0].GetTick().GetProgress() == nil {
		t.Fatalf("expected a progress tick, got %v", stream.received[0])
	}

	return stream.received
}

// contextFor is the context a handler sees for an RPC that agentID made. It is
// what the interceptor resolves an agent into, without an interceptor to
// resolve one: a handler reads only the id, and neither the peer it came from
// nor the method it was carried on.
func contextFor(tb testing.TB, agentID authn.AgentID) context.Context {
	tb.Helper()

	return server.ContextWithAgentID(tb.Context(), agentID)
}

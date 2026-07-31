package server

import (
	"context"
	"errors"
	"log/slog"

	"github.com/tkngch/fizzled-go/internal/authn"
	fizzledv1 "github.com/tkngch/fizzled-go/internal/gen/fizzled/v1"
	"github.com/tkngch/fizzled-go/internal/logging"
	"github.com/tkngch/fizzled-go/internal/registry"
	"github.com/tkngch/fizzled-go/internal/worker"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

// Service is an implementation of FizzledServiceServer.
//
// It takes authentication and authorization as already done: every handler
// reads the agent id that Interceptor resolved out of its context. A Service
// registered without those interceptors responds with Internal error.
type Service struct {
	fizzledv1.UnimplementedFizzledServiceServer

	registry *registry.Registry
	logger   *slog.Logger
}

// NewService instantiates a Service holding a registry of its own. A nil logger
// discards the service's log.
//
// The registry is not a parameter because nothing outside this package has any
// use for one: the Service is the only thing that starts a job, and Shutdown is
// the only way to stop the jobs it holds.
func NewService(logger *slog.Logger) *Service {
	logger = logging.OrDiscard(logger)

	return &Service{
		UnimplementedFizzledServiceServer: fizzledv1.UnimplementedFizzledServiceServer{},

		registry: registry.New(logger),
		logger:   logger,
	}
}

// Shutdown stops every job the Service holds and blocks until they have
// all finished. Once it is called, Start reports Unavailable.
//
// Shutdown is idempotent and safe to call concurrently.
func (s *Service) Shutdown() {
	s.registry.Shutdown()
}

// Start starts a job and returns its job id. The job is registered before the
// id is returned, so it is queryable, streamable and stoppable the instant the
// caller receives the id.
//
// It reports InvalidArgument when count is outside the range a job accepts, and
// Unavailable once the registry has stopped accepting jobs.
func (s *Service) Start(
	ctx context.Context,
	request *fizzledv1.StartRequest,
) (*fizzledv1.StartResponse, error) {
	agentID, err := s.agentID(ctx)
	if err != nil {
		return nil, err
	}

	// The RPC's cancellation is dropped and its values kept: the job outlives
	// the call that started it.
	jobID, err := s.registry.Create(
		context.WithoutCancel(ctx), agentID, int(request.GetCount()),
	)

	switch {
	case errors.Is(err, worker.ErrInvalidCount):
		return nil, status.Errorf(
			codes.InvalidArgument,
			"count must be between 1 and %d",
			worker.MaxCount,
		)

	case errors.Is(err, registry.ErrNotAcceptingJobs):
		return nil, status.Error(codes.Unavailable, "unavailable")

	case err != nil:
		s.logger.LogAttrs(
			ctx,
			slog.LevelError,
			"internal error in creating a job",
			slog.String("agent_id", string(agentID)),
			slog.String("error", err.Error()),
		)

		return nil, status.Error(codes.Internal, internalErrorMessage)
	}

	return &fizzledv1.StartResponse{JobId: string(jobID)}, nil
}

// Stop requests cancellation of a running job and reports the terminal status
// the job resolved to. It is a no-op on a job that has already reached a
// terminal status.
//
// It reports NotFound when the agent owns no job under the requested id.
func (s *Service) Stop(
	ctx context.Context,
	request *fizzledv1.StopRequest,
) (*fizzledv1.StopResponse, error) {
	job, _, err := s.findJob(ctx, request.GetJobId())
	if err != nil {
		return nil, err
	}

	return &fizzledv1.StopResponse{Status: s.protoStatus(ctx, job.Stop())}, nil
}

// GetStatus reports the current status of a job.
//
// It reports NotFound when the agent owns no job under the requested id.
func (s *Service) GetStatus(
	ctx context.Context,
	request *fizzledv1.GetStatusRequest,
) (*fizzledv1.GetStatusResponse, error) {
	job, _, err := s.findJob(ctx, request.GetJobId())
	if err != nil {
		return nil, err
	}

	return &fizzledv1.GetStatusResponse{Status: s.protoStatus(ctx, job.Status())}, nil
}

// StreamOutput replays every tick from the start of the job and then follows
// the live ticks. The stream closes once the terminal tick has been delivered,
// so no output is missed.
//
// It reports NotFound when the agent owns no job under the requested id.
func (s *Service) StreamOutput(
	request *fizzledv1.StreamOutputRequest,
	server grpc.ServerStreamingServer[fizzledv1.StreamOutputResponse],
) error {
	ctx := server.Context()

	job, agentID, err := s.findJob(ctx, request.GetJobId())
	if err != nil {
		return err
	}

	s.logger.LogAttrs(
		ctx,
		slog.LevelInfo,
		"stream opened",
		slog.String("agent_id", string(agentID)),
		slog.String("job_id", string(job.ID())),
	)
	defer func() {
		s.logger.LogAttrs(
			context.WithoutCancel(ctx),
			slog.LevelInfo,
			"stream closed",
			slog.String("agent_id", string(agentID)),
			slog.String("job_id", string(job.ID())),
			slog.String("job_status", string(job.Status())),
		)
	}()

	for tick := range job.Ticks(ctx) {
		err = server.Send(&fizzledv1.StreamOutputResponse{Tick: s.protoTick(ctx, tick)})
		if err != nil {
			// Send fails when the client has gone, which is ordinary rather
			// than exceptional: record it and let the status carry the reason.
			s.logger.LogAttrs(
				ctx,
				slog.LevelInfo,
				"error in streaming output",
				slog.String("job_id", string(job.ID())),
				slog.String("job_status", string(job.Status())),
				slog.String("error", err.Error()),
			)

			//nolint:wrapcheck // Send returns a gRPC status; wrapping rewrites the message.
			return err
		}
	}

	return nil
}

// agentID reads the agent id Interceptor resolved for this RPC.
//
// Its absence means the server was built without the interceptors, and results
// in an internal error.
func (s *Service) agentID(ctx context.Context) (authn.AgentID, error) {
	agentID, isFound := agentIDFrom(ctx)
	if !isFound {
		s.logger.LogAttrs(ctx, slog.LevelError, "no authenticated agent id in the context")

		return "", status.Error(codes.Internal, internalErrorMessage)
	}

	return agentID, nil
}

// findJob looks up a job the agent owns.
//
// A job owned by another agent is reported as not found, indistinguishably from
// one that does not exist, so the audit line below is the only record that the
// attempt happened at all. It returns the owning agent alongside the job, for
// the caller that records the two together.
func (s *Service) findJob(
	ctx context.Context,
	jobID string,
) (*worker.Job, authn.AgentID, error) {
	agentID, err := s.agentID(ctx)
	if err != nil {
		return nil, "", err
	}

	job, isFound := s.registry.Find(agentID, worker.JobID(jobID))
	if !isFound {
		s.logger.LogAttrs(
			ctx,
			slog.LevelInfo,
			"job not found",
			slog.String("agent_id", string(agentID)),
			slog.String("job_id", jobID),
		)

		return nil, "", status.Error(codes.NotFound, "job not found")
	}

	return job, agentID, nil
}

// protoStatus converts a job status to the one the wire carries.
func (s *Service) protoStatus(ctx context.Context, jobStatus worker.Status) fizzledv1.Status {
	switch jobStatus {
	case worker.StatusRunning:
		return fizzledv1.Status_STATUS_RUNNING

	case worker.StatusCompleted:
		return fizzledv1.Status_STATUS_COMPLETED

	case worker.StatusStopped:
		return fizzledv1.Status_STATUS_STOPPED

	case worker.StatusFailed:
		return fizzledv1.Status_STATUS_FAILED

	default:
		s.logger.LogAttrs(
			ctx,
			slog.LevelWarn,
			"unexpected job status",
			slog.String("job_status", string(jobStatus)),
		)

		return fizzledv1.Status_STATUS_UNSPECIFIED
	}
}

// protoTick converts a tick to the one the wire carries.
//
// Neither terminal tick carries its cause across: a stopped tick drops the
// cancelation cause and a failure tick reports a fixed message. Both are
// server-side detail, recorded by the worker's log rather than reported to the
// caller.
func (s *Service) protoTick(ctx context.Context, tick worker.Tick) *fizzledv1.Tick {
	pbTick := &fizzledv1.Tick{Kind: nil}

	switch typedTick := tick.(type) {
	case worker.Progress:
		pbTick.Kind = &fizzledv1.Tick_Progress{
			Progress: &fizzledv1.Progress{
				Elapsed: durationpb.New(typedTick.Elapsed),
				// Remaining counts down from a count that worker.NewJob rejects
				// above worker.MaxCount, so it always fits in an int32.
				//nolint:gosec // G115: bounded by worker.MaxCount.
				Remaining: int32(typedTick.Remaining),
			},
		}

	case worker.Stopped:
		pbTick.Kind = &fizzledv1.Tick_Stopped{Stopped: &fizzledv1.Stopped{}}

	case worker.PanicError:
		pbTick.Kind = protoFailure()

	default:
		// A tick type this package does not know is reported as a failure: the
		// stream has to end on something, and a tick that cannot be converted
		// is not progress.
		s.logger.LogAttrs(ctx, slog.LevelWarn, "unexpected tick", slog.Any("tick", tick))

		pbTick.Kind = protoFailure()
	}

	return pbTick
}

// protoFailure is the failure variant of a tick. It reports a fixed description
// rather than a cause.
func protoFailure() *fizzledv1.Tick_Failure {
	return &fizzledv1.Tick_Failure{
		Failure: &fizzledv1.Failure{Message: unexpectedErrorMessage},
	}
}

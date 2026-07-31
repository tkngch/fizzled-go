package server

import (
	"context"
	"log/slog"
	"runtime/debug"

	"github.com/tkngch/fizzled-go/internal/authn"
	"github.com/tkngch/fizzled-go/internal/authz"
	fizzledv1 "github.com/tkngch/fizzled-go/internal/gen/fizzled/v1"
	"github.com/tkngch/fizzled-go/internal/logging"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Interceptor authenticates the peer and authorizes the action behind an RPC,
// before the handler runs. The handler reads the agent id that the interceptor
// resolves.
//
// An Interceptor is immutable after construction and safe for concurrent use.
type Interceptor struct {
	authenticator *authn.Authenticator
	authorizer    *authz.Authorizer
	logger        *slog.Logger
}

// agentIDKey is the key the authenticated agent id is stored under. It is an
// unexported type, so no package outside this one can read the id out of a
// context or plant one in it.
type agentIDKey struct{}

// NewInterceptor returns an Interceptor that resolves an agent through
// authenticator and asks authorizer what that agent may do.
//
// logger records the authorization decision behind every RPC, allowed or
// denied. A nil logger discards them. The authentication outcome is not
// recorded here: authenticator already audits every connection it verifies.
func NewInterceptor(
	authenticator *authn.Authenticator,
	authorizer *authz.Authorizer,
	logger *slog.Logger,
) *Interceptor {
	logger = logging.OrDiscard(logger)

	return &Interceptor{
		authenticator: authenticator,
		authorizer:    authorizer,
		logger:        logger,
	}
}

// Unary returns the interceptor to install with grpc.UnaryInterceptor. It hands
// the handler a context carrying the authenticated agent id.
func (i *Interceptor) Unary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		request any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		var response any

		err := i.guard(ctx, info.FullMethod, func() error {
			authorized, authErr := i.authorize(ctx, info.FullMethod, targetJobID(request))
			if authErr != nil {
				return authErr
			}

			var handlerErr error

			response, handlerErr = handler(authorized, request)

			return handlerErr
		})
		if err != nil {
			return nil, err
		}

		return response, nil
	}
}

// Stream returns the interceptor to install with grpc.StreamInterceptor. It
// hands the handler a stream whose context carries the authenticated agent id,
// so a streaming handler reads it the same way a unary one does.
//
// The agent is resolved once, when the stream opens, rather than per message.
func (i *Interceptor) Stream() grpc.StreamServerInterceptor {
	return func(
		server any,
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		return i.guard(stream.Context(), info.FullMethod, func() error {
			authorized, err := i.authorize(stream.Context(), info.FullMethod, "")
			if err != nil {
				return err
			}

			return handler(server, authenticatedStream{ServerStream: stream, ctx: authorized})
		})
	}
}

// guard runs an RPC with a recover installed, so a panic becomes an Internal
// status rather than the end of the process.
//
// It covers the authentication and the authorization as well as the handler.
// The cause of panic is a server-side detail, so it is recorded here and
// withheld from the caller.
func (i *Interceptor) guard(ctx context.Context, fullMethod string, run func() error) (err error) {
	defer func() {
		recovered := recover()
		if recovered == nil {
			return
		}

		// The stack is taken here rather than after this function returns: the
		// panicking frames are still on the stack inside the deferred call, and
		// are what makes the line worth writing.
		i.logger.LogAttrs(
			ctx,
			slog.LevelError,
			"panic in handler",
			slog.String("method", fullMethod),
			slog.Any("panic", recovered),
			slog.String("stack", string(debug.Stack())),
		)

		err = status.Error(codes.Internal, internalErrorMessage)
	}()

	return run()
}

// authorize resolves the agent behind the RPC and checks it may take the action
// the method stands for. It returns ctx extended with the agent id.
//
// Authentication is checked before authorization, and the method is mapped to
// an action: a method this package does not know is refused rather than served,
// whatever the peer presented.
func (i *Interceptor) authorize(
	ctx context.Context,
	fullMethod, jobID string,
) (context.Context, error) {
	action, isKnown := actionFor(fullMethod)
	if !isKnown {
		// Reached only when an RPC is added to the proto and actionFor is not
		// updated with it. That is a server bug rather than anything the caller
		// did, so the request should fail and the log line should be loud
		// enough to find.
		i.logger.LogAttrs(
			ctx,
			slog.LevelError,
			"no action is mapped to the method",
			slog.String("method", fullMethod),
		)

		return ctx, status.Error(codes.Internal, internalErrorMessage)
	}

	agentID, err := i.authenticate(ctx)
	if err != nil {
		return ctx, err
	}

	err = i.authorizer.Authorize(agentID, action)
	if err != nil {
		// The authorizer's error names the agent and the action for this line.
		// It is not echoed back to the agent, which learns only the code.
		i.auditDecision(ctx, agentID, action, jobID, "deny", slog.String("reason", err.Error()))

		return ctx, status.Error(codes.PermissionDenied, "permission denied")
	}

	i.auditDecision(ctx, agentID, action, jobID, "allow")

	return context.WithValue(ctx, agentIDKey{}, agentID), nil
}

// authenticate resolves the agent id from the peer's verified certificate. The
// chain is re-verified here rather than trusted from the handshake.
func (i *Interceptor) authenticate(ctx context.Context) (authn.AgentID, error) {
	peerInfo, isFound := peer.FromContext(ctx)
	if !isFound {
		i.logger.LogAttrs(ctx, slog.LevelInfo, "no peer is found")

		return "", status.Error(codes.Unauthenticated, "no peer")
	}

	tlsInfo, isTLS := peerInfo.AuthInfo.(credentials.TLSInfo)
	if !isTLS {
		i.logger.LogAttrs(
			ctx,
			slog.LevelInfo,
			"connection is not mTLS",
			slog.Any("auth_info", peerInfo.AuthInfo),
		)

		return "", status.Error(codes.Unauthenticated, "connection is not mTLS")
	}

	agentID, err := i.authenticator.Authenticate(tlsInfo.State)
	if err != nil {
		// The reason is a server-side detail and is recorded by the
		// authenticator's own audit line.
		return "", status.Error(codes.Unauthenticated, "unauthenticated")
	}

	return agentID, nil
}

// auditDecision records one authorization decision. job_id is carried only when
// it is available.
func (i *Interceptor) auditDecision(
	ctx context.Context,
	agentID authn.AgentID,
	action authz.Action,
	jobID string,
	decision string,
	extra ...slog.Attr,
) {
	attributes := []slog.Attr{
		slog.String("agent_id", string(agentID)),
		slog.String("action", string(action)),
		slog.String("decision", decision),
	}

	if jobID != "" {
		attributes = append(attributes, slog.String("job_id", jobID))
	}

	attributes = append(attributes, extra...)

	i.logger.LogAttrs(ctx, slog.LevelInfo, "authorization decision", attributes...)
}

// agentIDFrom returns the agent id the interceptor resolved for this RPC, and
// false when there is none. There is none only when the server was built
// without the interceptors, never because the peer was unauthenticated: an
// unauthenticated RPC never reaches a handler.
func agentIDFrom(ctx context.Context) (authn.AgentID, bool) {
	agentID, isFound := ctx.Value(agentIDKey{}).(authn.AgentID)

	return agentID, isFound
}

// jobIDCarrier is the RPC request that carries a job ID. The Stop, GetStatus
// and StreamOutput requests satisfy it; a Start request does not.
type jobIDCarrier interface {
	GetJobId() string
}

// targetJobID is the job ID in an RPC request, or empty when it names none.
func targetJobID(request any) string {
	carrier, isCarrier := request.(jobIDCarrier)
	if !isCarrier {
		return ""
	}

	return carrier.GetJobId()
}

// actionFor maps a full RPC method name to the action the authorizer decides
// on. It reports false for a method it does not know.
//
// The mapping is spelled out rather than derived from the method name, so
// adding an RPC is a compile-and-test problem.
func actionFor(fullMethod string) (authz.Action, bool) {
	switch fullMethod {
	case fizzledv1.FizzledService_Start_FullMethodName:
		return authz.ActionStart, true

	case fizzledv1.FizzledService_Stop_FullMethodName:
		return authz.ActionStop, true

	case fizzledv1.FizzledService_GetStatus_FullMethodName:
		return authz.ActionGetStatus, true

	case fizzledv1.FizzledService_StreamOutput_FullMethodName:
		return authz.ActionStreamOutput, true

	default:
		return "", false
	}
}

// authenticatedStream carries the context the interceptor derived.
// grpc.ServerStream hands its context out through a method rather than taking
// one, so overriding that method is the only way to extend it.
type authenticatedStream struct {
	grpc.ServerStream

	//nolint:containedctx // ServerStream exposes its context through a method.
	ctx context.Context
}

// Context returns the context carrying the authenticated agent id.
func (s authenticatedStream) Context() context.Context {
	return s.ctx
}

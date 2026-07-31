package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/tkngch/fizzled-go/internal/authn"
	"github.com/tkngch/fizzled-go/internal/authz"
	fizzledv1 "github.com/tkngch/fizzled-go/internal/gen/fizzled/v1"
	"github.com/tkngch/fizzled-go/internal/logging"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

const (
	// keepaliveTime is how long the server waits on a quiet connection before
	// pinging the client, so a stream that outlives its client is noticed
	// rather than held open.
	keepaliveTime = time.Minute

	// keepaliveTimeout is how long the server waits for a reply to that ping
	// before closing the connection.
	keepaliveTimeout = 10 * time.Second

	// keepaliveMinTime is the shortest interval the server tolerates between
	// client-initiated pings. It is an order of magnitude longer than
	// keepaliveTime, which the server applies to itself, so the policy the
	// server enforces on clients never collides with the one it follows.
	keepaliveMinTime = 10 * time.Minute

	// defaultShutdownGrace bounds the transport's drain on shutdown when
	// Config.ShutdownGrace does not.
	defaultShutdownGrace = 5 * time.Second
)

// Config is what an operator supplies to stand a server up.
type Config struct {
	// Address is the address to listen on, such as "localhost:8443".
	Address string

	// CAPath is the trust bundle that every peer certificate is verified
	// against.
	CAPath string

	// CertPath and KeyPath are the server's own SVID, which it presents to
	// every client.
	CertPath string
	KeyPath  string

	// RolesPath is the agent-to-role mapping the authorizer decides from.
	RolesPath string

	// ShutdownGrace bounds how long a shutdown waits for open streams to drain
	// before cutting them off. Zero takes defaultShutdownGrace.
	ShutdownGrace time.Duration
}

// Server is the whole stack behind the gRPC contract: the transport, the
// interceptors that authenticate and authorize every RPC, and the Service
// holding the countdowns.
type Server struct {
	grpc          *grpc.Server
	service       *Service
	listener      net.Listener
	shutdownGrace time.Duration
	logger        *slog.Logger
}

// New builds the stack from config and starts listening on
// config.Address. Nothing is served until Serve is called.
//
// A nil logger discards the server's log.
func New(ctx context.Context, config Config, logger *slog.Logger) (*Server, error) {
	if config.Address == "" {
		return nil, fmt.Errorf("new server: %w", ErrEmptyAddress)
	}

	logger = logging.OrDiscard(logger)

	shutdownGrace := config.ShutdownGrace
	if shutdownGrace <= 0 {
		shutdownGrace = defaultShutdownGrace
	}

	// The authenticator records the bundle it loaded against a background
	// context of its own, deliberately: that line is about this process rather
	// than about whatever call stood it up.
	//nolint:contextcheck // authn.NewAuthenticator audits under its own context.
	authenticator, err := authn.NewAuthenticator(config.CAPath, logger)
	if err != nil {
		return nil, fmt.Errorf("new server: %w", err)
	}

	tlsConfig, err := authenticator.ServerConfig(config.CertPath, config.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("new server: %w", err)
	}

	authorizer, err := authz.Load(config.RolesPath)
	if err != nil {
		return nil, fmt.Errorf("new server: %w", err)
	}

	var listenConfig net.ListenConfig

	listener, err := listenConfig.Listen(ctx, "tcp", config.Address)
	if err != nil {
		return nil, fmt.Errorf("new server [%s]: %w", config.Address, err)
	}

	// The transport layer takes its context from the RPC, not from this call.
	//nolint:contextcheck
	grpcServer := newTransport(tlsConfig, authenticator, authorizer, logger)
	fizzled := NewService(logger)
	fizzledv1.RegisterFizzledServiceServer(grpcServer, fizzled)

	return &Server{
		grpc:          grpcServer,
		service:       fizzled,
		listener:      listener,
		shutdownGrace: shutdownGrace,
		logger:        logger,
	}, nil
}

// newTransport is the gRPC transport the stack is served over.
func newTransport(
	tlsConfig *tls.Config,
	authenticator *authn.Authenticator,
	authorizer *authz.Authorizer,
	logger *slog.Logger,
) *grpc.Server {
	interceptor := NewInterceptor(authenticator, authorizer, logger)

	return grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.UnaryInterceptor(interceptor.Unary()),
		grpc.StreamInterceptor(interceptor.Stream()),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			// The three connection-age knobs are left at their infinite
			// defaults: a job may be streamed for as long as it runs, and
			// an age limit would cut such a stream for no reason but its age.
			MaxConnectionIdle:     0,
			MaxConnectionAge:      0,
			MaxConnectionAgeGrace: 0,
			Time:                  keepaliveTime,
			Timeout:               keepaliveTimeout,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime: keepaliveMinTime,
			// A client with no active stream has nothing to keep alive, so a
			// ping from one is refused rather than answered.
			PermitWithoutStream: false,
		}),
	)
}

// Addr is the address the server listens on.
func (s *Server) Addr() net.Addr {
	return s.listener.Addr()
}

// Close releases the listener that New opened.
func (s *Server) Close() error {
	err := s.listener.Close()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("close: %w", err)
	}

	return nil
}

// Serve serves until ctx is done or the listener fails.
//
// A shutdown that drained every stream returns nil. One that ran out of grace
// and cut them off returns ErrShutdownGraceElapsed, so that a caller reporting
// the process's exit can tell the two apart.
func (s *Server) Serve(ctx context.Context) error {
	served := make(chan error, 1)

	go func() { served <- s.grpc.Serve(s.listener) }()

	var (
		serveErr  error
		isDrained bool
	)

	// Either the transport ends the serve, in which case its error is already
	// in hand, or ctx does, in which case the error arrives once the shutdown
	// below has stopped the transport.
	select {
	case serveErr = <-served:
		isDrained = s.shutdown(ctx)

	case <-ctx.Done():
		isDrained = s.shutdown(ctx)
		serveErr = <-served
	}

	switch {
	// ErrServerStopped means the shutdown above won the race to start the
	// transport. That is this method stopping itself, not a failure to serve.
	case serveErr != nil && !errors.Is(serveErr, grpc.ErrServerStopped):
		return fmt.Errorf("serve: %w", serveErr)

	case !isDrained:
		return fmt.Errorf("serve: %w", ErrShutdownGraceElapsed)

	default:
		return nil
	}
}

// shutdown stops the jobs and then the transport, in that order. The grace
// covers the whole sequence rather than the drain alone. It reports whether the
// sequence finished within the grace.
//
// The order is the whole of its correctness. GracefulStop waits for every
// handler to return, and a StreamOutput handler does not return until its job
// emits a terminal tick.
func (s *Server) shutdown(ctx context.Context) bool {
	stopped := make(chan struct{})

	// Both steps in the one goroutine, so the order above still holds while the
	// grace runs against the pair of them.
	go func() {
		defer close(stopped)

		s.service.Shutdown()
		s.grpc.GracefulStop()
	}()

	select {
	case <-stopped:
		return true

	case <-time.After(s.shutdownGrace):
		// Stop closes the transports out from under GracefulStop, which then
		// returns. A subscriber still open at this point loses its terminal
		// tick and observes a transport-level cancel instead.
		s.logger.LogAttrs(
			context.WithoutCancel(ctx),
			slog.LevelWarn,
			"shutdown grace elapsed with streams still open",
			slog.Duration("grace", s.shutdownGrace),
		)

		s.grpc.Stop()
		<-stopped

		return false
	}
}

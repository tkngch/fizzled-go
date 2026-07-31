package server_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"testing"

	"github.com/tkngch/fizzled-go/internal/authn"
	fizzledv1 "github.com/tkngch/fizzled-go/internal/gen/fizzled/v1"
	"github.com/tkngch/fizzled-go/internal/server"
	"github.com/tkngch/fizzled-go/internal/testpki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
)

// TestNewServerRejectsMisconfiguration pins down that every path in a Config is
// resolved at start-up, so a server that could never serve fails.
func TestNewServerRejectsMisconfiguration(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		apply func(tb testing.TB, authority testpki.Authority, config *server.Config)
	}{
		{
			name: "unreadable trust bundle",
			apply: func(tb testing.TB, _ testpki.Authority, config *server.Config) {
				tb.Helper()

				config.CAPath = filepath.Join(tb.TempDir(), "absent-ca.crt")
			},
		},
		{
			name: "unreadable roles file",
			apply: func(tb testing.TB, _ testpki.Authority, config *server.Config) {
				tb.Helper()

				config.RolesPath = filepath.Join(tb.TempDir(), "absent-roles.json")
			},
		},
		{
			name: "an SVID no client would accept",
			apply: func(tb testing.TB, authority testpki.Authority, config *server.Config) {
				tb.Helper()

				// A well-formed leaf from the right authority, but carrying an
				// agent identity where the server identity belongs.
				config.CertPath, config.KeyPath = testpki.NewLeafFiles(
					tb,
					authority,
					testpki.NewLeafOptions(smithURI),
				)
			},
		},
		{
			name: "an address that cannot be listened on",
			apply: func(_ testing.TB, _ testpki.Authority, config *server.Config) {
				config.Address = "256.256.256.256:0"
			},
		},
		{
			name: "empty address",
			apply: func(_ testing.TB, _ testpki.Authority, config *server.Config) {
				config.Address = ""
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			authority := testpki.NewAuthority(t, testpki.NewAuthorityOptions())

			config := newConfig(t, authority, smith)
			testCase.apply(t, authority, &config)

			_, err := server.New(t.Context(), config, nil)
			if err == nil {
				t.Errorf("expected %s to be rejected, got no error", testCase.name)
			}
		})
	}
}

func TestNewServerAcceptsAValidConfiguration(t *testing.T) {
	t.Parallel()

	authority := testpki.NewAuthority(t, testpki.NewAuthorityOptions())

	srv, err := server.New(t.Context(), newConfig(t, authority, smith), nil)
	if err != nil {
		t.Fatalf("unexpected error from New(): %v", err)
	}

	if srv.Addr() == nil {
		t.Errorf("expected a listening address, got none")
	}

	// This server is never served, so Close is the only thing that hands the
	// port back. Call Close twice, to ensure that Close does not error out on
	// an already-closed server.
	for range 2 {
		err = srv.Close()
		if err != nil {
			t.Errorf("unexpected error from Close(): %v", err)
		}
	}
}

// TestServerInstallsBothInterceptors checks the interceptors reach a server New
// built, on the streaming path as well as the unary one. A handler test cannot
// show this, because it calls the interceptor itself.
func TestServerInstallsBothInterceptors(t *testing.T) {
	t.Parallel()

	// jones presents a certificate the trust bundle accepts, but the roles file
	// names only smith.
	authority := testpki.NewAuthority(t, testpki.NewAuthorityOptions())
	srv, _ := newServer(t, newConfig(t, authority, smith))
	client := newClient(t, authority, srv.Addr().String(), jonesURI)

	_, err := client.Start(t.Context(), &fizzledv1.StartRequest{Count: 1})
	assertErrorCode(t, err, codes.PermissionDenied)

	// The stream opens optimistically; the refusal arrives on the first read.
	stream, err := client.StreamOutput(
		t.Context(),
		&fizzledv1.StreamOutputRequest{JobId: "smith/0"},
	)
	if err != nil {
		t.Fatalf("unexpected error opening the stream: %v", err)
	}

	_, err = stream.Recv()
	assertErrorCode(t, err, codes.PermissionDenied)
}

// TestServerReachesEveryHandler drives each RPC in the contract over a real
// transport. This test covers reachability and nothing further.
func TestServerReachesEveryHandler(t *testing.T) {
	t.Parallel()

	authority := testpki.NewAuthority(t, testpki.NewAuthorityOptions())
	srv, _ := newServer(t, newConfig(t, authority, smith))
	client := newClient(t, authority, srv.Addr().String(), smithURI)

	started, err := client.Start(t.Context(), &fizzledv1.StartRequest{Count: 100})
	if err != nil {
		t.Fatalf("unexpected error from Start(): %v", err)
	}

	queried, err := client.GetStatus(
		t.Context(),
		&fizzledv1.GetStatusRequest{JobId: started.GetJobId()},
	)
	if err != nil {
		t.Fatalf("unexpected error from GetStatus(): %v", err)
	}

	if queried.GetStatus() != fizzledv1.Status_STATUS_RUNNING {
		t.Errorf("expected STATUS_RUNNING, got %s", queried.GetStatus())
	}

	stream, err := client.StreamOutput(
		t.Context(),
		&fizzledv1.StreamOutputRequest{JobId: started.GetJobId()},
	)
	if err != nil {
		t.Fatalf("unexpected error from StreamOutput(): %v", err)
	}

	first, err := stream.Recv()
	if err != nil {
		t.Fatalf("unexpected error from Recv(): %v", err)
	}

	if first.GetTick().GetProgress() == nil {
		t.Errorf("expected a progress tick, got %v", first)
	}

	stopped, err := client.Stop(t.Context(), &fizzledv1.StopRequest{JobId: started.GetJobId()})
	if err != nil {
		t.Fatalf("unexpected error from Stop(): %v", err)
	}

	if stopped.GetStatus() != fizzledv1.Status_STATUS_STOPPED {
		t.Errorf("expected STATUS_STOPPED, got %s", stopped.GetStatus())
	}
}

func TestServerShutdown(t *testing.T) {
	t.Parallel()

	// The order shutdown runs in is the whole of its correctness: the jobs stop
	// first, so a job emits its terminal tick and the handler streaming it
	// returns, and only then does the transport drain. Stopping the transport
	// first would cut this stream off mid-countdown instead.
	t.Run("lets an open stream end on a terminal tick", func(t *testing.T) {
		t.Parallel()

		authority := testpki.NewAuthority(t, testpki.NewAuthorityOptions())
		srv, stop := newServer(t, newConfig(t, authority, smith))
		client := newClient(t, authority, srv.Addr().String(), smithURI)

		started, err := client.Start(
			t.Context(),
			&fizzledv1.StartRequest{Count: 100},
		)
		if err != nil {
			t.Fatalf("unexpected error from Start(): %v", err)
		}

		stream, err := client.StreamOutput(
			t.Context(),
			&fizzledv1.StreamOutputRequest{JobId: started.GetJobId()},
		)
		if err != nil {
			t.Fatalf("unexpected error from StreamOutput(): %v", err)
		}

		// Reading the first tick is what proves the handler is running, and so
		// that the shutdown below has a stream to wait for.
		_, err = stream.Recv()
		if err != nil {
			t.Fatalf("unexpected error from Recv(): %v", err)
		}

		stop()

		last, err := drainTicks(t, stream)
		if !errors.Is(err, io.EOF) {
			t.Errorf("expected the stream to close cleanly, got %v", err)
		}

		if last.GetStopped() == nil {
			t.Errorf("expected the stream to close on a stopped tick, got %v", last)
		}
	})

	t.Run("reports a clean stop when the shutdown wins the start", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(t.Context())

		authority := testpki.NewAuthority(t, testpki.NewAuthorityOptions())

		srv, err := server.New(ctx, newConfig(t, authority, smith), nil)
		if err != nil {
			t.Fatalf("new server: %v", err)
		}

		cancel()

		err = srv.Serve(ctx)
		if err != nil {
			t.Errorf("expected a clean stop, got %v", err)
		}
	})

	t.Run("refuses RPCs once it has stopped serving", func(t *testing.T) {
		t.Parallel()

		authority := testpki.NewAuthority(t, testpki.NewAuthorityOptions())
		srv, stop := newServer(t, newConfig(t, authority, smith))
		client := newClient(t, authority, srv.Addr().String(), smithURI)

		_, err := client.Start(t.Context(), &fizzledv1.StartRequest{Count: 100})
		if err != nil {
			t.Fatalf("unexpected error from Start(): %v", err)
		}

		stop()

		_, err = client.Start(t.Context(), &fizzledv1.StartRequest{Count: 1})
		assertErrorCode(t, err, codes.Unavailable)
	})
}

// newConfig is a Config that stands a server up from authority, on a port the
// operating system chooses, granting USER to each of agents. A test that wants a
// particular field broken overwrites it.
func newConfig(
	tb testing.TB,
	authority testpki.Authority,
	agents ...authn.AgentID,
) server.Config {
	tb.Helper()

	certPath, keyPath := testpki.NewLeafFiles(tb, authority, testpki.NewLeafOptions(serverURI))
	caPath := testpki.WriteCertificate(tb, tb.TempDir(), "ca.crt", authority.Certificate)

	return server.Config{
		Address:       "127.0.0.1:0",
		CAPath:        caPath,
		CertPath:      certPath,
		KeyPath:       keyPath,
		RolesPath:     writeRoles(tb, agents...),
		ShutdownGrace: 0,
	}
}

// newServer stands a server up from config and serves it until the returned stop
// is called or the test ends.
func newServer(tb testing.TB, config server.Config) (*server.Server, func()) {
	tb.Helper()

	srv, err := server.New(tb.Context(), config, nil)
	if err != nil {
		tb.Fatalf("new server: %v", err)
	}

	serveCtx, stopServing := context.WithCancel(tb.Context())
	served := make(chan error, 1)

	go func() { served <- srv.Serve(serveCtx) }()

	stop := sync.OnceFunc(func() {
		stopServing()

		serveErr := <-served
		if serveErr != nil {
			tb.Errorf("unexpected error from Serve(): %v", serveErr)
		}
	})

	tb.Cleanup(stop)

	return srv, stop
}

// newClient returns a client presenting a leaf that authority issued for
// agentURI, against the server at address.
//
//nolint:ireturn // The generated client is an interface.
func newClient(
	tb testing.TB,
	authority testpki.Authority,
	address, agentURI string,
) fizzledv1.FizzledServiceClient {
	tb.Helper()

	certPath, keyPath := testpki.NewLeafFiles(tb, authority, testpki.NewLeafOptions(agentURI))

	// Through an Authenticator rather than a tls.Config assembled here, so that
	// what the test presents is what a client of this server would.
	caPath := testpki.WriteCertificate(tb, tb.TempDir(), "ca.crt", authority.Certificate)

	authenticator, err := authn.NewAuthenticator(caPath, nil)
	if err != nil {
		tb.Fatalf("new authenticator: %v", err)
	}

	clientConfig, err := authenticator.ClientConfig(certPath, keyPath)
	if err != nil {
		tb.Fatalf("client config: %v", err)
	}

	connection, err := grpc.NewClient(
		address,
		grpc.WithTransportCredentials(credentials.NewTLS(clientConfig)),
	)
	if err != nil {
		tb.Fatalf("dial: %v", err)
	}

	tb.Cleanup(func() { _ = connection.Close() })

	return fizzledv1.NewFizzledServiceClient(connection)
}

// drainTicks reads a client stream to its end, and returns the last tick it
// carried along with the error that ended it. Whether that error is io.EOF is
// how a stream that closed on its own is told from one that was cut off.
func drainTicks(
	tb testing.TB,
	stream grpc.ServerStreamingClient[fizzledv1.StreamOutputResponse],
) (*fizzledv1.Tick, error) {
	tb.Helper()

	var last *fizzledv1.Tick

	for {
		response, err := stream.Recv()
		if err != nil {
			if last == nil {
				tb.Fatalf("expected at least one tick, got none")
			}

			return last, fmt.Errorf("drain ticks: %w", err)
		}

		last = response.GetTick()
	}
}

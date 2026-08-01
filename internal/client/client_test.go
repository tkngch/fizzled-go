package client_test

import (
	"context"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/tkngch/fizzled-go/internal/authn"
	"github.com/tkngch/fizzled-go/internal/client"
	"github.com/tkngch/fizzled-go/internal/server"
	"github.com/tkngch/fizzled-go/internal/testpki"
	"github.com/tkngch/fizzled-go/internal/worker"
)

// The agents these tests act as, and the SVIDs they present.
const (
	smith     authn.AgentID = "smith"
	jones     authn.AgentID = "jones"
	serverURI string        = "spiffe://fizzled.internal/server"
	smithURI  string        = "spiffe://fizzled.internal/client/agent/smith"
	jonesURI  string        = "spiffe://fizzled.internal/client/agent/jones"
)

func TestNewClient(t *testing.T) {
	t.Parallel()

	fizzle := newClientForAgentSmith(t)

	jobID, err := fizzle.Start(t.Context(), 1)
	if err != nil {
		t.Fatalf("unexpected error from Start(): %v", err)
	}

	for tick, err := range fizzle.StreamOutput(t.Context(), jobID) {
		if err != nil {
			t.Fatalf("unexpected error from StreamOutput(): %v", err)
		}

		if !strings.HasPrefix(string(tick), `{"progress":`) {
			t.Errorf("expected a progress tick, got %s", string(tick))
		}
	}

	status, err := fizzle.GetStatus(t.Context(), jobID)
	if err != nil {
		t.Fatalf("unexpected error from GetStatus(): %v", err)
	}

	if status != worker.StatusCompleted {
		t.Errorf("expected COMPLETED status, got %v", status)
	}
}

func TestNewClientStop(t *testing.T) {
	t.Parallel()

	fizzle := newClientForAgentSmith(t)

	jobID, err := fizzle.Start(t.Context(), 100)
	if err != nil {
		t.Fatalf("unexpected error from Start(): %v", err)
	}

	status, err := fizzle.GetStatus(t.Context(), jobID)
	if err != nil {
		t.Fatalf("unexpected error from GetStatus(): %v", err)
	}

	if status != worker.StatusRunning {
		t.Errorf("expected RUNNING status, got %v", status)
	}

	type streamOutput struct {
		tick []byte
		err  error
	}

	lastOutput := make(chan streamOutput, 1)

	go func() {
		var lastTick []byte

		for tick, err := range fizzle.StreamOutput(t.Context(), jobID) {
			if err != nil {
				lastOutput <- streamOutput{tick: nil, err: err}

				return
			}

			lastTick = tick
		}

		lastOutput <- streamOutput{tick: lastTick, err: nil}
	}()

	status, err = fizzle.Stop(t.Context(), jobID)
	if err != nil {
		t.Fatalf("unexpected error from Stop(): %v", err)
	}

	if status != worker.StatusStopped {
		t.Errorf("expected STOPPED status, got %v", status)
	}

	output := <-lastOutput
	if output.err != nil {
		t.Fatalf("unexpected error from StreamOutput(): %v", output.err)
	}

	if string(output.tick) != `{"stopped":{}}` {
		t.Errorf("expected STOPPED tick, got %s", string(output.tick))
	}
}

// TestNewRejectsMisconfiguration pins down that every path in a Config is
// resolved before anything is dialed, so a client that could never be
// authenticated fails here rather than on its first RPC.
func TestNewRejectsMisconfiguration(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		apply func(tb testing.TB, authority testpki.Authority, config *client.Config)
	}{
		{
			name: "unreadable trust bundle",
			apply: func(tb testing.TB, _ testpki.Authority, config *client.Config) {
				tb.Helper()

				config.CAPath = filepath.Join(tb.TempDir(), "absent-ca.crt")
			},
		},
		{
			name: "unreadable certificate",
			apply: func(tb testing.TB, _ testpki.Authority, config *client.Config) {
				tb.Helper()

				config.CertPath = filepath.Join(tb.TempDir(), "absent.crt")
			},
		},
		{
			name: "unreadable key",
			apply: func(tb testing.TB, _ testpki.Authority, config *client.Config) {
				tb.Helper()

				config.KeyPath = filepath.Join(tb.TempDir(), "absent.key")
			},
		},
		{
			// An address that is not an address at all. It reaches a different
			// failure from the ones above, which are about files, and it should
			// still leave as the same kind of error.
			name: "an address that cannot be parsed",
			apply: func(_ testing.TB, _ testpki.Authority, config *client.Config) {
				config.Address = "\x7f"
			},
		},
		{
			name: "an empty address",
			apply: func(_ testing.TB, _ testpki.Authority, config *client.Config) {
				config.Address = ""
			},
		},
		{
			name: "an SVID the server would never accept",
			apply: func(tb testing.TB, authority testpki.Authority, config *client.Config) {
				tb.Helper()

				// A well-formed leaf from the right authority, but carrying the
				// server identity where an agent identity belongs.
				config.CertPath, config.KeyPath = testpki.NewLeafFiles(
					tb,
					authority,
					testpki.NewLeafOptions(serverURI),
				)
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			authority := testpki.NewAuthority(t, testpki.NewAuthorityOptions())

			config := newConfig(t, authority, "127.0.0.1:1", smithURI)
			testCase.apply(t, authority, &config)

			_, err := client.New(config, nil)
			if !errors.Is(err, client.ErrConfig) {
				t.Errorf("expected ErrConfig for %s, got [%v]", testCase.name, err)
			}
		})
	}
}

func TestStartInvalidArgument(t *testing.T) {
	t.Parallel()

	testCases := []int{math.MinInt32 - 1, math.MaxInt32 + 1, -1}
	fizzle := newClientForAgentSmith(t)

	for _, count := range testCases {
		t.Run(fmt.Sprintf("count %d", count), func(t *testing.T) {
			t.Parallel()

			_, err := fizzle.Start(t.Context(), count)
			if !errors.Is(err, client.ErrInvalidArgument) {
				t.Errorf("expected ErrInvalidArgument, got [%v]", err)
			}
		})
	}
}

func TestClientReportsUnavailableOnARefusedHandshake(t *testing.T) {
	t.Parallel()

	srv := newServer(t, testpki.NewAuthority(t, testpki.NewAuthorityOptions()), smith)

	config := newConfig(
		t,
		testpki.NewAuthority(t, testpki.NewAuthorityOptions()),
		srv.Addr().String(),
		smithURI,
	)
	fizzle := newClientWith(t, config)

	_, err := fizzle.Start(t.Context(), 1)
	if !errors.Is(err, client.ErrUnavailable) {
		t.Errorf("expected ErrUnavailable, got [%v]", err)
	}
}

// TestClientReportsNotFoundForAnUnknownJob covers every id-bearing method. The
// status-to-sentinel mapping is pinned in errors_test.go; what is pinned here is
// that each method routes its failure through that mapping at all.
//
//nolint:wrapcheck // The closures below hand errors to errors.Is, not to a caller.
func TestClientReportsNotFoundForAnUnknownJob(t *testing.T) {
	t.Parallel()

	const unknown worker.JobID = "no-such-job"

	fizzle := newClientForAgentSmith(t)

	testCases := []struct {
		name string
		call func(context.Context) error
	}{
		{
			name: "GetStatus",
			call: func(ctx context.Context) error {
				_, err := fizzle.GetStatus(ctx, unknown)

				return err
			},
		},
		{
			name: "Stop",
			call: func(ctx context.Context) error {
				_, err := fizzle.Stop(ctx, unknown)

				return err
			},
		},
		{
			// A server-streaming RPC reports the rejection on the first Recv
			// rather than when the stream is opened, so this reaches the
			// mapping by a different route from the two above.
			name: "StreamOutput",
			call: func(ctx context.Context) error {
				for _, err := range fizzle.StreamOutput(ctx, unknown) {
					if err != nil {
						return err
					}
				}

				return nil
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := testCase.call(t.Context())
			if !errors.Is(err, client.ErrNotFound) {
				t.Errorf("expected ErrNotFound, got [%v]", err)
			}
		})
	}
}

func TestClientReportsNotFoundForAJobAnotherAgentOwns(t *testing.T) {
	t.Parallel()

	authority := testpki.NewAuthority(t, testpki.NewAuthorityOptions())
	srv := newServer(t, authority, smith, jones)

	smithClient := newClientWith(t, newConfig(t, authority, srv.Addr().String(), smithURI))
	jonesClient := newClientWith(t, newConfig(t, authority, srv.Addr().String(), jonesURI))

	jobID, err := smithClient.Start(t.Context(), 100)
	if err != nil {
		t.Fatalf("unexpected error from Start(): %v", err)
	}

	_, err = jonesClient.GetStatus(t.Context(), jobID)
	if !errors.Is(err, client.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got [%v]", err)
	}
}

func TestClientReportsPermissionDeniedForAnAgentWithNoRole(t *testing.T) {
	t.Parallel()

	authority := testpki.NewAuthority(t, testpki.NewAuthorityOptions())

	// A roles file granting USER to jones and nothing to smith. It cannot be
	// empty: the authorizer refuses to load a roles file that grants nothing.
	srv := newServer(t, authority, jones)

	fizzle := newClientWith(t, newConfig(t, authority, srv.Addr().String(), smithURI))

	_, err := fizzle.Start(t.Context(), 1)
	if !errors.Is(err, client.ErrPermissionDenied) {
		t.Errorf("expected ErrPermissionDenied, got [%v]", err)
	}
}

// newConfig is a valid Config for an agent presenting agentURI. A test
// that wants a particular field broken overwrites it.
func newConfig(
	tb testing.TB,
	authority testpki.Authority,
	address, agentURI string,
) client.Config {
	tb.Helper()

	certPath, keyPath := testpki.NewLeafFiles(tb, authority, testpki.NewLeafOptions(agentURI))

	return client.Config{
		Address:  address,
		CAPath:   testpki.WriteCertificate(tb, tb.TempDir(), "ca.crt", authority.Certificate),
		CertPath: certPath,
		KeyPath:  keyPath,
	}
}

func newClientForAgentSmith(tb testing.TB) *client.Client {
	tb.Helper()

	authority := testpki.NewAuthority(tb, testpki.NewAuthorityOptions())
	srv := newServer(tb, authority, smith)

	config := newConfig(tb, authority, srv.Addr().String(), smithURI)

	return newClientWith(tb, config)
}

func newClientWith(
	tb testing.TB,
	config client.Config,
) *client.Client {
	tb.Helper()

	clt, err := client.New(config, nil)
	if err != nil {
		tb.Fatalf("unexpected error from New(): %v", err)
	}

	tb.Cleanup(func() {
		closeErr := clt.Close()
		if closeErr != nil {
			tb.Errorf("unexpected error from Close(): %v", closeErr)
		}
	})

	return clt
}

func newServer(
	tb testing.TB,
	authority testpki.Authority,
	agents ...authn.AgentID,
) *server.Server {
	tb.Helper()

	certPath, keyPath := testpki.NewLeafFiles(tb, authority, testpki.NewLeafOptions(serverURI))
	caPath := testpki.WriteCertificate(tb, tb.TempDir(), "ca.crt", authority.Certificate)

	config := server.Config{
		Address:       "127.0.0.1:0",
		CAPath:        caPath,
		CertPath:      certPath,
		KeyPath:       keyPath,
		RolesPath:     testpki.WriteRoles(tb, agents...),
		ShutdownGrace: 0,
	}

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

	return srv
}

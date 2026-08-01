package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tkngch/fizzled-go/internal/authn"
	"github.com/tkngch/fizzled-go/internal/server"
	"github.com/tkngch/fizzled-go/internal/testpki"
	"github.com/tkngch/fizzled-go/internal/worker"
)

// The agents these tests act as, and the SVIDs they present.
const (
	smith     authn.AgentID = "smith"
	serverURI string        = "spiffe://fizzled.internal/server"
	smithURI  string        = "spiffe://fizzled.internal/client/agent/smith"
)

func TestRunStart(t *testing.T) {
	t.Parallel()

	flags := flagsForAgentSmith(t)

	code, stdout, stderr := runFizzle(t, arguments("start", flags, "5")...)
	assertCode(t, exitSuccess, code, stdout, stderr)

	if strings.TrimSpace(stdout) == "" {
		t.Error("expected a job id on stdout, got nothing")
	}

	if !strings.HasSuffix(stdout, "\n") || strings.Count(stdout, "\n") != 1 {
		t.Errorf("expected exactly one line on stdout, got [%q]", stdout)
	}

	if stderr != "" {
		t.Errorf("expected nothing on stderr, got [%q]", stderr)
	}
}

func TestRunStatus(t *testing.T) {
	t.Parallel()

	flags := flagsForAgentSmith(t)
	jobID := startRunning(t, flags)

	code, stdout, stderr := runFizzle(t, arguments("status", flags, jobID)...)
	assertCode(t, exitSuccess, code, stdout, stderr)

	expected := string(worker.StatusRunning) + "\n"
	if stdout != expected {
		t.Errorf("expected [%q], got [%q]", expected, stdout)
	}
}

func TestRunStopPrintsNothing(t *testing.T) {
	t.Parallel()

	flags := flagsForAgentSmith(t)
	jobID := startRunning(t, flags)

	for _, name := range []string{"a running countdown", "an already-stopped one"} {
		code, stdout, stderr := runFizzle(t, arguments("stop", flags, jobID)...)
		assertCode(t, exitSuccess, code, stdout, stderr)

		if stdout != "" {
			t.Errorf("expected nothing on stdout for %s, got [%q]", name, stdout)
		}

		if stderr != "" {
			t.Errorf("expected nothing on stderr for %s, got [%q]", name, stderr)
		}
	}

	code, stdout, stderr := runFizzle(t, arguments("status", flags, jobID)...)
	assertCode(t, exitSuccess, code, stdout, stderr)

	expected := string(worker.StatusStopped) + "\n"
	if stdout != expected {
		t.Errorf("expected [%q], got [%q]", expected, stdout)
	}
}

func TestRunOutputs(t *testing.T) {
	t.Parallel()

	flags := flagsForAgentSmith(t)
	jobID := startRunning(t, flags)

	code, stdout, stderr := runFizzle(t, arguments("stop", flags, jobID)...)
	assertCode(t, exitSuccess, code, stdout, stderr)

	code, stdout, stderr = runFizzle(t, arguments("outputs", flags, jobID)...)
	assertCode(t, exitSuccess, code, stdout, stderr)

	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")

	for _, line := range lines {
		if !json.Valid([]byte(line)) {
			t.Errorf("expected every line to be JSON, got [%q]", line)
		}
	}

	if !strings.HasPrefix(lines[0], `{"progress":`) {
		t.Errorf("expected the first tick to be a progress tick, got [%q]", lines[0])
	}

	if last := lines[len(lines)-1]; last != `{"stopped":{}}` {
		t.Errorf("expected the last tick to be [%s], got [%q]", `{"stopped":{}}`, last)
	}
}

func TestRunReportsNotFound(t *testing.T) {
	t.Parallel()

	flags := flagsForAgentSmith(t)

	for _, name := range []string{"stop", "status", "outputs"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			code, stdout, stderr := runFizzle(t, arguments(name, flags, "no-such-job")...)
			assertCode(t, exitFailure, code, stdout, stderr)

			if stdout != "" {
				t.Errorf("expected nothing on stdout, got [%q]", stdout)
			}

			if stderr == "" {
				t.Error("expected a diagnostic on stderr, got nothing")
			}
		})
	}
}

// TestRunRejectsBadUsage covers the argument grammar, which parse refuses
// before any of it reaches a server. Every one of them is a command line that
// could not be read, so every one of them exits 2 and is answered with the
// usage on stderr.
func TestRunRejectsBadUsage(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		args []string
	}{
		{name: "no command", args: []string{}},
		{name: "an unknown command", args: []string{"bogus", "1"}},
		{name: "missing argument", args: []string{"status"}},
		{name: "more than one arguments", args: []string{"status", "a", "b"}},
		{name: "an unknown flag", args: []string{"start", "--nosuch", "1"}},
		{name: "invalid count", args: []string{"start", "ten"}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			code, stdout, stderr := runFizzle(t, testCase.args...)
			assertCode(t, exitUsage, code, stdout, stderr)

			if stdout != "" {
				t.Errorf("expected nothing on stdout, got [%q]", stdout)
			}

			if !strings.Contains(stderr, usage) {
				t.Errorf("expected the usage on stderr, got [%q]", stderr)
			}
		})
	}
}

func TestRunReportsUsageForAnUnreadableCertificate(t *testing.T) {
	t.Parallel()

	authority := testpki.NewAuthority(t, testpki.NewAuthorityOptions())
	missing := t.TempDir()

	flags := []string{
		"--server", "127.0.0.1:1",
		"--ca", testpki.WriteCertificate(t, t.TempDir(), "ca.crt", authority.Certificate),
		"--cert", filepath.Join(missing, "no-such.crt"),
		"--key", filepath.Join(missing, "no-such.key"),
	}

	code, stdout, stderr := runFizzle(t, arguments("start", flags, "1")...)
	assertCode(t, exitUsage, code, stdout, stderr)
}

func TestRunReportsFailureOnARefusedHandshake(t *testing.T) {
	t.Parallel()

	address := newServer(t, testpki.NewAuthority(t, testpki.NewAuthorityOptions()), smith)

	foreign := testpki.NewAuthority(t, testpki.NewAuthorityOptions())
	flags := flags(t, foreign, address, smithURI)

	code, stdout, stderr := runFizzle(t, arguments("start", flags, "1")...)
	assertCode(t, exitFailure, code, stdout, stderr)
}

func TestRunPrintsHelpOnStdout(t *testing.T) {
	t.Parallel()

	code, stdout, stderr := runFizzle(t, "--help")
	assertCode(t, exitSuccess, code, stdout, stderr)

	if stdout != usage {
		t.Errorf("expected the usage on stdout, got [%q]", stdout)
	}

	if stderr != "" {
		t.Errorf("expected nothing on stderr, got [%q]", stderr)
	}
}

// runFizzle runs one invocation, and returns its exit code with whatever it
// wrote to stdout and to stderr.
func runFizzle(tb testing.TB, args ...string) (int, string, string) {
	tb.Helper()

	var stdout, stderr strings.Builder

	code := run(tb.Context(), args, &stdout, &stderr)

	return code, stdout.String(), stderr.String()
}

// arguments is the argument list for name, with flags between it and operand,
// which is the order the grammar takes them in.
func arguments(name string, flags []string, operand string) []string {
	args := make([]string, 0, len(flags)+2)
	args = append(args, name)
	args = append(args, flags...)

	return append(args, operand)
}

// startRunning starts a job and reports its id.
func startRunning(tb testing.TB, flags []string) string {
	tb.Helper()

	code, stdout, stderr := runFizzle(tb, arguments("start", flags, "100")...)
	if code != exitSuccess {
		tb.Fatalf("start: expected [%d], got [%d] (stderr %q)", exitSuccess, code, stderr)
	}

	return strings.TrimSpace(stdout)
}

// assertCode fails the test when code is not expected.
func assertCode(tb testing.TB, expected, code int, stdout, stderr string) {
	tb.Helper()

	if code != expected {
		tb.Errorf(
			"expected [%d], got [%d] (stdout %q, stderr %q)",
			expected,
			code,
			stdout,
			stderr,
		)
	}
}

// flagsForAgentSmith starts a server granting USER role to smith, and returns
// the flags that make fizzle talk to it as smith.
func flagsForAgentSmith(tb testing.TB) []string {
	tb.Helper()

	authority := testpki.NewAuthority(tb, testpki.NewAuthorityOptions())

	return flags(tb, authority, newServer(tb, authority, smith), smithURI)
}

// flags is the four flags that an agent presenting agentURI, with a PKI issued
// from authority.
func flags(
	tb testing.TB,
	authority testpki.Authority,
	address, agentURI string,
) []string {
	tb.Helper()

	svidPath, svidKeyPath := testpki.NewLeafFiles(
		tb,
		authority,
		testpki.NewLeafOptions(agentURI),
	)

	return []string{
		"--server", address,
		"--ca", testpki.WriteCertificate(tb, tb.TempDir(), "ca.crt", authority.Certificate),
		"--cert", svidPath,
		"--key", svidKeyPath,
	}
}

// newServer serves until the test ends, granting USER to agents, and returns
// the address it bound.
func newServer(tb testing.TB, authority testpki.Authority, agents ...authn.AgentID) string {
	tb.Helper()

	svidPath, svidKeyPath := testpki.NewLeafFiles(
		tb,
		authority,
		testpki.NewLeafOptions(serverURI),
	)

	fizzled, err := server.New(tb.Context(), server.Config{
		Address:       "127.0.0.1:0",
		CAPath:        testpki.WriteCertificate(tb, tb.TempDir(), "ca.crt", authority.Certificate),
		CertPath:      svidPath,
		KeyPath:       svidKeyPath,
		RolesPath:     testpki.WriteRoles(tb, agents...),
		ShutdownGrace: 0,
	}, nil)
	if err != nil {
		tb.Fatalf("new server: %v", err)
	}

	ctx, stopServing := context.WithCancel(tb.Context())
	served := make(chan error, 1)

	go func() { served <- fizzled.Serve(ctx) }()

	tb.Cleanup(func() {
		stopServing()

		serveErr := <-served
		if serveErr != nil {
			tb.Errorf("unexpected error from Serve(): %v", serveErr)
		}
	})

	return fizzled.Addr().String()
}

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tkngch/fizzled-go/internal/authn"
	"github.com/tkngch/fizzled-go/internal/client"
	"github.com/tkngch/fizzled-go/internal/testpki"
)

// The agents these tests act as, and the SVIDs they present.
const (
	smith     authn.AgentID = "smith"
	serverURI string        = "spiffe://fizzled.internal/server"
	smithURI  string        = "spiffe://fizzled.internal/client/agent/smith"
)

func TestRunServes(t *testing.T) {
	t.Parallel()

	authority := testpki.NewAuthority(t, testpki.NewAuthorityOptions())
	address := startServer(t, flagsForAgentSmith(t, authority)...)

	svidPath, svidKeyPath := testpki.NewLeafFiles(
		t,
		authority,
		testpki.NewLeafOptions(smithURI),
	)

	fizzle, err := client.New(client.Config{
		Address:  address,
		CAPath:   testpki.WriteCertificate(t, t.TempDir(), "ca.crt", authority.Certificate),
		CertPath: svidPath,
		KeyPath:  svidKeyPath,
	}, nil)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	t.Cleanup(func() {
		closeErr := fizzle.Close()
		if closeErr != nil {
			t.Errorf("unexpected error from Close(): %v", closeErr)
		}
	})

	jobID, err := fizzle.Start(t.Context(), 1)
	if err != nil {
		t.Fatalf("unexpected error from Start(): %v", err)
	}

	if jobID == "" {
		t.Error("expected a job id, got an empty one")
	}
}

// TestRunRejectsMisconfiguration covers what server.New refuses. Every one of
// them is something the flags named and could not be used, so every one of them
// exits 2 rather than 1.
func TestRunRejectsMisconfiguration(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		apply func(testing.TB, []string) []string
	}{
		{
			name: "an empty address",
			apply: func(tb testing.TB, args []string) []string {
				tb.Helper()

				return override(tb, args, "--server", "")
			},
		},
		{
			name: "a trust bundle that does not exist",
			apply: func(tb testing.TB, args []string) []string {
				tb.Helper()

				return override(tb, args, "--ca", filepath.Join(tb.TempDir(), "no-such.crt"))
			},
		},
		{
			name: "an SVID that does not exist",
			apply: func(tb testing.TB, args []string) []string {
				tb.Helper()

				return override(tb, args, "--cert", filepath.Join(tb.TempDir(), "no-such.crt"))
			},
		},
		{
			name: "a roles file that does not exist",
			apply: func(tb testing.TB, args []string) []string {
				tb.Helper()

				return override(tb, args, "--roles", filepath.Join(tb.TempDir(), "no-such.json"))
			},
		},
		{
			// The server refuses to start in a silent deny-all state.
			name: "a roles file that grants nothing",
			apply: func(tb testing.TB, args []string) []string {
				tb.Helper()

				return override(tb, args, "--roles", writeRoles(tb, "{}"))
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			authority := testpki.NewAuthority(t, testpki.NewAuthorityOptions())
			args := testCase.apply(t, flagsForAgentSmith(t, authority))

			code, stdout, stderr := runServer(t, args...)
			if code != exitUsage {
				t.Errorf("expected [%d], got [%d] (stderr %q)", exitUsage, code, stderr)
			}

			if stdout != "" {
				t.Errorf("expected nothing on stdout, got [%q]", stdout)
			}

			if stderr == "" {
				t.Error("expected a diagnostic on stderr, got nothing")
			}
		})
	}
}

func TestRunRejectsBadFlags(t *testing.T) {
	t.Parallel()

	code, stdout, stderr := runServer(t, "--nosuch", "x")
	if code != exitUsage {
		t.Errorf("expected [%d], got [%d]", exitUsage, code)
	}

	if stdout != "" {
		t.Errorf("expected nothing on stdout, got [%q]", stdout)
	}

	if !strings.Contains(stderr, usage) {
		t.Errorf("expected the usage on stderr, got [%q]", stderr)
	}
}

func TestRunPrintsHelpOnStdout(t *testing.T) {
	t.Parallel()

	code, stdout, stderr := runServer(t, "--help")
	if code != exitSuccess {
		t.Errorf("expected [%d], got [%d]", exitSuccess, code)
	}

	if stdout != usage {
		t.Errorf("expected the usage on stdout, got [%q]", stdout)
	}

	if stderr != "" {
		t.Errorf("expected nothing on stderr, got [%q]", stderr)
	}
}

// runServer runs the server that is expected to return without serving, and
// returns its exit code with whatever it wrote to stdout and to stderr.
func runServer(tb testing.TB, args ...string) (int, string, string) {
	tb.Helper()

	var stdout, stderr strings.Builder

	code := run(tb.Context(), args, &stdout, &stderr)

	return code, stdout.String(), stderr.String()
}

// startServer runs the server with args until the test ends, and returns the
// address it bound.
func startServer(tb testing.TB, args ...string) string {
	tb.Helper()

	reader, writer := io.Pipe()
	ctx, stop := context.WithCancel(tb.Context())
	codes := make(chan int, 1)

	go func() {
		code := run(ctx, args, io.Discard, writer)

		// Closed here, so the scanner below reaches EOF.
		_ = writer.Close()

		codes <- code
	}()

	addresses := make(chan string, 1)

	go func() {
		defer close(addresses)
		defer func() { _ = reader.Close() }()

		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			address, ok := listeningAddress(scanner.Bytes())
			if !ok {
				continue
			}

			// Non-blocking, because the buffer holds only one address.
			select {
			case addresses <- address:
			default:
			}
		}

		_ = scanner.Err()
	}()

	tb.Cleanup(func() {
		stop()

		code := <-codes
		if code != exitSuccess {
			tb.Errorf("expected [%d], got [%d]", exitSuccess, code)
		}
	})

	address, ok := <-addresses
	if !ok {
		tb.Fatal("expected the server to log the address it bound, got none")
	}

	return address
}

// listeningAddress is the address in a start-up record, and whether line was
// one.
func listeningAddress(line []byte) (string, bool) {
	var record struct {
		Msg     string `json:"msg"`
		Address string `json:"address"`
	}

	// listeningMessage is the log record that carries the bound address.
	const listeningMessage = "fizzled is listening"

	err := json.Unmarshal(line, &record)
	if err != nil || record.Msg != listeningMessage {
		return "", false
	}

	return record.Address, true
}

// flagsForAgentSmith is a working set of flags: a PKI issued from authority,
// USER granted to agent Smith, and an ephemeral port so that tests do not
// collide on one.
func flagsForAgentSmith(tb testing.TB, authority testpki.Authority) []string {
	tb.Helper()

	svidPath, svidKeyPath := testpki.NewLeafFiles(
		tb,
		authority,
		testpki.NewLeafOptions(serverURI),
	)

	return []string{
		"--server", "127.0.0.1:0",
		"--ca", testpki.WriteCertificate(tb, tb.TempDir(), "ca.crt", authority.Certificate),
		"--cert", svidPath,
		"--key", svidKeyPath,
		"--roles", testpki.WriteRoles(tb, smith),
	}
}

// override replaces the value of name in args, which is how a test breaks one
// flag of a set that is otherwise known to work.
func override(tb testing.TB, args []string, name, value string) []string {
	tb.Helper()

	replaced := slices.Clone(args)

	for index, arg := range replaced {
		if arg != name {
			continue
		}

		if index+1 == len(replaced) {
			tb.Fatalf("flag [%s] has no value to override in %v", name, args)
		}

		replaced[index+1] = value

		return replaced
	}

	tb.Fatalf("no flag [%s] to override in %v", name, args)

	return nil
}

// writeRoles writes a roles file whose contents are chosen by the caller, which
// is what testpki.WriteRoles does not allow.
func writeRoles(tb testing.TB, contents string) string {
	tb.Helper()

	path := filepath.Join(tb.TempDir(), "roles.json")

	err := os.WriteFile(path, []byte(contents), 0o600)
	if err != nil {
		tb.Fatalf("unable to write to a file [%s]: %v", path, err)
	}

	return path
}

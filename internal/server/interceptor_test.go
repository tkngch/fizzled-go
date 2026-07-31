package server_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/tkngch/fizzled-go/internal/authn"
	"github.com/tkngch/fizzled-go/internal/authz"
	fizzledv1 "github.com/tkngch/fizzled-go/internal/gen/fizzled/v1"
	"github.com/tkngch/fizzled-go/internal/server"
	"github.com/tkngch/fizzled-go/internal/testpki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func TestInterceptorUnary(t *testing.T) {
	t.Parallel()

	t.Run("handles the authenticated agent id", func(t *testing.T) {
		t.Parallel()

		interceptor, authority := newInterceptor(t, smith)

		// Read inside the handler, where a real one reads it: the id a handler
		// is given is the whole of what the interceptor promises it.
		var (
			agentID authn.AgentID
			isFound bool
		)

		_, err := interceptor.Unary()(
			peerContext(t, authority, smithURI),
			nil,
			&grpc.UnaryServerInfo{
				Server:     nil,
				FullMethod: fizzledv1.FizzledService_Start_FullMethodName,
			},
			func(ctx context.Context, _ any) (any, error) {
				agentID, isFound = server.AgentIDFrom(ctx)

				return struct{}{}, nil
			},
		)
		if err != nil {
			t.Fatalf("unexpected error from the interceptor: %v", err)
		}

		if !isFound {
			t.Fatalf("expected the handler's context to carry an agent id, got none")
		}

		if agentID != smith {
			t.Errorf("expected [%s], got [%s]", smith, agentID)
		}
	})

	t.Run("refuses an agent holding no role", func(t *testing.T) {
		t.Parallel()

		interceptor, authority := newInterceptor(t, smith)
		isCalled := false

		_, err := interceptor.Unary()(
			peerContext(t, authority, jonesURI),
			nil,
			&grpc.UnaryServerInfo{
				Server:     nil,
				FullMethod: fizzledv1.FizzledService_Start_FullMethodName,
			},
			func(context.Context, any) (any, error) {
				isCalled = true

				return struct{}{}, nil
			},
		)

		assertErrorCode(t, err, codes.PermissionDenied)

		if isCalled {
			t.Errorf("expected the handler not to run for a denied agent")
		}
	})

	t.Run("refuses a connection it cannot authenticate", func(t *testing.T) {
		t.Parallel()

		testCases := []struct {
			name string
			ctx  func(tb testing.TB, authority testpki.Authority) context.Context
		}{
			{
				name: "no peer",
				ctx: func(tb testing.TB, _ testpki.Authority) context.Context {
					tb.Helper()

					return tb.Context()
				},
			},
			{
				name: "peer without TLS",
				ctx: func(tb testing.TB, _ testpki.Authority) context.Context {
					tb.Helper()

					var peerInfo peer.Peer

					peerInfo.AuthInfo = insecureAuthInfo{}

					return peer.NewContext(tb.Context(), &peerInfo)
				},
			},
			{
				name: "leaf from an untrusted authority",
				ctx: func(tb testing.TB, _ testpki.Authority) context.Context {
					tb.Helper()

					// A well-formed SVID, but signed by an authority the trust
					// bundle knows nothing about.
					return peerContext(
						tb,
						testpki.NewAuthority(tb, testpki.NewAuthorityOptions()),
						smithURI,
					)
				},
			},
			{
				name: "leaf carrying the server identity",
				ctx: func(tb testing.TB, authority testpki.Authority) context.Context {
					tb.Helper()

					return peerContext(tb, authority, serverURI)
				},
			},
		}

		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				t.Parallel()

				interceptor, authority := newInterceptor(t, smith)

				_, err := interceptor.Unary()(
					testCase.ctx(t, authority),
					nil,
					&grpc.UnaryServerInfo{
						Server:     nil,
						FullMethod: fizzledv1.FizzledService_Start_FullMethodName,
					},
					func(context.Context, any) (any, error) { return struct{}{}, nil },
				)

				assertErrorCode(t, err, codes.Unauthenticated)
			})
		}
	})

	t.Run("turns a panic into an internal error", func(t *testing.T) {
		t.Parallel()

		interceptor, authority := newInterceptor(t, smith)

		// The test process surviving to the assertion is half of what is being
		// checked here: an unguarded panic would take it down with the server.
		_, err := interceptor.Unary()(
			peerContext(t, authority, smithURI),
			nil,
			&grpc.UnaryServerInfo{
				Server:     nil,
				FullMethod: fizzledv1.FizzledService_Start_FullMethodName,
			},
			func(context.Context, any) (any, error) { panic("handler panic") },
		)

		assertErrorCode(t, err, codes.Internal)
	})

	t.Run("refuses a method it maps to no action", func(t *testing.T) {
		t.Parallel()

		interceptor, authority := newInterceptor(t, smith)

		_, err := interceptor.Unary()(
			peerContext(t, authority, smithURI),
			nil,
			&grpc.UnaryServerInfo{
				Server:     nil,
				FullMethod: "/fizzled.v1.FizzledService/Unmapped",
			},
			func(context.Context, any) (any, error) { return struct{}{}, nil },
		)

		// Internal rather than PermissionDenied: an unmapped method is a server
		// that was extended without its authorization mapping, not an agent
		// reaching for something it may not have.
		assertErrorCode(t, err, codes.Internal)
	})
}

func TestInterceptorStream(t *testing.T) {
	t.Parallel()

	t.Run("handles a stream carrying the agent id", func(t *testing.T) {
		t.Parallel()

		interceptor, authority := newInterceptor(t, smith)

		var (
			agentID authn.AgentID
			isFound bool
		)

		err := interceptor.Stream()(
			nil,
			newRecordingStream(peerContext(t, authority, smithURI)),
			&grpc.StreamServerInfo{
				FullMethod:     fizzledv1.FizzledService_StreamOutput_FullMethodName,
				IsClientStream: false,
				IsServerStream: true,
			},
			func(_ any, stream grpc.ServerStream) error {
				agentID, isFound = server.AgentIDFrom(stream.Context())

				return nil
			},
		)
		if err != nil {
			t.Fatalf("unexpected error from the interceptor: %v", err)
		}

		if !isFound {
			t.Fatalf("expected the handler's stream to carry an agent id, got none")
		}

		if agentID != smith {
			t.Errorf("expected [%s], got [%s]", smith, agentID)
		}
	})

	t.Run("refuses an agent holding no role", func(t *testing.T) {
		t.Parallel()

		interceptor, authority := newInterceptor(t, smith)
		isCalled := false

		err := interceptor.Stream()(
			nil,
			newRecordingStream(peerContext(t, authority, jonesURI)),
			&grpc.StreamServerInfo{
				FullMethod:     fizzledv1.FizzledService_StreamOutput_FullMethodName,
				IsClientStream: false,
				IsServerStream: true,
			},
			func(any, grpc.ServerStream) error {
				isCalled = true

				return nil
			},
		)

		assertErrorCode(t, err, codes.PermissionDenied)

		if isCalled {
			t.Errorf("expected the handler not to run for a denied agent")
		}
	})

	t.Run("turns a panic into an internal error", func(t *testing.T) {
		t.Parallel()

		interceptor, authority := newInterceptor(t, smith)

		err := interceptor.Stream()(
			nil,
			newRecordingStream(peerContext(t, authority, smithURI)),
			&grpc.StreamServerInfo{
				FullMethod:     fizzledv1.FizzledService_StreamOutput_FullMethodName,
				IsClientStream: false,
				IsServerStream: true,
			},
			func(any, grpc.ServerStream) error { panic("handler panic") },
		)

		assertErrorCode(t, err, codes.Internal)
	})
}

// TestInterceptorCoversEveryMethod walks the service descriptor rather than a
// list written out here, so an RPC added to the proto without a matching action
// fails this test instead of quietly landing on the fail-closed branch.
func TestInterceptorCoversEveryMethod(t *testing.T) {
	t.Parallel()

	descriptor := fizzledv1.FizzledService_ServiceDesc

	for _, method := range descriptor.Methods {
		t.Run(method.MethodName, func(t *testing.T) {
			t.Parallel()

			interceptor, authority := newInterceptor(t, smith)

			_, err := interceptor.Unary()(
				peerContext(t, authority, smithURI),
				nil,
				&grpc.UnaryServerInfo{
					Server:     nil,
					FullMethod: "/" + descriptor.ServiceName + "/" + method.MethodName,
				},
				func(context.Context, any) (any, error) { return struct{}{}, nil },
			)
			if err != nil {
				t.Errorf("expected %s to map to an action, got %v", method.MethodName, err)
			}
		})
	}

	for _, stream := range descriptor.Streams {
		t.Run(stream.StreamName, func(t *testing.T) {
			t.Parallel()

			interceptor, authority := newInterceptor(t, smith)

			err := interceptor.Stream()(
				nil,
				newRecordingStream(peerContext(t, authority, smithURI)),
				&grpc.StreamServerInfo{
					FullMethod:     "/" + descriptor.ServiceName + "/" + stream.StreamName,
					IsClientStream: stream.ClientStreams,
					IsServerStream: stream.ServerStreams,
				},
				func(any, grpc.ServerStream) error { return nil },
			)
			if err != nil {
				t.Errorf("expected %s to map to an action, got %v", stream.StreamName, err)
			}
		})
	}
}

// newInterceptor is an Interceptor trusting a freshly issued authority, which it
// hands back, and granting USER to each of agents.
//
// The authority is a return value rather than a parameter so that a test cannot
// accidentally pair an interceptor with the wrong authority.
func newInterceptor(
	tb testing.TB,
	agents ...authn.AgentID,
) (*server.Interceptor, testpki.Authority) {
	tb.Helper()

	authority := testpki.NewAuthority(tb, testpki.NewAuthorityOptions())
	caPath := testpki.WriteCertificate(tb, tb.TempDir(), "ca.crt", authority.Certificate)

	authenticator, err := authn.NewAuthenticator(caPath, nil)
	if err != nil {
		tb.Fatalf("new authenticator: %v", err)
	}

	authorizer, err := authz.Load(writeRoles(tb, agents...))
	if err != nil {
		tb.Fatalf("load roles: %v", err)
	}

	return server.NewInterceptor(authenticator, authorizer, nil), authority
}

// peerContext presents a leaf that authority issued for uri as the peer of an
// mTLS connection.
func peerContext(tb testing.TB, authority testpki.Authority, uri string) context.Context {
	tb.Helper()

	certificate, _ := testpki.NewLeaf(tb, authority, testpki.NewLeafOptions(uri))

	var state tls.ConnectionState

	state.PeerCertificates = []*x509.Certificate{certificate}

	var authInfo credentials.TLSInfo

	authInfo.State = state

	var peerInfo peer.Peer

	peerInfo.AuthInfo = authInfo

	return peer.NewContext(tb.Context(), &peerInfo)
}

// insecureAuthInfo stands in for a peer that completed no TLS handshake.
type insecureAuthInfo struct{}

func (insecureAuthInfo) AuthType() string {
	return "insecure"
}

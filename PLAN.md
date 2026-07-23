# Step 1 — Move AgentID from authz to authn

The identity is minted by authentication and consumed by authorization, so the
type belongs to the producer. internal/authz/id.go:17-19 already says as much:
its validate() doc comment notes "the rule comes from the authentication
layer". Moving it also drops registry's dependency on authz entirely —
after the move registry imports only authn and worker.

- Move AgentID, ErrInvalidAgentID, and validate() from
internal/authz/id.go into internal/authn/id.go, exporting it as
Validate() so authz.Load can still call it. Keep the body as-is:
strings.TrimSpace(...) == "" plus strings.ContainsAny(string(a), "/.")
already covers the README's "empty, or contains /, ., or .." rule.
Delete internal/authz/id.go.
- Update internal/authz/authorizer.go (5 references, and
agentID.validate() → agentID.Validate()).
- Update internal/registry/registry.go and record.go (authz.AgentID →
authn.AgentID; the authz import goes away in both).
- Update the tests that name the type or the sentinel:
internal/authz/authorizer_test.go and internal/registry/registry_test.go.
internal/authz/role_test.go is untouched.

No import cycle: authn does not import authz.

# Step 2 — internal/authn itself

Five source files, mirroring authz's granularity.

## doc.go

Package doc in the style of authz/doc.go: authn establishes who the peer is;
authz decides what they may do.

## id.go — SPIFFE ID and AgentID

- AgentID and Validate(), moved in step 1.
- A SPIFFEID type parsed from a *url.URL. Certificates expose cert.URIs
already parsed, so never re-parse from a string.
- Shared validation: scheme is spiffe, authority is countdown.internal, and
no userinfo, port, query, or fragment.
- Two shapes, per README lines 353-375:
  - server: exactly one path component, server;
  - client: exactly three — client, agent, <agent identifier>.
The exactly-N-components rule already rejects stray / (X.509-SVID path
validation).
- AgentID() returns the third component of a client ID, run through
Validate().
- Sentinels: ErrInvalidSPIFFEID, ErrUnexpectedIdentity.

## svid.go — leaf certificate policy

Role-independent X.509-SVID leaf checks, from README lines 349-386:

- exactly one URI SAN — reject zero, reject two or more;
- cA false in basic constraints;
- neither x509.KeyUsageCertSign nor x509.KeyUsageCRLSign set;
- public key is ECDSA on P-256 (*ecdsa.PublicKey with
Curve == elliptic.P256()), matching the Secrets issuance policy.

A distinct sentinel per failure class, so the audit log can name a reason.

## verifier.go — chain verification and peer identity

Builds the func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
closure for tls.Config.VerifyPeerCertificate, parameterised by the expected
peer shape: the server expects a client SVID, the client expects the server
SVID.

- Parses rawCerts and verifies the chain via x509.Certificate.Verify against
the trust bundle, with KeyUsages: []x509.ExtKeyUsage{ExtKeyUsageClientAuth}
on the server side and ExtKeyUsageServerAuth on the client side. Every leaf
carries both EKUs by design (README line 487-490), so the EKU is not what
separates the roles — the URI-SAN path check is.
- One verifier serves both directions. The client side must set
InsecureSkipVerify: true to drop hostname verification, since our leaves
carry no DNS SAN; that also drops chain verification and leaves
verifiedChains nil, so manual verification is unavoidable there. Using
ClientAuth: tls.RequireAnyClientCert on the server side runs that same
tested path in both directions. The server thereby gives up Go's built-in
chain check as a backstop — but it has to regardless, because that check runs
at time.Now() and would reject a certificate inside the skew window before
our verifier ever saw it.
- Clock skew: clamp the verification time into the leaf's validity window —
use leaf.NotBefore when now is up to skew early, leaf.NotAfter when it
is up to skew late, otherwise now — and pass it as
x509.VerifyOptions.CurrentTime. One pass, no retry loop, testable at both
boundaries. skew is a package constant of 2 minutes.
- Errors wrap the SPIFFE ID and the certificate serial number where known, and
never the PEM: the README's Audit section wants "the extracted SPIFFE ID, and
accept/reject with the reason on rejection" while forbidding key material in
logs.

## config.go — TLS configuration and PEM loading

- ServerConfig and ClientConfig, each taking certificate, key, and
trust-bundle paths and returning *tls.Config.
- Trust bundle via x509.NewCertPool() + AppendCertsFromPEM, treating a
false return as an error — an empty or unreadable bundle must fail loudly at
start-up, as authz.Load does for empty roles (authorizer.go:55-57).
- Key pair via tls.LoadX509KeyPair.
- MinVersion: tls.VersionTLS12, Renegotiation: tls.RenegotiateNever, and
CipherSuites set to the two ECDSA suites in README lines 405-409. Go does
not allow configuring TLS 1.3 suites and already offers exactly the three the
README asks for, so there is nothing to set there.
- Wires in the verifier plus InsecureSkipVerify / ClientAuth as above.

## Identity extraction for the RPC layer

AgentIDFromConnectionState(state tls.ConnectionState) (AgentID, error) — the
function that started this discussion, but taking a tls.ConnectionState rather
than a gRPC type, so authn stays stdlib-only. A future server package converts
from credentials.TLSInfo, which will also need depguard's allowlist widened
for gRPC. It re-reads the URI SAN from the peer leaf and returns the AgentID
that authz.Authorize and registry.Find take. Belongs in id.go; not worth
its own file.

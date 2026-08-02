# How mTLS operates in this project

`README.md` gives the requirements for this system. This document tells you how
the mTLS mechanism operates. It uses the code as an example.

Each statement in this document has a `file:line` reference. You can compare
each statement with the source code.

## Contents

1. [What mTLS gives](#what-mtls-gives)
2. [The parts that exist before a connection](#the-parts-that-exist-before-a-connection)
3. [The trust bundle](#the-trust-bundle)
4. [The SPIFFE identity](#the-spiffe-identity)
5. [The handshake](#the-handshake)
6. [What the client sends](#what-the-client-sends)
7. [How the client authenticates the server](#how-the-client-authenticates-the-server)
8. [How the server authenticates the client](#how-the-server-authenticates-the-client)
9. [Session resumption](#session-resumption)
10. [The protection after the handshake](#the-protection-after-the-handshake)
11. [From the identity to the authorization](#from-the-identity-to-the-authorization)
12. [The audit record](#the-audit-record)
13. [The certificate lifecycle](#the-certificate-lifecycle)
14. [The limits of this design](#the-limits-of-this-design)
15. [Where the code is](#where-the-code-is)

## What mTLS gives

TLS gives three properties to a connection:

- **Authentication.** Each side knows the identity of the other side.
- **Confidentiality.** A person who monitors the network cannot read the data.
- **Integrity.** A person who monitors the network cannot change the data. The
  receiver detects each change.

The usual TLS authenticates one party only. The server shows its identity, and
the client stays unknown. Then the application must identify the client by a
different method, for example a password or a token.

mTLS means *mutual TLS*. It uses the same procedure in the two directions. The
client also shows a certificate, and the server verifies it. Thus this project
needs no password and no token. The certificate is the credential
(`README.md:49-54`).

mTLS does not give authorization. It tells the server *who* the caller is. It
does not tell the server *what* the caller can do. This project keeps the two
apart. See [From the identity to the
authorization](#from-the-identity-to-the-authorization).

## The parts that exist before a connection

The command `make secrets` (`makefile:55-167`) makes a PKI with two levels in
the directory `.secrets/`.

**One self-signed root CA** — the files `ca.crt` and `ca-private.key`
(`makefile:115-122`):

- The key is ECDSA P-256.
- The certificate has `CA:TRUE, pathlen:0`. Thus the CA can sign leaf
  certificates, but it cannot sign a second CA.
- The certificate is valid for 1825 days.
- The SAN is `URI:spiffe://fizzled.internal`. This SAN connects the root to the
  trust domain. Without this SAN, the root has no SPIFFE ID. Then the
  trust-domain checks on a signing certificate have no data to compare, and they
  agree with all certificates.

**Leaf certificates**, one for each identity. The CA signs them
(`makefile:124-141`, `makefile:153-164`):

- Each key is ECDSA P-256.
- Each certificate has `CA:FALSE` and `digitalSignature` only.
- Each certificate has the two EKUs `serverAuth` and `clientAuth`. Thus the EKU
  does not separate a server from a client. The URI SAN does this
  (`identity.go:31-38`).
- Each certificate has a random serial number of 128 bits.
- The four extensions above are critical. Thus a program that does not know an
  extension must reject the certificate.

The CA gives the server the identity `spiffe://fizzled.internal/server`. It
gives each agent the identity
`spiffe://fizzled.internal/client/agent/<agent identifier>`.

This is SPIFFE and not the usual web PKI, because of the location of the
identity. This is the client certificate on the disk:

```
$ openssl x509 -in .secrets/agent-smith.crt -noout -subject -issuer -ext subjectAltName
subject=                                            ← empty. There is no CN.
issuer=CN=fizzled.internal local CA
X509v3 Subject Alternative Name: critical
    URI:spiffe://fizzled.internal/client/agent/smith
```

The certificate has no CN, no DNS SAN, and no IP SAN. The certificate has only
one name: a URI SAN that contains a SPIFFE ID. The server certificate has the
same structure, with `URI:spiffe://fizzled.internal/server`.

This one fact is the reason for the unusual TLS configuration that follows.

## The trust bundle

The trust bundle is the set of root certificates that a process accepts. Here it
is the one file `.secrets/ca.crt`. Both the server and the client read it
(`cmd/fizzled/flags.go:12-19`, `cmd/fizzle/flags.go:12-17`).

The bundle is the most important input. If a person can add a root to it, that
person can make a certificate for any identity. Thus the parser is strict.

The function `loadTrustBundle` (`trustbundle.go:41-53`) reads the file. The
function `parseTrustBundle` (`trustbundle.go:59-121`) reads the content one PEM
block at a time. It does not use `x509.CertPool.AppendCertsFromPEM`. That
function ignores each block that it cannot use, and it reports only if it added
one block or no block. An operator must know about a bad bundle at start-up.

The parser rejects a bundle for these reasons:

| Condition | Error |
| --- | --- |
| The bundle has no certificate | `ErrEmptyTrustBundle` |
| A PEM block is not a certificate | `ErrBundleNotCertificate` |
| A PEM block has RFC-1421 headers | `ErrBundleBlockHasHeaders` |
| There are bytes outside a PEM block | `ErrBundleUnexpectedData` |
| A PEM block is not readable | `ErrBundleBlockDropped` |
| The same certificate is present two times | `ErrBundleDuplicateCertificate` |
| A root has a URI SAN of a different trust domain | `ErrWrongTrustDomain` |

The parser also counts the PEM start markers. It compares this count with the
number of certificates that it read (`trustbundle.go:105-113`). Thus no block
can disappear without an error.

The function `ValidateSigningCertificate` (`x509svid/verifier.go:230-269`) tests
each root. A root must be a CA and must have `keyCertSign`. A root does not need
a URI SAN. If a root has one, that SAN must have no path.

The verifier makes its own certificate pool from these roots
(`verifier.go:45-48`). Thus the pool contains only these roots.

## The SPIFFE identity

A SPIFFE ID is a URI. It has this format:

```
spiffe://<trust domain>/<path>
```

The package `spiffeid` parses it (`spiffeid/id.go:37-64`). The package is
domain-free: it knows the standard, but it does not know this project. The rules
are:

- The ID must start with `spiffe://`.
- The ID is 2048 bytes or less. The trust domain is 255 bytes or less.
- The trust domain matches `^[a-z0-9._-]+$`.
- Each path component matches `^[a-zA-Z0-9._-]+$`.
- A path component cannot be `.` or `..`.
- The parser rejects percent-encoding, a port, userinfo, a query, a fragment,
  and an empty path component.

The package `authn` adds the rules of this project (`identity.go:15-29`):

- The trust domain must be `fizzled.internal` (`authenticator.go:17`).
- The server ID has one path component: `server`.
- The client ID has three path components: `client`, `agent`, and the agent
  identifier.

The agent identifier becomes the `AgentID` (`agentid.go:20-30`). The rules for
an `AgentID` are stricter than the rules for a SPIFFE path component
(`agentid.go:37-62`):

- It is 1 to 64 bytes.
- It matches `^[a-zA-Z0-9_-]+$`. Thus a full stop is not permitted.

## The handshake

The handshake does two different tasks at the same time. Do not confuse them:

1. **The key agreement.** The two sides make a shared secret with ECDHE. The
   session keys come from this secret.
2. **The authentication.** Each side signs the transcript with its private key.
   This signature connects the identity in the certificate to the key
   agreement above.

The certificates do not encrypt the data. They only authenticate the key
agreement. This is the reason for forward secrecy: if a person gets a private
key later, that person still cannot decrypt an old recorded session.

The server starts the client authentication. It sets `ClientAuth`
(`internal/authn/tlsconfig.go:28`). Then the server sends a
`CertificateRequest` message.

This is the TLS 1.3 sequence. The project permits TLS 1.2 and TLS 1.3, but no
version before them (`tlsconfig.go:43-44`):

```
client → ClientHello          versions, cipher suites, ECDHE key share
server → ServerHello          chosen version + suite, ECDHE key share
                              ── the messages below are encrypted ──
server → CertificateRequest   ← the server requests a client certificate
server → Certificate          server.crt
server → CertificateVerify    signature over the transcript, by server-private.key
server → Finished
client → Certificate          agent-smith.crt
client → CertificateVerify    signature over the transcript, by agent-smith-private.key
client → Finished
```

The `Finished` message contains a MAC over the transcript. Thus a person who
changes an earlier message causes a failure of the handshake.

## What the client sends

The client sends two items. The difference between the two items is important.

### 1. The certificate chain

This is the content of the file `agent-smith.crt`. This data is public. It
contains the public key of the agent, the SPIFFE ID, the validity period, and
the signature of the CA. A person who can read the file can copy the file. On a
TLS 1.2 connection, a person who monitors the network can also see the
certificate. The certificate alone is not proof of identity. It is a statement,
and not a credential.

The chain contains one certificate. The command `openssl x509 -req` writes only
the leaf certificate into `agent-smith.crt`. The function `tls.LoadX509KeyPair`
(`identity.go:106`) sends the content of that file. The client does not send the
root certificate. The two sides read the root certificate from the file
`.secrets/ca.crt`.

### 2. A `CertificateVerify` signature

This is an ECDSA-P256-SHA256 signature. The client makes the signature with the
key `agent-smith-private.key`. The client signs a hash of the full handshake
transcript.

This message is the proof of identity. It makes a copy of a certificate of no
use. The transcript contains the two random values and the two ECDHE key shares.
Thus the signature applies to this connection only. If a person copies the
signature and sends it on a new connection, the signature does not agree with
the new transcript. Then the new connection fails.

**The client does not send the private key.** The private key stays in the
client process. The client sends a public certificate and a new proof of
possession. This is the reason why a person can copy a certificate, but cannot
use it. The secret is the private key, and not the certificate.

There is one more property. In TLS 1.3, the client sends the `Certificate`
message after the two sides start encryption. Thus a person who monitors the
network cannot see which agent makes the connection. In TLS 1.2, this message is
not encrypted.

## How the client authenticates the server

The client configuration is different from the usual configuration. The
configuration can look incorrect. This section gives the reason for it.

```go
// internal/authn/tlsconfig.go:8-19
func newClientTLSConfig(identity tls.Certificate, verify func(tls.ConnectionState) error) *tls.Config {
	config := baseTLSConfig(identity, verify)
	config.InsecureSkipVerify = true
	return config
}
```

The related configuration has `RootCAs: nil`, `ServerName: ""` and
`VerifyPeerCertificate: nil` (`tlsconfig.go:61-64`). These settings stop all the
Go verification of the server.

The empty subject is the reason. The Go verification asks this question: is this
certificate valid for the hostname? It compares `ServerName` with the DNS SANs
of the certificate. The server SVID has no DNS SAN. Thus this comparison has no
data, and it rejects each connection. The identity of the server is not
`localhost`. The identity is `spiffe://fizzled.internal/server`.

Thus `InsecureSkipVerify = true` does not mean *no verification*. It means *no
Go verification*. The same function installs a replacement (comment at
`tlsconfig.go:5-7`). Thus you cannot set one without the other. The replacement
is the `VerifyConnection` callback (`tlsconfig.go:51`). This callback calls
`verifyServerPeer` (`authenticator.go:92`). The callback does more checks than
the Go verification.

**Step 1 — verification of the chain** (`x509svid/verifier.go:113-125`). The
package `crypto/x509` verifies the signature, the validity period, and the basic
constraints. Only the parameters are different:

```go
_, err := leaf.Verify(x509.VerifyOptions{
	DNSName:     "",                    // hostname matching skipped, on purpose
	Roots:       v.bundle,              // only .secrets/ca.crt — never system roots
	CurrentTime: clampToValidity(time.Now(), leaf.NotBefore, leaf.NotAfter, v.skew),
	...
})
```

The verifier rejects a pool that is nil (`verifier.go:102-104`). Thus the
verifier does not use the system trust store of the host. The function
`clampToValidity` (`verifier.go:140-149`) applies a clock-skew tolerance of two
minutes. It moves the test time to the edge of the validity period, but not more
than two minutes. Thus a small difference between the two clocks does not cause
a failure.

**Step 2 — the X509-SVID rules** (`verifier.go:182-215`). The leaf certificate
is not a CA. It does not have `keyCertSign` or `cRLSign`. It has
`digitalSignature`. It has one URI SAN only, and this SAN contains a SPIFFE ID
with a path. The verifier applies these rules to the chain that the peer sent.
Thus it rejects a certificate that the peer added but did not use
(`verifier.go:61-66`).

**Step 3 — the issuance policy** (`identity.go:39-58`). The leaf certificate has
the two EKUs. Its public key is ECDSA P-256.

**Step 4 — the identity** (`identity.go:85-96`):

```go
if spiffeID.TrustDomain() != TrustDomain { ... }        // must be fizzled.internal
components := spiffeID.PathComponents()
if len(components) != 1 || components[0] != "server" { ... }
```

Thus the client does not ask if the certificate is valid for a hostname. The
client asks two different questions. Does this chain go to my CA? Does the chain
contain the ID `spiffe://fizzled.internal/server`? The client uses the identity
for the verification, and not the name.

There is one important result. The client does no hostname verification. Thus
the client accepts the server SVID at each address. The trust applies to the
identity, and not to `localhost:8443`. This is correct behavior for the SPIFFE
model. A person who operates a false server at that address must have a
certificate with that SPIFFE ID. The CA does not give this person such a
certificate.

## How the server authenticates the client

The server uses the same code, with two differences (`tlsconfig.go:23-32`):

```go
config.ClientAuth = tls.RequireAnyClientCert
config.SessionTicketsDisabled = true
```

The value is `RequireAnyClientCert`, and not `RequireAndVerifyClientCert`. Also,
`ClientCAs` is nil. Thus Go requires a certificate from the client. If the
client sends no certificate, the handshake fails. But Go does not verify the
certificate. The comment at `authenticator.go:98-101` gives the reason. The Go
verification uses `time.Now()` with no tolerance. Thus it can reject a
certificate that is in the clock-skew period of two minutes. It rejects this
certificate before `verifyClientPeer` reads it.

Thus the `VerifyConnection` callback does all the verification. Steps 1 to 3 are
the same as the steps for the client. Step 4 is different. The function
`clientAgentID` (`identity.go:62-80`) requires the three path components
`client/agent/<id>`. It returns `<id>` — for example `smith` — as the `AgentID`.

The two sides share the code for steps 1 to 3. The functions `clientSVID`
(`authenticator.go:188`) and `serverSVID` (`authenticator.go:207`) both call
`leaf` (`authenticator.go:223`). Thus the standard cannot become different on
the two sides.

Each side also verifies its own certificate at start-up. It uses the same
function as its peer (`authenticator.go:87` and `authenticator.go:118`). If the
server cannot accept a client, that client fails in `client.New`. It does not
fail at the first RPC.

## Session resumption

TLS can resume an earlier session. Then the two sides do not send certificates
again. This is faster, but it can also prevent an identity check.

This project does not permit resumption (`doc.go:29-31`). There are two
controls:

- The server sets `SessionTicketsDisabled = true` (`tlsconfig.go:29`). Thus the
  server gives no ticket to the client.
- The code uses the callback `VerifyConnection` and not `VerifyPeerCertificate`
  (`authenticator.go:147-151`). Go calls `VerifyConnection` for a resumed
  session also. Thus the identity check operates even if a session resumes.

The second control is the important one. It does not depend on the first
control.

## The protection after the handshake

The handshake gives the session keys. The connection then protects each message.

**The cipher suites** (`tlsconfig.go:45-48`). The configuration permits two
suites:

```
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
```

Both use ECDHE for the key agreement and AES-GCM for the data. AES-GCM gives
confidentiality and integrity together. Both suites use ECDSA, because each leaf
certificate has an ECDSA key. A suite with `_RSA_` could never operate with
these certificates. This list applies to TLS 1.2 only. In TLS 1.3, Go selects
the suite, and the configuration cannot change it.

**The TLS version** (`tlsconfig.go:43-44`). The minimum is TLS 1.2 and the
maximum is TLS 1.3. Go selects the highest common version. Thus two current
programs use TLS 1.3.

**Renegotiation** (`tlsconfig.go:49`). The value is `tls.RenegotiateNever`. TLS
1.2 permits a second handshake on the same connection. This project does not
permit it. TLS 1.3 removed this function.

**Keepalive** (`server.go:145-160`). The server sends a ping on a quiet
connection after one minute. It waits 10 seconds for the answer. The server does
not set a maximum age for a connection, because a job can stream output for a
long time.

## From the identity to the authorization

The authentication gives the name of the caller. The authorization decides what
that caller can do. The two steps are separate.

The TLS configuration goes to gRPC through `credentials.NewTLS`. See
`internal/client/client.go:71` and `internal/server/server.go:142`. The server
then does these steps for each RPC (`internal/server/interceptor.go:146-215`):

```go
tlsInfo, isTLS := peerInfo.AuthInfo.(credentials.TLSInfo)   // non-TLS → Unauthenticated
agentID, err := i.authenticator.Authenticate(tlsInfo.State) // re-verifies the chain
```

1. The function `actionFor` (`interceptor.go:273-290`) maps the RPC method to an
   action. The actions are `Start`, `Stop`, `GetStatus`, and `StreamOutput`. An
   unknown method gives an `Internal` error. The server does not serve it.
2. The function `Authenticate` (`authenticator.go:138`) verifies the chain
   again. It does not use the result of the handshake. Thus the result is
   correct for each `tls.Config`.
3. The function `Authorize` (`authz/authorizer.go:92`) reads the role of the
   agent from the file `roles.json`. The role `USER` permits the four actions.
4. The server puts the `AgentID` into the context (`interceptor.go:182`). The
   handler reads it from there.

For a stream, the server resolves the agent one time, when the stream opens
(`interceptor.go:90`). It does not do this for each message. The verification of
a chain is not free.

The error messages are short on purpose. A denied caller gets
`PermissionDenied` and the text `permission denied` (`interceptor.go:177`). A
caller that fails the authentication gets `Unauthenticated` and the text
`unauthenticated` (`interceptor.go:211`). The reason stays in the log of the
server. The caller does not learn it.

## The audit record

The `Authenticator` records the result of each connection
(`authenticator.go:20-22`).

**At start-up** (`authenticator.go:239-248`): the path of the trust bundle, the
number of roots, and the earliest expiry date of a root. That date is the date
before which you must restart the process.

**For an accepted peer** (`authenticator.go:255-266`): the side (`client` or
`server`), the SPIFFE ID, the serial number of the certificate, and the
`AgentID`.

**For a rejected peer** (`authenticator.go:272-286`): the side, the reason, and
the serial number of the certificate that the peer sent. The SPIFFE ID is not a
separate field here, because it is not verified on this path.

**For each authorization decision** (`interceptor.go:219-240`): the `AgentID`,
the action, the decision (`allow` or `deny`), and the job ID if there is one.

The log never contains a private key or a full certificate in PEM format
(`README.md:467-468`). The test `TestHandshakeAudit` asserts that the log does
not contain the text `-----BEGIN` (`authenticator_test.go:1370`).

## The certificate lifecycle

**The read.** A process reads the trust bundle one time, in `NewAuthenticator`.
It reads its own SVID one time, in `ClientConfig` or `ServerConfig`
(`doc.go:33-38`).

**The rotation.** A new certificate has no effect on a process that operates. You
must restart the process. The command `make secrets` issues a new certificate if
the old one expires in less than one day (`makefile:66-79`). It keeps the
private key and changes only the certificate (`README.md:554-558`).

**The validity period.** The CA is valid for 1825 days. A leaf certificate is
valid for a short period, on the order of days (`README.md:495-497`). A short
period is the answer to a leaked key, because this project has no revocation.

**The expiry during a connection.** The server does not disconnect a client when
the certificate of that client expires (`README.md:347-348`). The verification
occurs at the handshake and at each RPC, but a stream that operates continues.

## The limits of this design

Read this section before you use this design in a different project.

- **There is no revocation.** There is no CRL and no OCSP
  (`x509svid/doc.go:19-22`). If a private key leaks, you cannot cancel the
  certificate. It stays valid until it expires. The answer is a short validity
  period.
- **A stolen private key is a stolen identity.** A person with the key file can
  be that agent. The mTLS cannot detect this. Protect the key files. This
  project makes them readable by the owner only (`makefile:106-110`).
- **The trust applies to the identity, not to the address.** See the end of [How
  the client authenticates the
  server](#how-the-client-authenticates-the-server).
- **The CA is one point of failure.** A person with `ca-private.key` can make a
  certificate for each identity. No program at run time reads this file. Only
  the makefile reads it, and only to sign.
- **mTLS does not give authorization.** The file `roles.json` gives it, and that
  file is separate.
- **The verification has a cost.** The server verifies the chain again for each
  RPC (`authenticator.go:126-137`). This is a deliberate exchange: correctness
  for speed.

## Where the code is

| Package | Task |
| --- | --- |
| `internal/authn` | The mTLS policy of this project: the trust domain, the skew, the two identities, the `AgentID` |
| `internal/authn/spiffeid` | The parser for a SPIFFE ID. It is domain-free |
| `internal/authn/x509svid` | The verification of an X509-SVID chain. It is domain-free |
| `internal/authz` | The roles and the actions |
| `internal/server` | The gRPC server and the interceptors |
| `internal/client` | The gRPC client |
| `internal/testpki` | A CA for the tests |
| `makefile` | The PKI for development (`make secrets`) |

The package `authn` is the only place that makes a `tls.Config`
(`tlsconfig.go`). The two domain-free packages contain no knowledge of this
project. Thus you can read the standard and the policy separately.

## Summary

This system has no password, no token, and no bearer credential. The certificate
is the credential. The private key gives the proof, but the client does not send
the key. Each side verifies the chain of its peer against one root. Each side
then compares the SPIFFE ID with the identity that it expects. The server reads
the name of the caller from the URI SAN. The server verifies the chain before
the first gRPC message.

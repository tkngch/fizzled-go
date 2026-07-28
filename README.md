# fizzled-go

A service to run "stochastic countdown" jobs. A countdown starts at a given
count and ticks down at exponentially-distributed intervals, completing when it
reaches zero. The service provides a gRPC API over mTLS.

## Contents

- [Motivation](#motivation)
- [Requirements](#requirements)
- [Design](#design)
  - [CLI client commands](#cli-client-commands)
  - [Server](#server), including the [gRPC API](#grpc-api) and [Job state machine](#job-state-machine)
  - [Worker](#worker), including [output buffering and fan-out](#output-buffering-and-fan-out)
  - [Authentication](#authentication) and [Authorization](#authorization)
  - [Audit and observability](#audit-and-observability)
  - [Secrets](#secrets)

## Motivation

This project is a chance for me to learn about mTLS and SPIFFE, to explore how
mTLS can be used in a system where AI agents interact with services. In
particular, a use-case in mind is where an agent streams from a service via gRPC
API.

## Requirements

### Functional Requirements

- An agent can start a countdown by supplying an initial count.

- An agent can stop a running countdown.

- An agent can query status of countdown. A countdown starts in `RUNNING` status
  and moves to `COMPLETED` when zero is reached, `STOPPED` when an
  agent stops it, or `FAILED` when the countdown exits for other reasons.

- An agent can stream output of countdown. Each tick emits a string containing
  the elapsed time in seconds and the remaining count. The stream replays all
  outputs from the start of the countdown and then follows live outputs. When
  the countdown reaches `COMPLETED`, `STOPPED`, or `FAILED` status, the stream
  delivers the final output before closing, so no output is missed. Server
  shutdown has one bounded exception (see [Server](#server)).

### Non-Functional Requirements

- Transport security: mTLS only. Server requires and verifies client certs. Use
  strong set of cipher suites for TLS and good crypto setup for certificates. No
  authentication mechanism on top of mTLS.

- Authorization: derived from the client certificate identity (URI SAN).
  Owner-only: an agent may act on and see only the countdowns it started.

- No-poll discovery: new output is pushed to subscribers without busy-wait or
  polling.

- Concurrency: many countdowns and many subscribers per countdown.

- API: gRPC. RPCs: Start, Stop, GetStatus, and StreamOutput (server-streaming).

### Out of Scope

- Pause/resume of countdown.

- Agent management.

- Running arbitrary / agent-supplied commands, executables, or shell input.

- Scheduling/queuing of countdown.

- Resource limiting.

- Persistence.

- Auto-rotation of certificates.

## Design

Throughout, a _countdown_ is tracked internally as a _job_, identified by a
_job-ID_; the two terms refer to the same thing.

### CLI client commands

The CLI program is called `fizzle`.

- `fizzle start <count>`: starts the countdown and prints out the countdown's
  id in stdout.

- `fizzle stop <id>`: requests a stop and exits 0 whether or not the countdown was
  still running. A no-op on an already-terminal countdown still exits 0. The
  `Stop` RPC's `true`/`false` result is not surfaced by the CLI. The exit-0
  guarantee applies to a countdown the caller owns; a `NOT_FOUND` (unknown id, or
  one owned by another agent) or any other RPC error exits 1.

- `fizzle status <id>`: prints the status of the countdown
  (`RUNNING`/`COMPLETED`/`STOPPED`/`FAILED`) in stdout and exits 0. The terminal
  state is conveyed in stdout, not in the exit code.

- `fizzle outputs <id>`: streams outputs of the countdown and prints each
  message to stdout verbatim, including the terminal tick, the completion tick
  `{"elapsed": <total>, "remaining": 0}` or an `{"error": ...}` tick.
  Exits 0 when the server closes the stream cleanly, regardless of whether the
  countdown ended COMPLETED, STOPPED, or FAILED. The terminal state is conveyed
  in the streamed messages, not in the exit code.

- Use exit codes 0 for success, 2 for usage/config error, and 1 for everything
  else (e.g., mTLS failure). An invalid `count` (`INVALID_ARGUMENT`) is a usage
  error -> exit 2; `NOT_FOUND` and other operational RPC errors -> exit 1.

- Accept `--server` flag (default: `localhost:8443`) to set the dial address.

- Accept `--cert` flag for the path to the certificate file (required; the client
  must present its own identity, so there is no default).

- Accept `--key` flag for the path to the private key (required).

- Accept `--ca` flag for the path to the trust bundle, with a reasonable
  default. Verify server SVID with this trust bundle.

### Server

- Maintain a registry that maps each job-ID to its job and owner. Ownership is
  derived from the authenticated SPIFFE identity (see
  [Authentication](#authentication)); the job itself owns its status and output
  buffer (see [Worker](#worker)). Register each job-ID's entry atomically as one
  unit under the registry's synchronization boundary, so no lookup ever sees a
  partially-registered job, and support concurrent access (see
  [Start](#grpc-api) and [Job state machine](#job-state-machine)).

- Maintain a per-agent counter used to mint job-IDs (see [Start](#grpc-api)).
  Increment it atomically so concurrent Start calls from the same agent never
  collide on a job-ID, and create the counter on an agent's first Start
  race-free, so two concurrent first calls from a new agent do not each
  initialize it.

- On server shutdown, (1) stop accepting new RPCs; (2) cancel all workers (see
  [Worker](#worker)), each of which appends its `{"error": "stopped"}` sentinel;
  (3) let in-flight `StreamOutput` subscribers drain to that sentinel, bounded
  by a short grace deadline; (4) close any streams still open past the deadline.
  A subscriber that reaches its sentinel has already closed itself; only when
  the grace deadline elapses does a client observe a transport-level cancel
  instead of the sentinel. That bounded case is the one place shutdown may
  deliver less than the normal-path guarantee, that every subscriber receives
  the terminal sentinel before its stream closes.

- Accept `--server` flag (default: `localhost:8443`) to set the listen address.

- Accept `--cert` flag for the path to the certificate, with a reasonable default.

- Accept `--key` flag for the path to the private key, with a reasonable default.

- Accept `--ca` flag for the path to the trust bundle used to verify the client
  certificate, with a reasonable default. Verify client SVID with this trust bundle.

- Accept `--roles` flag for the path to the agent-to-role mapping (see
  [Authorization](#authorization)), with a reasonable default. Its format is an
  implementation detail.

#### gRPC API

- `Start(count)`: starts a countdown, and returns a job-ID.

  - A job-ID is a string, consisting of the agent's identifier with an
    auto-incremented integer. This integer auto-increment is scoped per agent,
    not global. The exact format joining the agent identifier and the integer is
    an implementation detail. A job-ID is ephemeral and will be reused when the
    server restarts. Therefore, an ID minted before a restart may afterward
    refer to a different countdown (or to no countdown yet), and clients must
    not treat a job-ID as stable across restarts.

  - Before returning the job-ID, atomically register the job: record its owner,
    set its status to RUNNING, and create its output buffer. The job is
    therefore queryable, streamable, and stoppable the instant the ID is
    returned; the worker task then emits the initial tick `{"elapsed": 0.0,
    "remaining": <count>}` and every tick after it.

- `Stop(id)`: requests cancellation of the countdown's worker (see
  [Worker](#worker)); the worker performs the actual `RUNNING` -> `STOPPED`
  transition. If a countdown is not RUNNING, this is a no-op. Returns `true` if
  and only if the cancellation drove `RUNNING` -> `STOPPED`, and `false`
  otherwise. So `false` is returned, for example, when the countdown had already
  reached a terminal state (e.g., natural completion won the race). The `Stop`
  RPC does not write status directly.

- `GetStatus(id)`: returns status (RUNNING/COMPLETED/STOPPED/FAILED). The
  server keeps the mapping of job-ID to the status until it shuts down.

- `StreamOutput(id)`: replays the outputs from the start of the countdown and
  then follows live outputs. The server sends a transport-level keepalive ping to
  the client every minute, with a 10-second timeout.

  - The stream closes as soon as the subscriber has delivered the end-of-stream
    sentinel to the client: the completion tick with `remaining == 0` or with an
    `error` field. The worker appends exactly one such sentinel as the final
    buffer entry (see [Worker](#worker)). The subscriber decides to close purely
    from what it has sent and never consults the status map.

  - A client that disconnects and reconnects gets a fresh replay from the start;
    there is no resume-from-cursor across connections.

- Configure the server's keepalive enforcement policy, the minimum interval it
  tolerates between client-initiated pings, to 10 minutes. This is the opposite
  direction from the per-minute keepalive above (which the server sends to the
  client), so the two do not conflict.

##### Error mapping

`PERMISSION_DENIED` (no role) is checked first, before any argument validation
or ownership check, so an unauthorized agent learns nothing about arguments or
job existence. `INVALID_ARGUMENT` applies only to `Start`'s `count` and
`NOT_FOUND` only to the id-bearing RPCs, so those two never overlap.

- `PERMISSION_DENIED`: the authenticated agent does not have any role assigned
  and thus is not authorized.

- `INVALID_ARGUMENT`: when `count` argument to start a countdown is negative or
  zero or larger than 100.

- `NOT_FOUND`: when a job-ID is not found among the countdowns that the agent
  owns. This error is returned when an agent tries to access a countdown that
  another agent owns.

#### Job state machine

- States: `RUNNING` (initial) and the terminal states `COMPLETED`, `STOPPED`,
  and `FAILED`. Terminal states never transition further.

- The worker task is the single terminal authority. It performs the one terminal
  compare-and-set from `RUNNING` on its single exit path; the write is atomic
  and only `RUNNING` can be updated, so concurrent triggers resolve to exactly
  one terminal state.

  - `RUNNING` -> `COMPLETED`: when the countdown reaches zero.

  - `RUNNING` -> `STOPPED`: when the worker is cancelled, by a client `Stop` or
    on server shutdown.

  - `RUNNING` -> `FAILED`: when the task exits with an unexpected error.

- Invariant: the worker appends exactly one terminal sentinel to the output
  buffer, and it always matches the final status (see [Worker](#worker)). A
  subscriber can therefore never observe, say, a `remaining == 0` completion
  tick on a job whose status is `STOPPED`.

- `Stop` and shutdown do not write status themselves. They cancel the worker in
  a best-effort basis, because the task may already be exiting via natural
  completion. A `Stop` racing natural completion resolves by which exit path the
  worker takes: already at zero -> `COMPLETED` (`Stop` returns `false`); still
  running -> cancellation drives `STOPPED` (`Stop` returns `true`).

- Because the job is registered in `RUNNING` before `Start` returns, no RPC ever
  observes a job that exists but has no status.

### Worker

The worker is an in-process task per countdown. This worker executes a
stochastic countdown and emits a string containing the elapsed time in seconds
and the remaining count in JSON on every tick: for example, `{"elapsed": 12.3,
"remaining": 3}`.

- On start request, start the countdown in a new task and emit the first
  tick `{"elapsed": 0.0, "remaining": <count>}`, where `<count>` is the input
  argument. The required parameters for stochasticity (i.e., rate parameter for
  exponential distribution) are fixed and hardcoded. Their exact values are
  arbitrarily chosen.

- On stop request, cancel the task. This is best-effort cancellation,
  because the task naturally exits when the count reaches zero.

- Capture the output from the task into the job's own in-memory output buffer
  (see [Output buffering and fan-out](#output-buffering-and-fan-out) below).

- When the worker task exits without an error, compare-and-set the status from
  `RUNNING` to `COMPLETED` (see [Job state machine](#job-state-machine)) and, as
  part of that transition, append `{"elapsed": <total>, "remaining": 0}` where
  `<total>` is the elapsed time since the countdown start in seconds.

- When the worker task exits with an error, compare-and-set the status from
  `RUNNING` to `FAILED` and, as part of that transition, append
  `{"error": <error message>}`.

- When the worker task is cancelled, compare-and-set the status from `RUNNING`
  to `STOPPED` and, as part of that transition, append `{"error": "stopped"}`.

- The compare-and-set and its sentinel append are one unit, so the buffer's
  single terminal sentinel always matches the status (see
  [Job state machine](#job-state-machine)).

- The tick with `remaining == 0` or an `error` field is the last entry ever
  appended to its buffer. Subscribers close on delivering it (see [StreamOutput](#grpc-api)).

- Cancel all worker tasks when the server exits.

#### Output buffering and fan-out

Output buffering and fan-out are per-job responsibilities of the worker: each
job owns its own output buffer, and any number of subscribers can read it
concurrently. A _subscriber_ is a single in-flight `StreamOutput` stream (see
[StreamOutput](#grpc-api)). There is no separate shared component; the server's
registry (see [Server](#server)) is what maps a job-ID to the job a subscriber
reads from.

- Store the job's outputs in an unbounded, append-only buffer owned by the job.
  The buffer and the job's status share a single synchronization boundary, so a
  terminal transition and its sentinel append happen as one unit (see [Job state
  machine](#job-state-machine)).

- When a client starts streaming, the subscriber replays every buffer entry from
  the start and then follows live output. Each subscriber tracks its own read
  position; the job keeps no per-subscriber state, so a client that disconnects
  and reconnects gets a fresh replay from the start (see
  [StreamOutput](#grpc-api)).

- When a new output arrives, append it to the buffer and then signal every
  subscriber. Each signalled subscriber reads forward from its own position,
  pushes the new entries to its client, and suspends again once it reaches the
  current end of the buffer. Serialize the append-then-signal and each
  subscriber's check-position-then-suspend so the two cannot interleave;
  otherwise an output arriving between a subscriber observing the end of the
  buffer and suspending would be lost.

- Wake a suspended subscriber on either of two events: a new-output signal, or
  the client disconnecting. On disconnect, stop the subscriber so it stops
  reading the buffer; the job keeps no per-subscriber state to clean up. Server
  shutdown needs no separate wakeup path, because the worker appends the
  `{"error": "stopped"}` sentinel, which wakes suspended subscribers (see
  [Worker](#worker) and the shutdown sequence under [Server](#server)).

- Do not delete the buffer after the worker task exits and all subscribers stop
  reading. Memory usage will grow unbounded, but it is an acceptable defect for
  this project.

- Do not disconnect a subscriber when the client certificate expires. It is an
  acceptable risk for this project.

### Authentication

- Use mutual TLS authentication (mTLS) with subject alternative names (SANs).

- Use an X.509-SVID certificate per agent, which encodes a SPIFFE ID in the SAN field.

  - Use the server URI: `spiffe://fizzled.internal/server`

  - Use the client URI: `spiffe://fizzled.internal/client/agent/<agent identifier>`

  - Given that we do not have any authentication on top of mTLS (e.g., OIDC/JWT
    layer), encode agent identifier in the path.

  - Verify X.509-SVID certificate using the trust bundle. Assert that the
    certificate has only one URI SAN, and then extract SPIFFE ID. Reject a
    certificate without a URI SAN or with two or more URI SANs.

  - Client-side checks (on the server certificate):

    - that the scheme is spiffe;

    - that the trust domain is `fizzled.internal`;

    - that `serverAuth` is in the EKU; and

    - that the server URI has exactly one path component, `server` (c.f.,
      [X.509-SVID path validation](https://spiffe.io/docs/latest/spiffe-specs/x509-svid/#51-path-validation)).

  - Server-side checks (on the client certificate):

    - that the scheme is spiffe;

    - that the trust domain is `fizzled.internal`;

    - that `clientAuth` is in the EKU,

    - that the client URI has exactly three path components, `client`, `agent`
      and the agent identifier. Reject an agent identifier that is empty or that
      contains `/`, `.`, or `..`. Note that the exactly-three-components check
      already rejects extra `/` (c.f., [X.509-SVID path validation](https://spiffe.io/docs/latest/spiffe-specs/x509-svid/#51-path-validation)).

  - Implement a custom verifier as necessary.

  - Assert that the `cA` field in the basic constraints extension is set to
    `false` ([X.509-SVID leaf validation](https://spiffe.io/docs/latest/spiffe-specs/x509-svid/#52-leaf-validation)).

  - Assert that `keyCertSign` and `cRLSign` are not set in the key usage
    extension ([X.509-SVID leaf validation](https://spiffe.io/docs/latest/spiffe-specs/x509-svid/#52-leaf-validation)).

  - Assert that the leaf's public key is ECDSA on the P-256 curve, matching the
    issuance policy in Secrets.

  - Disable TLS hostname verification, but retain other TLS verifications (e.g.,
    chain, signature, and expiry validations).

  - Apply a small clock-skew tolerance (a few minutes, as a policy value) when
    checking `notBefore` / `notAfter`, so minor clock differences between agent
    and server do not spuriously reject otherwise-valid certificates.

  - Extract the agent identifier from SPIFFE ID. The authorization (described
    below) is based on this agent identifier.

- Support TLS 1.2 and 1.3, and reject earlier versions of TLS. Follow the
  recommendations in [IETF RFC9325](https://datatracker.ietf.org/doc/html/rfc9325).

  - Prefer TLS 1.3 over TLS 1.2.

  - Disable TLS 1.2 renegotiation (TLS 1.3 does not renegotiate).

  - For TLS 1.2, use the following cipher suites (ECDSA-only, matching the ECDSA
    P-256 issuance policy in [Secrets](#secrets), because an `_RSA_` suite could
    never be negotiated with ECDSA leaf certificates):
    `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` and
    `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`.

  - For TLS 1.3, support the following cipher suites, if the implementation
    allows: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, and
    `TLS_CHACHA20_POLY1305_SHA256`.

### Authorization

- Maintain the pre-configured mapping from an agent identifier to a role.

  - The mapping is loaded at startup from a server-side configuration file, given
    by the `--roles` flag (see [Server](#server)); its format is an implementation
    detail. Agents `smith` and `jones`, whose certificates are issued under
    [Secrets](#secrets), are seeded with the USER role.

  - If the mapping is absent or empty at startup, the server fails fast rather
    than starting in a silent deny-all state, so a misconfiguration is loud.

- One role: USER.

- Allow an agent with USER role to start a countdown.

- Allow an agent with USER role to stop and query countdowns that the agent
  started.

- Allow an agent with USER role to stream outputs of a countdown that the agent
  started.

### Audit and observability

- Log security-relevant events for learning and inspection (this is not a
  compliance audit trail):

  - Authentication outcome per connection: the extracted SPIFFE ID, and
    accept/reject with the reason on rejection.

  - Authorization decisions: the agent identifier, the action (Start / Stop /
    GetStatus / StreamOutput), the target job-ID, and allow/deny.

  - Job lifecycle transitions: RUNNING -> COMPLETED / STOPPED / FAILED, with the
    job-ID and owning agent.

- Never log secrets: no private keys and no full certificate PEM. Log at most the
  SPIFFE ID and/or the certificate serial number.

### Secrets

- Create one self-signed root CA for `fizzled.internal`, to sign the server
  and agent certificates.

  - Use 256-bit ECDSA.

  - Mark the basic constraints extension as critical, set `cA` field to `true`
    and set `pathLenConstraint` to zero.

  - Use `spiffe://fizzled.internal` as URI SAN.

  - Set a validity period (`notBefore` / `notAfter`) as a policy value: for
    example a few years. It should be long enough to outlive the leaf
    certificates it signs.

- Issue SVID from the CA. Note that, in this project, it is acceptable that a
  leaked certificate is valid until expiry.

  - Use 256-bit ECDSA.

  - Set the basic constraints extension with `cA` set to `false` (a non-CA
    leaf), matching the leaf validation performed in
    [Authentication](#authentication).

  - Set a validity period (`notBefore` / `notAfter`) as a policy value: for
    example on the order of days. It should be shorter than the CA. This bounds
    the exposure of a leaked leaf, since revocation is out of scope.

  - Mark the following extensions as critical: the URI SAN, the key usage, and
    the extended key usage (EKU), as the EKU is recommended
    [here](https://spiffe.io/docs/latest/spiffe-specs/x509-svid/#44-extended-key-usage).

  - Set `digitalSignature`, `serverAuth`, and `clientAuth`. Every leaf therefore
    carries both EKUs, so the server/client role separation does not rely on the
    EKU. The separation is enforced by the URI-SAN path checks in
    [Authentication](#authentication).

  - Do not set `keyEncipherment`, `keyAgreement`, `keyCertSign`, or `cRLSign`.

- Store the certificates under `.secret` directory.

  - `.secret/ca.crt`: the root certificate.

  - `.secret/ca-private.key`: the root private key.

  - `.secret/server.crt`: the server certificate.

  - `.secret/server-private.key`: the server private key.

  - `.secret/agent-smith.crt`: the certificate for agent Smith.

  - `.secret/agent-smith-private.key`: the private key for agent Smith.

  - `.secret/agent-jones.crt`: the certificate for agent Jones.

  - `.secret/agent-jones-private.key`: the private key for agent Jones.

  - Do not commit `.secret` to git.

# Shared PostgreSQL transport foundation

Issue #495 remains incomplete. `internal/sharedpg` builds native Go connection
configurations and owns shared connections. The application now connects protected
invitation enrollment/recovery, admission, authenticated catalogs and supported
protocol flows. See the [roadmap](vault-roadmap.md) for the current application
boundary; setup/deployment and administration are still incomplete.

The [deployment migrations](vault-shared-postgresql-deployment.md) provide
provisioning-only roles and identity tables, followed by audited session admission,
with real PostgreSQL regression tests. The remaining business APIs are incomplete.

The transport pins pgx v5.12.0 and requires SCRAM-SHA-256. TLS has three explicit
modes: off, encrypted without certificate identity verification, and verified
against an in-memory CA bundle with hostname verification. Standard and higher
profiles require verified TLS. Every TLS connection requires channel binding;
trusted proxy exceptions and device client certificates are not implemented yet.
These checks enforce the transport subset of the profile, not full Hardened or
Paranoid compliance.

All configured fallback hosts receive the same policy, with their own TLS server
name. There is no implicit plaintext fallback. Connections target a read-write
server, bound incoming protocol messages to 16 MiB, and use a ten-second connection
timeout. `Connect` additionally imposes a thirty-second overall context deadline
across DNS, host attempts, TLS, authentication, and read-write validation, respecting
any earlier caller deadline. `Session` owns one query connection and optionally
one notification connection, with no implicit reconnect or retained login secret.
It opens at most once; its package-private leases serialize use of each connection.
Both connections can be leased independently.

`Session.Close` first cancels active and queued leases, then waits for exclusive
ownership and the driver's `CleanupDone` acknowledgement. `IsClosed` alone is
insufficient because pgx can still be closing resources asynchronously. Close is
bounded to five seconds (or the earlier caller deadline). On timeout or uncertain
cleanup, the connection remains attached to the owner for a later retry. A partial
open attempts bounded cleanup and likewise preserves any uncertain connection.
Callers must retain the owner and call Close even when Open fails. The native
admission controller and application lock lifecycle own this cleanup. Typed
business APIs and change fetching are connected through the authenticated shared
runtime; additional business/admin flows remain incomplete.

The native runtime publishes the successfully opened transport mode only after
admission and account unlock. Main validates the mode alongside current native
security/identity, then adds it to the public admission projection. Unknown modes
and non-Verified modes at Standard+ refuse activation. The renderer never supplies
transport authority. Off and encrypted/unverified modes display a permanent notice
while the shared workspace is admitted; catalog refresh cannot overwrite it.

`AuthenticateSession` is the controller's typed admission API. It performs the
current-credential proof and audited admission in one short transaction and owns
a native-memory session capability with profile-aware page locking. The earlier `StartSession` method remains
for schema-v2 compatibility tests; it is not an authentication fallback and
schema-v4 rejects its old three-argument SQL call. Both decode the same admission
result. Admission binds API version, bounded app
version and `ui`/`mcp` source as parameters, and compares returned workspace/user/
device UUIDs against the caller's authenticated expected identities. It requires
one complete result, canonical UUIDs/integers, valid API bounds, a positive epoch,
a nonnegative change sequence, and a nonempty profile of at most 64 KiB. Explicit
SQL hex encoding avoids dependence on server `bytea_output` settings. Temporary
result buffers are cleared; decoded profile bytes belong to the caller.

The result is deliberately named `UnverifiedAdmission`: structural validation and
transport authentication do not establish profile signature trust, admin authority,
or rollback protection. The native controller must verify these before enabling
workspace operations. It must not treat this result as renderer-ready policy.
There is no automatic retry of the audited request. Malformed or mismatched
responses invalidate the owner. SQLSTATE `WH001` (unavailable user/device) and
`WH007` (missing or stale credential proof/capability) also
invalidates the owner and cancels its operations; the caller must still call Close
to confirm both connections have stopped. `WH002` through `WH006` map to fixed
provisioning, required TLS, API compatibility, audit and isolation errors. Raw
server messages, hints and details never accompany those errors.

`VerifyAdmissionPolicy` authenticates the signed profile using the existing vault
Ed25519 verifier. The pinned workspace, signer identity/key version, public key and
minimum sequence are supplied in `PolicyTrust`; none is learned from the response.
Canonical signed-policy decoding rejects duplicate, unknown, omitted or
case-folded fields and bounds the document to 64 KiB. Signature verification
precedes the sequence check. An authenticated older sequence produces a distinct
rollback error; modified documents produce an authentication error. Unsigned API
bounds must agree with the signed bounds and support the requested API.

This returns only an authenticated `vault.Policy`. It does not authenticate the
server's admin flag, epoch or change sequence, enforce the effective runtime
profile, persist a higher sequence floor, or activate the workspace. Native
[encrypted trust-state persistence](vault-shared-trust-state.md) now exists, while
protected enrollment and controller integration remain pending. The future
controller must persist the accepted sequence securely before using the profile,
enforce OS/user/transport requirements, and close the owner on failed admission.
The real PostgreSQL suite now exercises retrieval and verification of a signed
profile, rejection of an unsigned profile, and rejection against a newer trusted
sequence floor in both TLS and plaintext transport fixtures. The plaintext case
tests cryptographic verification only; it does not authorize Standard-profile use
over plaintext.

`Session.Open` now takes authenticated deployment metadata in `ChangePolicy`.
Above 300 concurrent devices or with a transaction-mode pooler it opens only the
query connection, selecting a 30-second polling interval. Other deployments open
the second notification connection. This implements selection and connection count,
not the polling loop. All clients still need an authoritative
`get_changes_since` call after unlock/reconnect, regardless of notification hints.

`SubscribeChanges` idempotently issues `LISTEN wormhole_changes` only on the
dedicated connection, with a 30-second bound and a validated empty LISTEN result.
Callers must subscribe first, then fetch authoritative changes, then wait; this
covers hints that arrive during subscription setup. `NextChangeHint` accepts only
canonical, nonzero UUID payloads from that channel. Other channels and invalid
payloads are discarded, along with benign notices/status messages, up to 64
ignored messages per call. Excess noise returns a fixed error; unexpected protocol
messages invalidate the session. No arbitrary payload or server diagnostic is
returned. A hint never authorizes access or updates local records by itself.

Notification waits honor caller cancellation and workspace lifetime cancellation.
An ordinary wait timeout leaves the connection usable; it does not idle-close or
reconnect the session. Explicit owner Close cancels an active wait and then confirms
the teardown of both connections. Scheduling refreshes, handling noise with bounded
backoff, and integrating the stream with authenticated change retrieval remain work
for the workspace controller.

`Session.Query` is a native-only, parameterized transport primitive for the future
typed business API. Arbitrary SQL must never be exposed through IPC. It leases the
query connection exclusively and bounds the full operation (including lease wait)
to 30 seconds. Limits are 32 KiB of SQL, 64 parameters totaling 1 MiB, 1,024 result
rows, 64 columns, and 8 MiB of result values; the 16 MiB protocol-message limit also
applies. Results are independent native byte copies and preserve SQL NULL. On
failure, accumulated copies are cleared and no partial result is returned. Invalid
or oversized result streams close the connection immediately and invalidate the
session instead of draining arbitrary additional rows. Other server errors use
fixed messages, including SQLSTATE 55P03 for another change in progress.

Read-write validation streams exactly one row containing `off`; missing, null,
extra, or failing results close the connection. This replaces the driver's
validator, whose result indexing assumes a well-formed response and whose
`ReadAll` call accumulates server results. The protocol message-size limit remains
in force during this validation.

Inputs are typed metadata, never arbitrary DSNs. Names, hosts, ports, endpoint
count, and CA bytes are bounded. The internal parser uses a constant password
placeholder to suppress pgpass lookup; the returned password is empty. Ambient
service configuration is rejected and ambient CA, client-key, connection, protocol,
authentication, startup-option, and timezone choices cannot enter the resulting
configuration. TLS-off alone is insufficient to suppress pgx CA file loading, so
the parser's root-certificate setting is explicitly emptied as well.
Startup explicitly requests `client_encoding=UTF8`, so text parameters do not
silently inherit a different database encoding. Authenticated protocol fixtures
check this request on the wire.

The native caller must authenticate the profile and trust bundle before connecting,
then supply the derived device password in Go. `Connect` borrows a bounded secret
buffer, clears its configuration password reference after the attempt, and returns
fixed errors without wrapping server-controlled messages. PostgreSQL code `53300`
produces a specific workspace-server connection-limit error even when another fallback host
failed for a different reason. Authentication SQLSTATEs likewise produce a fixed
authentication error. Other failures remain generic; canceled or expired contexts
retain their standard error values. Callers must not serialize configurations or
surface raw errors from subsequent queries. Password strings in pgx are not
claimed to be zeroizable. Signed trust bundles, provisioning, device enrollment,
remaining role permissions and audited SQL APIs, key distribution, application
connection ownership, password changes, later migrations, and application
integration remain future work.

Tests exercise the actual pgx protocol against local simulated servers rejecting
cleartext-password and MD5 requests, premature AuthenticationOk, missing SCRAM
server-final messages, and TLS refusal. Policy tests cover each mode/profile,
fallback configuration, invalid input, and hostile PostgreSQL environment options.
Connection tests also verify deadline inheritance, secret-buffer ownership,
sanitization of aggregated host failures, real protocol `53300` rejection, and
socket closure when an unresponsive server exceeds the caller deadline.
An authenticated fixture completes and verifies both SCRAM proofs, accepts a
valid writable server, and rejects malformed or failing post-authentication
validation responses.
Owner tests cover partial opens, concurrent lock/open, active and queued operation
cancellation, idempotent lease release, uncertain asynchronous cleanup, retries,
and two authenticated TCP connections with explicit protocol termination.
Query tests use authenticated extended-protocol exchanges to verify parameter
binding, copied rows, null/empty values, oversized and malformed results, late
errors, and SQLSTATE mapping. Cancellation tests include a real PostgreSQL
CancelRequest exchange and confirmed cleanup. Policy tests pin the 300/301-device
boundary and transaction-pooler behavior.
Notification tests use two authenticated connections and validate fixed LISTEN
setup, idempotency, malformed subscription responses, untrusted hint filtering,
noise bounds, timeout followed by successful reuse, and lock during an active wait.

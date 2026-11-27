# Native session credential proof

Changing a PostgreSQL role password does not close its existing connections.
Checking an account epoch only during the first application admission also leaves
an old, previously unopened application session able to request admission later.
The application needs evidence of the current credential at admission time.

`sharedpg.ProveSession` and `VerifySessionProof` implement the native proof
construction and reference verification. Deployment migration 0004 adds SQL
challenge verification and admission using an explicit client-held capability.
The native admission controller uses this exchange. Account credential provisioning,
password changes and the user-facing shared-workspace flow remain incomplete.

The calculation follows the ClientProof and ServerSignature mechanics of
[RFC 5802](https://www.rfc-editor.org/rfc/rfc5802.html), using SHA-256 as in
[RFC 7677](https://www.rfc-editor.org/rfc/rfc7677.html). A test independently checks
the published RFC 7677 proof and server signature. The application transcript is
domain-separated and runs over the existing authenticated PostgreSQL transport;
it does not replace the transport's SCRAM negotiation or TLS channel binding.

The client supplies a fresh 32-byte nonce and SHA-256 of an independent random
32-byte session capability. The server supplies another 32-byte
nonce, the verifier's public salt and iteration count, and a binding containing
workspace, user, device, account epoch, backend PID, expiry and capability hash. The native client
must independently check the expected binding and its own nonce. It must not
blindly copy an untrusted response into both expected and actual arguments.
Expiry is a positive Unix timestamp in seconds; freshness enforcement is a
separate responsibility of admission state.

The server nonce in the SCRAM transcript is unpadded base64url of SHA-256 over:

```text
"wormhole/v1/session-proof"
|| workspace UUID (16 bytes)
|| user UUID (16 bytes)
|| device UUID (16 bytes)
|| epoch (8-byte big-endian)
|| backend PID (4-byte big-endian)
|| expiry (8-byte big-endian)
|| server random nonce (32 bytes)
|| SHA-256 of client session capability (32 bytes)
```

The client nonce is also unpadded base64url. Their concatenation forms the combined
nonce. The transcript uses the canonical device UUID as the SCRAM username, the
standard padded-base64 salt, canonical decimal iteration count, and `c=biws`.
The latter is part of this application transcript, not a claim that it performs
transport channel binding. Costs are bounded to 4096–1000000 and salts to 16–64
bytes before PBKDF2 runs. Login material must be the same 32-byte HKDF output used
to generate the account's SCRAM verifier; it is encoded by `EncodeLoginSecret`.

The verifier authenticates the proof against the current StoredKey and returns a
ServerSignature only on success. The client verifies that signature in constant
time. Proof and expected-signature buffers belong to the caller and must be
wiped; the expected signature is excluded from JSON. Temporary key buffers are
wiped, without claiming complete erasure of Go cryptographic internals.

Migration 0004 stores private account SCRAM components and an account epoch, one
outstanding challenge per device, and one admitted capability hash per device.
`session_challenge` validates identity, readiness and TLS policy, creates a nonce
from two cryptographically random UUIDs, and expires it after at most 30 seconds.
Creating a challenge does not invalidate an already admitted capability.

`session_prove` checks the current epoch, expiry, PID and backend start time, then
verifies the native transcript using PostgreSQL's built-in SHA-256. Its HMAC helper
accepts only a 32-byte key and a bounded message. It examines every comparison byte
without claiming constant-time PL/pgSQL execution. Successful proof consumption
and admission replacement are atomic; rolling back restores both prior records.
An identical consumed proof fails after commit. Failed proof attempts retain the
unconsumed challenge until replacement or expiry.

The capability hash is bound into the proof transcript, so substituting it makes
verification fail. The raw capability is not sent during this exchange and is
never stored in the database. Native orchestration keeps it in protected
memory and wipes it on lock/close. It must not reach the renderer, logs or process
arguments. Subsequent API calls pass it as a bound parameter; the server checks its
hash, the current account epoch and the authenticated device role. SQL logging of
parameters must remain disabled, as required for other credential-bearing APIs.

`require_device(capability)` checks an **audited** admission and current epoch.
Proof verification alone permits only `session_start(api, version, source,
capability)`. That function records the session and login audit and activates the
capability in the same transaction. An audit failure leaves no usable application
session. Replacing a capability with a new proof requires audited admission again.
User, device, account and admission locks are retained until transaction end;
concurrent changes use NOWAIT. Disabled accounts, revoked devices and NOLOGIN
device roles are refused even on already-open connections. The old no-argument
guard is replaced in place with a refusal so cached API plans cannot continue
using its old identity-only implementation. The old three-argument session-start
API also fails closed. `WH007` maps to
a fixed authentication error in the native transport and invalidates its owner,
including any partial results. Private tables and helper functions are not granted
to workspace users or administrators. Deployment migrations coordinate
through the same workspace advisory transaction lock, in addition to identity,
version and metadata-row checks.

Continuing authorization deliberately does not depend on backend PID or backend
start time: transaction poolers reuse those between logical clients. A valid
capability can be used on another backend for the same authenticated device;
another client cannot inherit access by receiving the previously used backend.
The initial challenge/proof exchange still needs one backend and must run inside
one short transaction when pooling. Do not retain that transaction or its locks
for the workspace lifetime. Real pooler interoperability tests are still required
before exposing this flow in the app.

`Session.AuthenticateSession` now owns that short transaction and keeps one query
slot lease through BEGIN, challenge, proof verification, audited admission and
COMMIT. It checks every response, independently binds configured identities and its
own nonce/capability commitment, and verifies the server signature before sending
the raw capability. SQL supplies its current backend PID in the same response;
the client does not confuse a proxy's BackendKeyData PID with the actual backend.
The capability is generated directly in a native allocation and retained only
after success. Page locking is mandatory at Hardened/Paranoid; Default/Standard
may continue with a native memory-lock warning. The controller combines that
warning with the trust-root allocation status for the future shared-workspace UI.
Parameter encodings and proof buffers are wiped after use.
Signed profile validation still belongs to the admission controller; a successful
SQL exchange alone does not activate the workspace UI.

There is no retry or fallback to the old API. Failure, malformed data, cancellation
or an uncertain COMMIT invalidates the owner and closes the connection, rolling
back any uncommitted transaction. Close wipes/releases the capability and retains
an allocation only if native release needs retry. A concurrent Close cancels the
active query before waiting for its lease. The controller now accepts exactly
32 bytes of derived login material, encodes the transport credential for Open,
and supplies the same material to AuthenticateSession. It does not retain it.

Real PostgreSQL tests cover interoperability, long salt encoding, wrong proofs,
cross-connection use, challenge replacement, expiry, backend lifetime mismatch,
epoch changes, old connections attempting re-admission, revocation, transaction
rollback, audit failure, migration rollback, cached API plans and lock contention.
Logical-client backend reassignment is modeled with two real PostgreSQL connections:
the correct capability works across backends, while a different capability and the
hash commitment itself fail even on the previously used backend. This is not a test
against an actual pooler. SQL coverage
is exercised through integration tests; the project has no numeric PL/pgSQL
coverage instrumentation. The modified Go functions are measured separately.

The native reference verifier deliberately has no clock or database state:
replaying an identical valid challenge still verifies mathematically. The SQL
implementation supplies state and capability checks, but actual pooler integration, provisioning of account
credentials, and native/UI password-change orchestration are still incomplete.
The [atomic SQL password-change transaction](vault-shared-password-change.md) is
implemented in migration 0005.

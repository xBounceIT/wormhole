# Atomic shared password change

Migration `0005_password_change.sql` adds private user-key wrapper storage and
`wormhole_api_v1.change_password`. It is not yet a complete user-facing password
change: UI orchestration and the protected enrollment lifecycle remain to be connected.
Native controller verification and local trust-root staging/promotion are now
connected as described below. Encrypted capsule retrieval is
available through the [account-key API](vault-shared-account-keys.md).

`user_key_wraps` retains the encryption/signing key references, wrapping revision,
KDF preset and ASK requirement. It stores the v1 AES-256-GCM capsule as a 12-byte
nonce and exactly 81 ciphertext bytes. The key references are foreign keys into
the key graph. Users and workspace administrators have no direct table access.
Enrollment must create these records; migration does not invent account credentials
or automatically mark a workspace ready.

The API takes the native session capability, expected wrapping revision, new SCRAM
verifier, new nonce/ciphertext and audit source. It requires the existing audited
session and enabled account/device. It locks the user, all of its devices, account
authentication state and wrapper, using NOWAIT and deterministic device ordering.
It refuses stale/exhausted revisions and missing or mismatched active key ownership.

The verifier parser independently enforces the same bounded canonical format as
the Go implementation: SCRAM-SHA-256, at most 256 bytes, 4096–1000000 iterations,
16–64 salt bytes, two 32-byte keys, exact standard-base64 round trips and canonical
decimal cost. A raw password or another hash format is rejected before role changes.

The transaction replaces every existing device-role verifier belonging to the
caller, updates the private SCRAM components and wrapping capsule, advances the
account epoch/wrapping revision, invalidates all of the user's challenges and
admissions, and records a password-change audit event. The same private key pair,
key references, KDF preset and ASK requirement are preserved. The client must use
the existing ASK when deriving the new account master; the server cannot verify
the cryptographic contents of the encrypted capsule.

Role identifiers come only from private device metadata and are identifier-quoted.
Verifiers are literal-quoted only after strict validation. The owner requires
CREATEROLE and ADMIN OPTION for each device role; PostgreSQL automatically grants
the latter when a non-superuser CREATEROLE owner creates a role.
See [PostgreSQL 16 role attributes](https://www.postgresql.org/docs/16/role-attributes.html)
and [ALTER ROLE permissions](https://www.postgresql.org/docs/16/sql-alterrole.html).
Privileged roles are refused. LOGIN, role expiry and other privileges are never
changed, so password replacement cannot reactivate a revoked device. A pending
device without a PostgreSQL role has nothing to update; a missing role for an
active/revoked device fails the transaction. Enrollment must lock the same user
and consume current authentication metadata before creating a new device role.

Any role or audit failure rolls back role passwords, wrapper, epoch, revisions and
admission invalidation together. Explicit client rollback does the same. Successful
commit invalidates even the caller's old capability; the native caller must close
that owner and authenticate anew. An uncertain network result must be reconciled,
not blindly retried with stale account state.

Error codes are fixed and omit verifier/ciphertext details: WH008 for invalid
payload/key metadata, WH009 for role-update failure, WH010 for stale/exhausted
account revision, and the existing WH005 for audit failure. Client parameter and
server statement/statistics logging restrictions remain mandatory deployment
concerns. This increment does not establish server-log or pg_stat_statements secret
scan coverage, nor full production deployment readiness.

Real PostgreSQL tests cover native/SQL parser parity, stale/maximum revisions,
incorrect key ownership, privileged-role rejection, a late missing ADMIN OPTION,
audit failure, concurrent readers, explicit rollback, unrelated-user isolation,
revoked-role preservation, old-session invalidation, new/old login behavior and
opening the persisted capsule under the new account master with unchanged private
keys. Numeric Go coverage is measured; SQL is covered by integration behavior
because the project has no PL/pgSQL coverage instrumentation.

The native `PreparePasswordChange` opens the existing wrapper against independently
certified public keys, rewraps the unchanged private pair with the next revision,
and creates a SCRAM verifier from the new account master's login derivation. Its
private fields cannot be serialized through JSON. The caller owns this short-lived
plan, must call `Wipe`, and must not use it concurrently with wiping. Both masters
are borrowed; neither master nor the decrypted private keys are retained. Signed
policy validation, preserving the current ASK and KDF, and a durable local trust
transition are prerequisites for any future user-facing caller.

`Session.ChangePassword` binds the plan to the authenticated workspace/user and
uses the retained native capability. It requires an idle connection and submits
one autocommit statement; callers cannot wrap it in their own transaction. Success
requires exactly one canonical result containing the expected next wrapping
revision and authentication epoch, followed by idle transaction status. It returns
a receipt, invalidates the old owner and wipes its capability. Always call `Close`
to confirm transport cleanup, including the optional notification connection.

Recognized SQL rejections preserve the session unless authentication/identity has
been invalidated. Disconnects, malformed responses and other unknown outcomes
after submission return `ErrPasswordChangeUncertain`, retire the owner and never
retry. A non-nil receipt still proves the checked committed response if native
memory release separately returns `ErrSessionCleanup`; retry cleanup, never the
mutation. Without a receipt, an uncertain result requires reconciliation against
server state before changing local credentials. That reconciliation and local
trust-root recovery are not implemented by this transport primitive.

The [local trust-root transition](vault-shared-root-transition.md) now provides a
durable encrypted journal, exact-source checks, promotion and abort recovery.
The native controller stages it before calling the session's `ChangePassword`,
retains the borrowed new root until local completion, and uses the checked receipt
before promotion. Merely finding a prepared journal proves neither commit nor
noncommit.

`sharedAdmissionController.ChangePassword` requires an already-unlocked owner and
native-derived old/new masters with the same KDF/ASK, plus the new protected
enrollment root. It validates argument shape and source before taking the operation
gate. Once an attempt starts it withdraws unlocked status, and always retires the
owner afterward. Invalid/cancelled preflight does not alter the current owner.
The caller owns and must wipe the borrowed inputs after return; the method does
not provide password entry, derivation or enrollment persistence itself.

Before dispatch it reuses the complete unlock verification path: match the old
master's login commitment, validate the signed policy and effective runtime floor,
retrieve and persist current signed account state (including revocations), verify
certificates and open the capsule, then persist its authenticated wrapping floor.
It derives the certified public pair and immediately wipes the temporary private
pair. The transport preparation independently reopens and rewraps the capsule;
its short-lived verifier/ciphertext plan is always wiped after use.

Durable journal staging, including one exact-state confirmation after uncertain
replacement, precedes SQL. A cancellation detected before dispatch aborts staging.
The session contract reports every unknown post-dispatch outcome as
`ErrPasswordChangeUncertain`; these outcomes retain the journal, as do missing or
inconsistent receipts. Definite preflight/SQL rejections abort the journal while
the previous ciphertext is unchanged. No SQL mutation is automatically retried.

A checked receipt promotes the local successor even though successful SQL retires
`Session.Done` and cancels the controller lifetime. Local promotion is deliberately
not suppressed by that cancellation. The receipt remains available alongside
promotion/cleanup errors, so callers cannot mistake local uncertainty for failure
of the remote commit. Error joining preserves remote uncertainty and cleanup
failure independently for `errors.Is`. Cleanup releases account-key memory, root
and session under the same operation gate; failed cleanup remains retryable.

Controller regression tests use real encrypted files and an injected typed session
for stage-before-dispatch ordering, commit-triggered session retirement, rejection,
unknown outcomes, malformed receipts, uncertain staging, local promotion failure,
cleanup failure, borrowed-input preservation, revocation and concurrent Close.
The transport has separate real PostgreSQL tests; this controller increment does
not establish a full running-app password-change test. Native
[outcome reconciliation](vault-shared-password-recovery.md) now handles pending
journals; application restart wiring, password entry and the enrollment-root
lifecycle remain pending.

The PostgreSQL integration test also verifies the ordering needed for future
reconciliation: a fresh audited proof on the **same device** cannot overtake an
operation that already holds the old capability's device lock. After that proof
commits, the replaced capability cannot submit a delayed password mutation.
Successful SCRAM login alone does not provide this barrier. The test checks that
the rejected old-capability mutation leaves the wrapping revision and epoch
unchanged; a busy/error result never establishes noncommit.

Native tests cover key preservation, derived-verifier consistency, invalid masters
and public keys, wiping, identity binding, exhausted epochs, existing transactions,
known rejections, unexpected result shapes/values/status, disconnects and retirement.
The real PostgreSQL test commits through the typed method and authenticates with
the resulting credential afterward.

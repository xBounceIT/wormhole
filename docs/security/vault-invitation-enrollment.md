# Invitation login coordinates

## Native application entry and restart selection

The native `shared-join-initial` operation and Electron Client/Host bridge now
coordinate initial preparation, one invitation commit, independent device
confirmation and ordinary admission. The first-launch screen now opens a
dedicated protected Join dialog. Code, password and optional ASK stay in that
isolated document and the native stdin flow; the application receives only public
admission metadata. Complete onboarding still requires the early staging recovery
work described below.

The dialog accepts a pasted token or a file selected by main. Go reads bounded
regular files and validates the canonical enrollment invitation without opening
SQLite or contacting PostgreSQL. Its public response contains only the canonical
token, workspace ID, login name and TLS mode. This checks format and expiry, not
organisation identity or policy. Only native TLS-Off metadata enables the explicit
acknowledgement. The typed response has an invitation-specific size limit, so a
valid large CA bundle does not hit the ordinary 64 KiB metadata limit.

Its stdin payload contains `invitation`, `code`, `password`, optional `ask`,
`deviceName`, main-owned `appVersion` and `acknowledgeTLSOff`. Secret fields use
the existing mutable byte-frame encoder. Code is exactly 16 bytes, password is
1–1024 bytes and a supplied ASK is exactly 32 bytes. Native decoding rejects
unknown/duplicate/null fields, oversized values, invalid device names, control
characters in login names, invalid client metadata and non-enrollment/expired
tokens before connecting. No request field can replace a local path, role,
device identity or transport setting independently of the invitation.

`OpenInitialInvitation` applies native OS/user floors before the first SCRAM
connection. The supported application profiles are currently Default and
Standard; higher or unknown floors fail closed. Standard requires Verified TLS.
`WHINV3` adds a signed organisation TLS identity. Its native first connection uses
the signed roots/hosts/revocations; bootstrap certification must authenticate the
same organisation and signer before preparing account keys. The coordinator
durably publishes the bundle cache and TLS floor with the initial checkpoint.
The public bridge accepts both enrollment formats under the same bounded hint
shape and never grants authority from the token alone.
Default TLS Off additionally requires the explicit acknowledgement; it never
disables validation of signed policy or organisation identity. Preparation then
authenticates the bootstrap and signed policy before deriving account material.
Until deployment metadata is independently authenticated, initial change
tracking conservatively polls so transaction poolers do not lose LISTEN events.

One native workspace owner keeps preparation, temporary connection, join
coordinator, device account, admission controller and cleanup obligations under
the same lease. Prepared account material moves through `TakeDeviceAccount`
after confirmed enrollment. It is not copied into a renderer or derived a
second time in production. Final publication shares the normal native admission
path, then retires account derivation roots. Electron accepts a fresh completed
startup checkpoint and current native runtime identity/policy before publishing
the shared workspace. The still-current parent then performs guarded application
authentication activation and mounts the admitted workspace without asking for
the password again. Cancellation and errors refresh native startup selection;
pending or completed enrollment cannot fall back to local or legacy creation.

Before the only commit dispatch, a separate OS-protected `.join-startup` sidecar
pins the native path, binding, canonical login and encrypted device-file snapshot.
It contains public slot hints and ciphertext, never a factor or root. Startup
describes this initial selection without deriving keys, querying PostgreSQL or
opening local/legacy data. The ordinary shared-unlock path rejects an initial
selection; explicit `shared-recover-enrollment` instead unlocks the exact staged
device and confirms the pending device/capsule through a fresh native session.
It never invokes `commit_invitation` again. Only authenticated active trust and
ordinary admission can publish the completed startup anchor and retire the
initial selection. Uncertain publication preserves retry obligations.

Controlled failures before dispatch validate every owned destination before
removal. Only the originating native attempt may remove its empty staging
directory and empty lock placeholder. Directory identity is captured through an
open handle, including on Windows, and cleanup reads at most two entries.
Replacements, unknown files, submitted state and unconfirmed cleanup remain
protected by the lease until positive cleanup or process retirement.

Abrupt termination before local staging finishes remains a separate recovery
requirement. Empty shared directories and snapshot-only partial staging fail
closed and are preserved. A missing local intent is not proof that the server
did not commit. No implementation may erase unknown state or blindly repeat an
invitation to enable another join.

The native admission receipt returns exactly `admitted`, `lockedMemory` and
`orgEscrow`. Go derives `orgEscrow` from the authenticated policy in the persisted
startup checkpoint, verifying its signature, identity, sequence and digest before
publishing the acknowledgement. Invitation hints and renderer input cannot supply
this value. After its existing current-owner/runtime checks, main adds the admitted
transport's `tls` mode to the public application projection. It takes this value
from the native runtime, never invitation hints or factor input. No additional
SQL request is needed.

After Join and each subsequent admission, the shared startup screen displays
"Your admin can see your personal items" or "Your admin cannot see your personal
items" from that admission-time policy. Missing, malformed or legacy two-field
acknowledgements fail closed. The renderer also signs out a claimed admission with
an invalid notice before mounting sessions or the catalog. The current
Default/Standard runtime requires escrow on. Signed Paranoid policies with either
value are covered at the projection and display boundaries; this does not enable
the unfinished Paranoid runtime or establish its key-visibility enforcement.
Missing or invalid transport notices likewise sign out before sessions/catalog
mount. A separate permanent notice remains visible for TLS Off or encrypted TLS
without certificate verification, including while refreshing the catalog. A new
admission refreshes it; confirmed sign-out removes it. Standard and higher runtime
projections require Verified TLS in main, matching Go's transport validation.

A sandbox/preload/Go test covers native invite-file inspection, a valid large CA
bundle, long public hints, TLS-Off acknowledgement and factor erasure with an
explicit refusal before SQL. A separate opt-in test now completes the protected
Join through the actual Client, Host and Go process against a disposable PostgreSQL
server, then locks and reopens through ordinary device admission. Main activates
the authenticated runtime and application in both cases. An independent database
query verifies one invitation consumption, one Join audit row, retirement of the
temporary invitation role and a confirmed permanent device role bound to the
committed certificate. Positive application tests cover Default with TLS Off and
its explicit acknowledgement, Encrypted TLS, and Verified TLS against a pinned
test CA. TLS-on modes do not acknowledge TLS Off. These tests do not establish other platform/profile
or deployment-wizard interoperability.

The new native operation has a five-minute overall bound and its Client request
allows six minutes for bounded cleanup. The initial input dialog has a ten-minute
absolute lifetime and keeps code, password and ASK inside its protected document.
The main application receives public acknowledgements only.

## Invitation format and temporary role

The approved initial-enrollment route uses a temporary SCRAM role per invitation,
with grants restricted to enrollment APIs. This avoids requiring a device role
before the device has joined.

`WHINV2` contains the existing public connection coordinates and organisation-key
fingerprint, plus a role tag and complete public `InviteContext`: workspace,
user, invitation, bootstrap encryption-key reference and canonical login name.
The temporary role is deterministically named `wh_<tag>_i_<invite UUID>`. Arbitrary
role names, invalid tags, empty key references and mismatched coordinates are
rejected. These fields do not contain the code, login password or SCRAM verifier.

Native `EnrollmentLogin` derives login material using the existing domain-separated
`vault.DeriveInviteLogin`, encodes it as the PostgreSQL password and returns an
independent transport snapshot. Native `EnrollmentVerifier` derives the same
material and generates a freshly salted SCRAM verifier for provisioning. Callers
must wipe both returned credential buffers. The original 128-bit code is never
sent to PostgreSQL, and the login material cannot decrypt the bootstrap envelope.

The token checksum detects transcription errors only. Bootstrap decryption using
the separately delivered code remains necessary to authenticate the organisation
key. For v2, bootstrap opening additionally requires exact equality with the token's
complete invitation context. An envelope for another issuance is rejected even
when it was correctly encrypted using the same code.

Canonical legacy `WHINV1` encodings remain unchanged and support their existing
offline bootstrap operations. They do not implicitly gain a temporary login role.
Token prefix and format version must agree, and every credential preparation
rechecks invitation expiry.

Tests cover canonical round trips, legacy/version confusion, context mismatches,
code size, expiry, independent transport ownership and real PostgreSQL SCRAM login
with the generated verifier. PostgreSQL `VALID UNTIL` rejects new connections after
expiry but does not end an existing connection. Therefore the enrollment SQL APIs
must independently check expiry, consumption and revocation on every call.

Schema migration 10 adds the separate `wh_<tag>_enroll` group and a private mapping
from invitation to exact role name and PostgreSQL OID. Its owner-only provisioning
helper creates a new SCRAM role with a finite `VALID UNTIL`, connection limit 2,
no administrative privileges and inherited enrollment grants. It never adopts an
existing role. Device/user/admin grants are not inherited by this group.

The public `enrollment_bootstrap(invite_id)` API is granted only to that group.
It identifies the caller using `session_user`, checks the stored role OID, login
status, finite unexpired role lifetime, privilege flags, invitation expiry/use/
attempt limit and disabled-user state. It also enforces the workspace TLS/API
requirements. Shared row locks keep a successful read ordered before consumption.
It returns only the caller's encrypted bootstrap, signed manifest and public
binding coordinates. No password, plaintext key or verifier is returned.

An owner-only revocation helper marks the mapping revoked and changes the role to
`NOLOGIN`. Updating an invitation's `used_at` invokes this helper in the same
transaction. An OID mismatch fails the transaction instead of altering another
role. Already-open connections then fail the API's per-call checks. Retired roles
remain disabled; physical role deletion is separate maintenance work.

Real PostgreSQL tests exercise migration identity/replay rejection, role creation
under the non-superuser owner, connection and membership permissions, duplicate
role refusal, bootstrap bindings, TLS refusal, expiry, attempts, disabled users,
OID mismatch, transaction locking and atomic consumption/retirement. Numerical
Go coverage does not instrument PL/pgSQL; these integration tests verify its behavior.

Native `Session.OpenInvitation` opens one query connection using the temporary
SCRAM credential and wipes the temporary password buffer. Its caller owns the
session and must close it even after an error. `Session.InvitationBootstrap` uses
a fixed parameterized statement and the existing bounded query transport. It
rechecks local expiry after the response, verifies all returned coordinates and
canonical numeric fields, and invalidates the owner on malformed responses.

The encrypted bootstrap is canonical JSON of `vault.Envelope`, bounded to 64 KiB
and restricted to the current AES-GCM format, expected bootstrap key reference,
12-byte nonce and 113-byte ciphertext. The signed manifest uses its existing
canonical codec and 1 MiB bound. Unknown/duplicate fields, noncanonical encodings
and mismatched issuance, expiry or manifest revision are rejected. Structural
parsing returns `UnverifiedInvitationBootstrap`, never an authenticated key.

Its `Authenticate` method opens the envelope using the separately delivered code,
pins the organisation key using the invitation fingerprint, verifies the signed
manifest and minimum revision, and checks both bootstrap public keys against the
decrypted private material. This verification is shared with final rewrap through
`vault.VerifyInviteBootstrap`. Failure wipes plaintext material; on success the
native caller must wipe the returned bootstrap. The payload cannot be serialized
through its Go JSON representation.

Real PostgreSQL tests now store and retrieve an actual encrypted envelope and signed
manifest, verify authentication after query buffers are wiped, reject a forged
manifest signature and retire a session after malformed encrypted-envelope data.

Schema migration 11 adds `enrollment_key_copies`, restricted to the enrollment
group. It reuses the complete bootstrap authorization gate and requires the exact
manifest revision and SHA-256 digest observed by the client. Only copies held by
the current invitation's bootstrap encryption key are eligible. One cursor snapshot
validates and returns at most 1,024 copies; unsupported suites and incorrect
encapsulation/ciphertext/signature lengths fail the call. This avoids checking one
snapshot and returning another during concurrent changes.

Native `Session.PrepareInvitationJoin` fetches and authenticates the bootstrap first,
then downloads the manifest-bound copy set. It matches rows to signed key, holder
and issuer references, independent of SQL row order; missing, extra, duplicate or
malformed rows invalidate the owner. The existing certified rewrap verifies every
issuer signature and HPKE ciphertext before producing the replacement plan. The
plan preserves the source manifest revision and digest and must be wiped by its
native owner on completion or cancellation. Bootstrap plaintext is wiped before
the method returns.

This prepares a plan; it does not redeem the invitation or commit enrollment.
The final transaction must revalidate authorization, manifest revision/digest and
complete replacement set before atomically activating the device and retiring the
temporary login. The complete audited invitation-creation and join APIs, one-time
redemption and application integration remain work. The private provisioning helper
is not granted to client/admin device roles until a validated invitation-creation
API owns that transaction.

`vault.UserEnrollmentCertificate` now represents the public certification chain
from organisation-certified bootstrap keys to bootstrap-signed final user keys.
Verification requires independently pinned organisation identity, current signed
account state selecting the bootstrap anchor, certificate revision floors and a
manifest revision floor. It rejects key identifier reuse across the bootstrap,
organisation and final keys. Canonical bounded encoding rejects ambiguous input.

Live preparation checks the exact invitation context and expiry, then returns an
independent public snapshot. Historical verification intentionally permits an
expired invitation: an enrolled account must remain usable after its invitation
expires. Signed account revocation, anchor replacement and rollback floors still
apply. Opening an encrypted final-key capsule verifies this chain and both derived
public keys before returning caller-owned private material.

This primitive does not establish that redemption occurred, authorize a device or
select a winning redemption among competing bootstrap-signed proposals. The join
transaction must commit exactly one final pair and the account/device path must
retain that committed selection. The existing direct-certificate login path is
unchanged; account retrieval and controller integration for the new chain are
described below.

Schema 12 now stores the committed public chain in the private `user_enrollments`
table, together with final encryption/signing key references. Runtime roles cannot
read or write that table. The capability-gated `account_enrollment_material` API
retrieves the caller's capsule, signed state and chain under retained share locks.
It rejects a wrapper that selects a different pair and rechecks the final keys'
owner, kind and active status while holding their locks. Temporary invitation roles
cannot call this account API.

Native `Session.AccountEnrollmentMaterial` uses the existing bounded, timed account
transport. Its decoder checks the final capsule against the rekey proof and the
bootstrap against the signed-state coordinates. These checks are structural;
the caller must verify the chain against independently pinned organisation trust
and revision floors before decrypting. Malformed data retires the session. Real
PostgreSQL tests exercise an actual encrypted capsule and chain, false signatures,
mixed key selection, retired keys, lock contention, ACLs and migration guards.

The enrollment commit must populate this record atomically with device activation.
The application controller selects the enrollment path only after its final
selection has been established in protected local trust, as described below.

Protected trust format 5 now supports `EnrollmentPin`: final key references, a
domain-separated digest of both fixed-size public keys, and the highest verified
manifest revision. `AdvanceEnrollment` verifies the chain against the current
signed bootstrap state before accepting this metadata. A different final pair,
changed public keys or an older manifest is refused even when it is presented
under the same bootstrap. First acceptance still requires evidence of successful
redemption or independently authenticated device enrollment; this helper does not
turn an arbitrary database response into that evidence.

Policy updates, TLS updates, wrapping revisions and password-root journal recovery
preserve this selection. Revocation preserves it while refusing unlock. A newer
organisation-signed state replacing the bootstrap anchor retires the old selection;
the old chain then fails verification. The persistence boundary refuses ordinary
writers that erase or replace a selection under an unchanged anchor. Existing
formats 2–4 retain their canonical representation, and upgrading to format 5 does
not implicitly enable TLS or weaken an existing TLS floor.

The native admission controller now uses the protected pin to select
`AccountEnrollmentMaterial` for unlock, password changes and password-change
reconciliation. It never falls back to direct certificates on failure. A format-5
state whose pin was retired by an authenticated reset requires re-enrollment. Mixed
direct/enrollment material is refused. The shared verification helper checks the
pin and manifest floor before opening the encrypted capsule; the controller
persists the resulting floors before publishing unlocked private keys.

Recovery preserves enrollment observations in the protected password-root journal
before promotion or rollback. It still requires the appropriate wrapping revision
for the independently proven old/new credential outcome. Tests cover real native
certificates and capsules, persistent selection, password changes, both recovery
outcomes, forged/missing/mixed materials, a reset, altered final references and
durability failure. This connects existing enrolled accounts to the controller;
the native application route and protected Join flow at the top of this document
now orchestrate the invitation primitives below.

Schema 13 introduces the `commit_invitation` transaction for first-account invites.
It rejects reset invites and accounts already holding authentication, wrappers,
devices or enrollment records. It first takes an exclusive invitation lock, reuses
the complete temporary-role/TLS/expiry gate, pins the exact manifest revision and
digest, and locks the user and bootstrap keys. Each source copy is locked and must
have exactly one replacement; extra, duplicate, missing or oversized sets fail.

The transaction creates fresh final key rows, installs replacement copies, retires
the bootstrap keys, creates a fresh device role with a prehashed SCRAM verifier,
and stores account authentication, encrypted capsule and public certification.
Only enrollment roles can call it; they cannot select another account or adopt an
existing role. Device login initially expires with the invitation, as specified
for join; the confirmation API below makes the login permanent. The role inherits
only user APIs, with no SET ROLE permission.

The audit row and invitation consumption are part of the same transaction. Audit
failure or a role collision rolls back every preceding write, including role DDL.
Consumption disables the temporary login, deletes the code-wrapped bootstrap
capsule and removes old holder copies. Public certification remains available for
future login. Signatures remain independently checked by Go; successful SCRAM
authentication of the scoped invite role authorizes the SQL mutation.

Real PostgreSQL tests verify successful device login and native capsule/key-copy
decryption after commit, malformed/missing/duplicate/oversized copies, foreign
manifest revision/digest, role collision, audit rollback, invitation/source-lock
contention, API ACLs, migration guards and refusal of repeated redemption. Negative
cases invoke the transaction directly; the successful path uses the native
prepared request, device proof, capsule verification and confirmation. Completion
orchestration and the join UI are still required; an interrupted call must not be
blindly retried.

Schema 14 adds `confirm_enrollment`, restricted to audited device sessions. It
uses the session's own device identity and the digest of the exact committed public
certificate. The current login must be active, unprivileged, `NOINHERIT` and have
a finite future expiry. Expiry is checked on every call, including connections
opened before expiration. Under the device lock, confirmation changes only
`VALID UNTIL` to infinity, stores the role OID and certificate digest in a private
confirmation record, and commits an audit row atomically. An audit failure restores
the finite expiry and leaves no confirmation record.

A repeated confirmation checks the stored role OID, digest and permanent expiry
and returns success without another audit. A different role incarnation or changed
certificate/expiry fails closed. Temporary invitation roles cannot call this API,
and no runtime role can read or write its confirmation table.

Native `Session.ConfirmEnrollment` accepts the digest only after its caller has
verified the committed certificate and opened the capsule. It requires autocommit,
uses bounded parameters and validates the returned device identity. It does not
retry automatically. Unknown failures after dispatch or malformed responses return
an uncertain-outcome error and retire the session. Reconciliation must reconnect,
authenticate and verify the same enrollment before using the idempotent operation.
This helper does not establish initial trust or replace durable join recovery.

Schema 15 adds `enrollment_certification` for the temporary invitation role. It
returns the signed account state, workspace policy and both organisation-signed
bootstrap key certificates. The existing enrollment gate binds the caller to its
live invitation, and the request pins the exact manifest revision and digest.
State and key rows are locked for a consistent read; missing certificate metadata
fails closed. User, administrator and PUBLIC roles receive no execution grant.

Native `InvitationCertification` bounds and structurally decodes the response.
Its result remains explicitly unverified until `Verify` checks the invitation's
organisation fingerprint, manifest signature and expiry, account signature and
sequence floor, active bootstrap selection, both certificate signatures and
revision floors, exact manifest public keys, and signed policy/API compatibility.
No device authorization or first-use trust is established by this read. Malformed
responses retire the session; signatures are verified independently of SQL.

The first-account commit also rechecks the current signed account selection and
certificate floors under lock. A revocation or reset between the download and
commit therefore refuses activation. Current policy KDF and ASK requirements are
checked in the transaction, including the Hardened administrator and Paranoid
requirements. Real PostgreSQL regressions change signed requirements after the
download and verify that rejection leaves the invitation and account untouched.
The protected pending-join journal and user-facing flow remain to be connected.

Native `PrepareInvitationCommit` now snapshots a first-enrollment request after
verifying the certification, live manifest, exact source revision/digest, rekey
proof, final private/public key correspondence and complete replacement copy set.
Every replacement copy is authenticated and opened locally before submission. The
account master must belong to the same workspace and immutable login name, and its
KDF/ASK facts must satisfy the signed policy. Preparation seals the final private
keys and derives a SCRAM verifier without retaining the master or private keys.
The caller still owns and wipes the source plan and account master independently.
The resulting native request has no exported fields or JSON secret representation;
its `Wipe` clears the verifier and payload buffers.

`Session.CommitInvitation` accepts only this prepared request, uses autocommit and
dispatches once. Its fixed statement has a separate 4 MiB parameter bound so that
a large certificate and all 1,024 copies fit without raising the generic query
limit. A successful response must identify the prepared device and role, wrapping
revision one and authentication epoch one. Success retires the temporary session.
An unknown error, disconnect or malformed response after dispatch also retires it
and returns `ErrInvitationCommitUncertain`. Known SQL rejections are preserved;
there is no automatic retry. A durable protected pending enrollment must precede
dispatch, and device proof, capsule verification and durable initial trust must
follow it. The primitives below support these steps; application orchestration
remains outstanding.

`PreparedInvitationCommit.PendingEnrollment` now provides an independent snapshot
for staging: the pinned organisation, signed policy and account state, exact public
certificate, device identity, KDF/ASK facts and a domain-separated digest of the
encrypted private-key capsule. It contains neither the credential verifier nor any
private key, password or ASK. The record represents intent only. It deliberately
does not select an active `EnrollmentPin` or recreate a request for automatic retry.

`SealPendingEnrollment` and `OpenPendingEnrollment` protect this record with a
distinct AEAD table/field domain and the independently supplied local trust binding.
Canonical encodings, size bounds, signatures, identity and policy checks apply on
read. The record remains decryptable after invitation expiry so interrupted joins
can be reconciled; expiry never becomes an authorization to submit a new commit.
Pending and active trust files cannot be substituted for one another.

The native file layer stages the ciphertext at the trust path's `.enrollment`
sidecar under the same exclusive lock used by trust writes and password transitions.
It refuses existing trust, pending enrollment or password-change records. Ordinary
trust creation/confirmation and password-change staging refuse a pending enrollment.
An atomic-write directory-sync failure returns uncertain durability. Exact-record
confirmation authenticates the entire record and republishes it through the durable
writer; readback alone is insufficient. Neither staging nor confirmation activates
trust. Initial dispatch still requires application orchestration and durable setup
metadata; the recovery coordinator below handles an already staged journal.

Pending records can now retain authenticated policy, account-state and TLS
observations without changing the original preparation. Updates use the existing
monotonic trust rules and preserve revocations, resets and higher floors. The file
writer compares the complete expected record under the same lock; it accepts an
exact next-record readback for durable confirmation after an uncertain replacement,
but rejects a competing or older observation. These observations must be saved
before their results are used, including results that prevent enrollment.

`Session.VerifyPendingEnrollment` requires an audited session for the exact
workspace, user and device, at the first authentication epoch. A SCRAM connection
alone is insufficient. The returned material must match the recorded certificate,
capsule digest, initial wrapping revision and KDF/ASK facts, and must carry the exact
currently observed account state. It verifies and opens the capsule with the
matching account master, wipes the temporary private keys, and checks the latest
policy requirements. Hardened administrators require ASK; Hardened and Paranoid
require locked master/capability memory. Session administrator status comes from
the same audited admission and is cleared on retirement.

Successful verification returns an opaque native `VerifiedEnrollment`. It binds
the intended activation state and certificate digest to the entire pending record
and independent local binding. It cannot be serialized as proof, and changing any
pending observation invalidates its use for activation. This is verification
evidence only; it does not establish permanent device login or local durability.

`ConfirmVerifiedEnrollment` accepts evidence only from the same native session,
checks the exact pending record and performs the audited confirmation. Success
returns an opaque `ConfirmedEnrollment`; a verification-only object cannot satisfy
the file promotion interface. Errors and uncertain confirmation never produce a
confirmed object. Restart recovery must reauthenticate and verify before using the
server's idempotent confirmation again.

`promoteSharedEnrollment` takes the shared file lock, checks the complete journal
against the confirmed evidence, durably publishes the resulting trust state, then
deletes and directory-syncs the journal. If publication durability is uncertain,
the journal remains. A matching destination is always republished to confirm
durability. An interrupted older publication may advance only with the identical
final selection and valid monotonic observations. If the journal is already absent,
only the exact target state is accepted for cleanup confirmation. Corrupt, foreign,
newer or unselected destinations are not replaced.

Ordinary admission reads the pending marker and trust file under one shared lock,
before contacting PostgreSQL. It cannot use an intermediate trust file while its
journal still exists. Tests inject publication and cleanup sync failures, later
observations, competing destinations and, on Windows, a deletion-blocking open
journal handle.

`sharedAdmissionController.RecoverEnrollment` now connects journal read, fresh
device authentication, observation persistence, native proof, remote confirmation
and durable promotion. It borrows the native account master and independently
authenticated setup options/root. It rejects a known revocation, reset, wrong
device role or mismatched login before opening a connection. Signed profile,
account-state and TLS observations are saved before use; an observed TLS rotation
requires a fresh connection. A changed KDF/ASK policy cannot be bypassed by the
original journal. Only an uncertain local observation write gets one exact retry;
the coordinator never submits or retries `commit_invitation`.

The recovery owner uses a single query connection and always closes it. It never
becomes an admitted or unlocked application session. A successful remote
confirmation remains explicit in the result if later local publication or cleanup
fails. Callers must handle the accompanying error and retain the owner if native
cleanup needs another attempt. Cancellation before confirmation leaves the journal;
cancellation after confirmation cannot undo the remote result. A restart with a
journal reauthenticates and verifies again, while an absent journal with durable
active trust uses ordinary admission.

Coordinator tests exercise encrypted persistence and real capsule cryptography
with an explicit substituted session-proof boundary. PostgreSQL integration tests
separately exercise the production verification/confirmation pair. Initial join
dispatch, device key-slot integration and the user-facing join flow remain outstanding.
The current coordinator retains the runtime gate for unsupported Hardened/Paranoid
integration; it does not silently lower the requested profile.

The connection setup has a separate encrypted `.connection` sidecar format.
`EncodeTransportSnapshot` preserves the signed managed TLS document explicitly;
serializing `Settings` directly would omit its native `TLSBundle`. Decode verifies
that document against independently supplied trust and reapplies the current
workspace, OS and user profile floors. Unknown/duplicate/noncanonical JSON,
unsupported versions, mixed managed/unmanaged CA metadata and stale TLS bundles
are rejected. The AEAD domain differs from both trust and pending enrollment.

`stageSharedTransportSetup` requires missing active trust, no password transition
and no pending join, and refuses to replace an existing setup. It takes the same
trust-file lock and uses the private atomic writer. Exact-record confirmation
rewrites through that durable writer; matching readback does not hide a failed
directory sync. A pending join may already exist during confirmation, so the
future dispatcher can reconfirm setup and intent before its single SQL mutation.
Neither operation authenticates a new organisation or dispatches a join.

`RecoverEnrollmentFromSetup` now reads the protected journal and connection file
before calling the native recovery coordinator. It ignores caller-supplied host,
role and TLS settings, while preserving independently supplied device identity,
root and current local security floors. Missing or corrupt configuration never
falls back to those caller settings. The coordinator rereads the journal before
opening its session, so an intervening higher TLS floor cannot be bypassed.

For a historical managed snapshot, the file reader can use the current signed TLS
cache that was published before the protected floor. `OpenTransportSetupWithTLS`
authenticates the original document against the same organisation and requires
its sequence to be strictly older. It then verifies the replacement against the
current exact sequence/digest before applying transport policy. Equal-sequence
equivocation, future observations, foreign bundles, unmanaged settings and missing
or corrupt cache are rejected. Hosts, role and other protected settings remain
unchanged; neither this read nor recovery rewrites the original setup file.

Password-root staging now includes an existing connection sidecar. Journal format
2 carries the exact source ciphertext digest and a target ciphertext authenticated
under the new root and the same device binding. Format 1 remains readable for
legacy states without a sidecar. The journal bound is 16 MiB to accommodate the
bounded nested ciphertext; passwords, roots and ASK values remain absent.
Rewrapping preserves the canonical metadata bytes and does not consult PostgreSQL
environment settings or change TLS policy. Using the result still verifies all
current trust and transport requirements.

Staging and exact confirmation check the source under the shared file lock.
After independent proof of remote commit, completion accepts only that source or
the exact previously published target, durably writes the target setup, writes
the trust state, and finally removes and syncs the journal. Every retry confirms
both local publications without resending SQL. A conflict or uncertain write
retains the journal. Abort and proven noncommit preserve the original setup; they
cannot erase a journal after the target setup has been partially published.
Ordinary admission now refuses a password-change journal before contacting SQL,
preventing use of an intermediate pair of files.

`RecoverPasswordChangeFromSetup` can read the journal's target configuration using
only the new root, even while the sidecar itself still uses the old root. It
ignores caller connection settings and uses the existing audited password recovery
to determine whether to complete or roll back. Old-password noncommit recovery
still needs the old root. Neither the journal nor its configuration proves commit.

`sharedInvitationJoin` now coordinates a prepared first join. It consumes the
native prepared request once, requires the same live `AccountMaster` used for
preparation, and rejects already expired requests before staging. It applies local
and signed policy floors, derives the exact device role from the intended identity,
stages connection setup, publishes any managed TLS cache, and stages the intent.
Both protected records are reconfirmed immediately before the single commit call.
The prepared verifier is wiped before device recovery and on every terminal path
of a started attempt.

The coordinator's lifetime is independent of the temporary invitation session,
which intentionally retires after commit. It confirms that session's cleanup
before creating a fresh native recovery owner. A receipt or an uncertain outcome
can lead to `RecoverEnrollmentFromSetup`; uncertainty never resubmits the commit.
Successful device confirmation resolves uncertainty. Failed recovery retains the
original uncertainty and the protected records. Known SQL rejections also retain
the records once the commit API has been invoked. `Submitted` denotes that API
invocation, not proof that the server received a mutation. `Committed` and
`Confirmed` record known remote outcomes even if later local cleanup fails.

Before any commit invocation, a failing attempt can clean up only destinations
that it published itself. It authenticates and compares both records under the
shared lock before deleting either. Active trust, password transitions, competing
observations, changed settings or unowned intent prevent deletion. A retained
owner can retry `DiscardPreparation` after a partial deletion or uncertain sync;
that method always refuses an owner that invoked commit. It retains public
preparation metadata but no root key. A process termination loses the in-memory
proof of non-submission, so persisted records must be treated as uncertain and
never blindly discarded or resubmitted.

Coordinator tests use real encrypted files and native preparation, with explicit
invitation-transport and session-proof test boundaries; production PostgreSQL
tests separately exercise the delegated commit/verification/confirmation APIs.
Windows tests use deletion-blocking handles to verify cleanup retry.

Native startup supplies an authenticated, recoverable root and binding from
device key slots through the protected selection and input routes above. The
setup contains no password, ASK or root. The application renderer invokes only
the fixed dialog mode; it cannot call the coordinator with paths or factors.

`OpenAccountFromSetup` provides ordinary native reopen after enrollment has been
confirmed. It loads the protected connection settings inside the admission
owner's gate, after checking active trust and both recovery markers, and before
any network operation. Caller connection settings are ignored. Current local
policy floors still apply. Managed TLS rotation uses the exact authenticated
cache selected by the current trust floor; missing or altered setup/cache fails
closed. Admission, account-key unlock and failure cleanup use the existing owner
lifecycle. Reopening does not rewrite the setup or retain the borrowed account
master. Device key-slot and native startup integration remain required.

`AccountMaster.DeriveTrustRoot` now produces an independently owned native
`DeviceTrustRoot`. Its HKDF-SHA256 label is `wormhole/v1/shared-device-root`;
the salt concatenates the 16-byte workspace, user, device and key UUIDs, followed
by the four-byte big-endian key version. The input is the mixed account master,
so the same password/ASK and enrollment binding reproduce the same root.
Password/ASK changes require the existing root transition protocol. The root
cannot be substituted for login or capsule keys, and no root bytes are serialized.

The root owner inherits the account derivation's locked-memory requirement and
survives closure of the master. Derivation releases the master before returning,
allowing subsequent root use to call native operations that borrow the master.
Failed derivation wipes temporary material and retires an allocated root; an
unconfirmed native release returns its owner for cleanup retry. A fixed known-answer
test pins this derivation format, alongside actual encrypted trust recovery tests.

This derivation does not authenticate enrollment metadata or persist ASK, key
slots, or an independent binding. Native startup must still supply those inputs
through its protected enrollment and input flow before opening any shared data.

`Session.PrepareInitialEnrollment` now connects bootstrap download, code
authentication, signed account certification, account derivation, complete-copy
rewrap and device-root creation on the temporary enrollment session. It uses one
authenticated bootstrap snapshot throughout. Policy comes from the verified
certification; current native OS/user floors can strengthen it. A Default-only
low-memory KDF is raised to `kdf-v1` when Standard is required. Unsupported shared
runtime profiles fail closed. ASK remains a separately supplied native factor.

The resulting `PreparedInitialEnrollment` owns the master, device root, device
storage allocation and single prepared commit request. Native code borrows them for the join
coordinator and closes the preparation afterward. Borrow and close must be
serialized by the caller. Closing wipes the verifier and independently retires
all key owners, retaining any owner whose release needs retry. The bootstrap
private keys and temporary rewrap plan are wiped before preparation returns.
This step neither commits nor persists the enrollment; the generated binding
must still be stored through the independent native enrollment flow before
dispatch. Tests exercise the complete preparation against PostgreSQL, then
confirm that the invitation remains usable by the separate commit path.

Native device metadata now has a protected storage format. `SealDeviceEnrollment`
snapshots the prepared binding, immutable login, KDF/ASK requirements and initial
signed trust into an AEAD envelope under a **separate device storage root**. It
does not store a password, ASK, account master or derived account root. The
`wormhole/v1/shared-device-setup` key domain and the slot file's vault/file/key
identity separate this envelope from account trust and other local records.

`OpenDeviceEnrollment` first verifies the slot-file MAC, selected vault/file IDs
and minimum sequence, then authenticates the encrypted metadata. The payload is
also bound to the exact slot sequence. Only then can its account derivation be
used, with current local floors reapplied without silently changing the stored
KDF. Every password slot must be at least as strong as the account KDF; recovery
slots use independent random recovery keys. Missing ASK remains a native input
requirement. The authenticated snapshot is not current server authorization:
ordinary admission still checks the separately maintained trust state.

The canonical device file combines slots and ciphertext for a single atomic
publication at `.device`. Decoding it before unlock returns only **untrusted**
slot candidates; it grants no policy or identity authority. Native staging shares
the trust-file lock, refuses existing device/configuration files and active or
pending account state, and never activates trust or sends SQL. A failed directory
sync leaves an uncertain result. Confirmation authenticates the exact expected
pair and durably rewrites it; matching readback alone is insufficient.

Application startup now uses independent device selection and protected factor
entry. The native password-change protocol below coordinates device-file updates;
its complete protected-UI-to-server interoperability remains unverified.
The old account root cannot decrypt this file: the storage root is intentionally
independent, and its slot lifecycle must be coordinated with account changes.

`PrepareInitialEnrollment` now creates that storage root directly in native
memory and wraps it with a fresh password slot while the original password/ASK
inputs are still borrowed. It uses both factors when ASK is present, retains
neither, and generates fresh storage vault/file/key identities. Slot derivation
is at least `kdf-v1`, even when a signed Default policy permits a lower account
KDF: before opening metadata, the client cannot authenticate that exception.
Stronger selected account KDFs are preserved for the slot.

The preparation owns the resulting slot/envelope file and storage allocation.
`BorrowDeviceStorage` authenticates and lends the root plus independently decoded
metadata to native publication code; it exposes no password or ASK. Callers must
serialize borrowing and closure and must not retain the borrowed root. Closing
the preparation attempts all three key owners and retains failed allocations for
cleanup retry. `DeviceStorageLocked` reports allocation status for the future
native warning flow. No recovery slot is generated by this step.

Roundtrip tests close the entire preparation, reopen its password/ASK slot,
authenticate the stored enrollment, and reconstruct the same account root and
device binding. Wrong passwords and missing ASK fail. PostgreSQL integration
also verifies the generated storage pair before the independent commit path.
Publication and selection in the application remain outstanding.

`sharedInvitationJoin.JoinPrepared` now connects native preparation to durable
publication. It claims the single-use coordinator before borrowing any keys,
takes identity and revision from the prepared native device, and stages the
authenticated `.device` pair before connection settings and enrollment intent.
Immediately before the single commit call, it confirms the exact device bytes
under the shared file lock with the exact authenticated intent. Confirmation
requires a durable rewrite, including after uncertain directory sync.

Before submission, cleanup validates every owned destination before removing
any. It requires both independently unlocked roots for device cleanup, refuses
changed or competing files, and retains ownership when deletion or directory
sync needs retry. Once submission starts, device storage survives rejected or
unknown outcomes; the coordinator never retries the commit or deletes those
files. Recovery still uses a fresh device session and authenticated server proof.
The prepared native aggregate remains caller-owned and must be closed after use.

Coordinator tests use real encrypted files and native key owners with an explicit
SQL/proof test boundary. They cover interrupted writes, altered files, final
intent mismatch, cancellation, duplicate attempts and Windows deletion failures.
They do not establish application startup or a complete UI-to-PostgreSQL join.

`PrepareDevicePasswordFile` prepares the next encrypted device file without
publishing it or changing PostgreSQL. It authenticates the source against native
vault/file selection and the sequence floor, reapplies local profile constraints,
and preserves account identity, account KDF and ASK mode. It replaces every old
password slot with one fresh slot, keeps recovery slots, preserves stronger slot
KDF costs, and increments the authenticated file/metadata sequence together.
Even a signed low account KDF receives at least a `kdf-v1` password slot.
The same borrowed new password and existing ASK must feed account derivation.

The candidate is not evidence of remote commit. Format-3 password journals now
commit the exact old device digest and next encrypted file. A bounded outer
wrapper repeats the encrypted candidate so native code can discover its password
slot after restart. `UnverifiedTransitionDevice` grants no trust: selection,
slot MAC and encrypted metadata must authenticate before account derivation.
`OpenTrustRootTransition` then authenticates the inner journal under the new root
and requires its candidate to match the outer bytes exactly. Removing the wrapper,
substituting another candidate or wrapping a legacy journal is rejected.

Preparation authenticates both device files, preserves account metadata and
storage identity, requires sequence+1 and exactly one fresh password slot, and
preserves recovery slots and stronger KDF costs. Observation updates preserve the
device commitment. Formats 1 and 2 remain supported for devices without this file.

`ChangeDevicePassword` durably stages the complete transition before the single
remote mutation. A receipt permits publication in device, configuration, trust
order; interrupted committed publication accepts only the exact source or target
and can resume. Abort requires the unchanged source device. Unknown outcomes keep
the journal for a fresh audited session; recovery never repeats the mutation.
Legacy trust/setup-only transitions refuse unexpected device files at staging,
confirmation, promotion and abort rather than silently ignoring them.

Tests reconstruct the new account root from only the wrapper's password slot,
the protected factors and independent selection after native owners have closed.
Coordinator tests cover commit/rejection/uncertainty, both recovery outcomes and
directory-sync failures at each publication step. Their SQL boundary is explicit;
the complete UI-to-PostgreSQL password-change flow is not established yet.
Native startup selection and protected factor entry use the application routes
described above.

`OpenDeviceAccount` now performs the native unlock as one owned operation. Native
selection supplies vault/file identity, minimum sequence and an explicit password
slot; file descriptors cannot replace these values. Local profile and pre-unlock
KDF checks precede password derivation. Slot MAC and enrollment authentication
precede account derivation. `OpenDeviceTransitionAccount` additionally verifies
the root-encrypted journal before returning an owner for recovery.

`UnlockedDeviceAccount` owns storage, account master and device root independently.
It retains only encrypted file/journal bytes, never password or ASK. Borrowing
and closure must be serialized. Storage borrowing reauthenticates the retained
file; journal borrowing releases the root lock before calling recovery code.
Closing attempts all native releases, denies subsequent borrowing and retains
failed owners for cleanup retry. `Locked` supports the native warning flow and
must not be called while borrowing storage from the same owner.

Its `PreparePasswordChange` creates the candidate and next master/root from the
same borrowed new password/ASK, and commits the exact
source-file digest in private preparation metadata. A reopened arbitrary file
cannot impersonate that preparation. `BorrowPasswordChange` checks the source
and binding before lending the independent native owners; the main coordinator's
`ChangeDeviceAccountPassword` consumes that contract to drive the durable change.
These native APIs still require the application's protected input and selection
lifecycle to be wired before the shared workflow is available in the UI.
Preparation authenticates its generated file with the already unlocked storage
key instead of repeating the password-slot KDF; restart tests independently open
that slot with the new factors after the prepared owners have closed.

The native startup anchor (`.startup`) preserves public selection, derivation,
signed trust and transport facts using the operating system's protected store.
It contains no password, ASK, account master or storage root. A purpose tag and
path digest bind the protected record to its device path, including on Windows
where DPAPI itself does not bind ciphertext to filenames. Reading it needs no
unlocked account. OS-store failures fail closed without a plaintext fallback.

Registration and updates require a live native device owner and exact agreement
with the active device file. Under the trust-file lock, pending enrollment and
password transitions block publication; trust and transport come from their
authenticated files, not caller settings. Updates preserve identity and account
derivation and cannot lower observed trust or device sequence floors. Exact replay
can confirm uncertain directory durability. Malformed existing anchors are never
silently replaced. These checks do not provide hardware-backed anti-rollback of
all local files; fresh server admission and signed state remain mandatory.

The anchor is a prerequisite for adopting a password changed by another device:
the old local password slot cannot be opened with the new password. Remote password
adoption, rebuilding local wrapping after fresh authenticated server admission,
anchor lifecycle updates, application selection and protected input wiring remain
unfinished. The shared workspace is still unavailable in the application.

`unlockSharedSelectedDevice` now consumes the protected anchor to select an
explicit password slot for ordinary opening or local password-journal recovery.
Native runtime options supply the absolute path, API and local floors; identity,
vault/file IDs and sequence floors come from the anchor. Caller connection
settings are discarded. The anchored profile is checked before file unlock, so
an older enrollment profile cannot bypass an unsupported current profile.

A shared file lock covers anchor, pending-marker and encrypted-file reads. After
unlock, native binding, login, KDF and ASK mode must match the anchor. Authenticated
active or journal trust must preserve its pins and high-water marks. The highest
observed revision is carried into subsequent admission, preventing rollback in
the interval between selection and connection. Native account ownership remains
explicit and cleanup is required even for a nonnil result returned with an error.

The selected owner's `Open` uses protected transport setup; `RecoverNewPassword`
uses the authenticated journal and a fresh audited recovery session. The modes
cannot invoke each other's operation and there is no credential fallback. Tests
cover rejection of the old capsule, completion from a correctly rewrapped capsule,
and ordinary reopening afterward with real native keys/files and an explicit
simulated SQL/proof boundary. Initial invitation selection and application/service
wiring use the dedicated routes described above. The old-password recovery UX
and remote password adoption remain open.

The native vault service now handles stdin-only `shared-unlock` and
`shared-recover-password` requests. They carry the native application version and
the existing typed-factor input, never paths, endpoints or trust records. A shared
profile lives at `<databasePath>.shared/device.trust`; the backend chooses that
path. Any shared marker, including a damaged file in place of its directory,
blocks legacy access, local initialization and local unlock. Shared opening also
rejects an existing local database or slot file; conversion requires its own
migration rather than selecting both stores.

The service holds exclusive workspace ownership through admission and all
cleanup. Uncertain cleanup retires the handler and retains the lease for retry.
Successful admission refreshes the protected startup anchor, then releases the
selection's storage/account roots immediately. Only the controller's independent
session keys remain. A controller retired during publication cannot return a
successful admission response. Recovery closes every owner and releases the lease
before returning its metadata-only result.

Native admission selects the shared owner. Shared catalog and protocol operations
independently check that owner and their permissions; local workspace operations
remain blocked. Startup and description project a valid shared profile; a damaged
profile never advertises a new empty local vault. Electron protected-input routing
and guarded main activation connect these paths as described above.

Shared startup adds only an optional `shared` object containing `lastLoginName`
and `serverDisplayName` to the existing slots/cosmetics/new-workspace response.
Electron validates the exact fields, UTF-8 byte bounds and control-free strings,
and rejects shared metadata without an encrypted descriptor or with new-workspace
status. Local responses keep their existing shape. Description returns only slots.

Before any factor entry, native code reads the OS-protected anchor and bounded
slot container under the shared trust-file lock. A pending password journal supplies
its unverified candidate instead of the old active slots; malformed pending state
cannot fall back to ordinary hints. Native vault/file identity and sequence floors
still come from the anchor. Neither slot MAC, encrypted metadata nor the journal
is authenticated by this projection: the explicit native unlock/recovery path must
do that before network access. The descriptor's encrypted flag refers to the shared
encrypted container, not the reusable slot file's local SQLite migration marker.
No transport settings, trust records, policies, ciphertext or account keys cross
the startup response. If an owned shared profile disappears, startup fails closed.

Electron's native client now forwards shared admission and pending-password
recovery through explicit operations. Password and optional ASK use bounded byte
inputs and mutable stdin frames; input copies and frames are erased on completion,
failure, queue rejection or lock. Overlapping caller views are copied before
consumption so erasing the password cannot corrupt the ASK. Application version
comes from main, separately from factor input. Responses contain admission or
recovery metadata only, never a local-workspace unlock result.

The main host checks a fresh shared startup descriptor against the selected vault
and password slot, reserves authentication against overlapping attempts and
rechecks the caller and backend owner after asynchronous work. Failed or stale
requests close their captured backend. Admission does not activate local policy,
catalog access or the renderer's unlocked state. These methods are main-only.
Initial invitation input uses the separate protected `join-initial` route above;
remote password adoption remains pending.

The application now routes a selected shared profile to its own startup screen.
The application renderer requests only an admission or password-recovery dialog;
it never receives the factors. Main captures the originating document before the
startup read and invalidates it on navigation or renderer loss. A fresh, sandboxed
modal window owns the password and optional ASK input, with a separate ephemeral
partition, restricted preload, content protection where supported and no network
access. The dialog pins its operation, vault and password slot. Its main-frame IPC
checks run before submission and after completion. Cancellation erases borrowed
factors immediately and closes an in-flight backend before completing cleanup.

The input page accepts the ASK as 64 hexadecimal characters representing its 32
bytes. Both DOM fields are cleared before waiting, and typed buffers are erased
after IPC forwarding and again in preload cleanup. No factor enters application
state. Recovery explicitly asks for the new password of an interrupted change on
this computer; it does not implement another device's password adoption.

Admission displays a distinct acknowledgement and a protected-memory warning
when appropriate. An explicit sign-out uses the existing application lock path.
OS lock and application shutdown also cancel the shared dialog. This admission
transport does not mount a local workspace. The separate shared catalog and session
flows consume the admitted native owner; invitation onboarding has its own
protected input flow.

`PreparedInitialEnrollment.TakeDeviceAccount` now transfers the native account,
device-trust and local storage owners to `UnlockedDeviceAccount`. It verifies the
encrypted device metadata against the live identities and KDF/ASK facts first.
The operation copies no key material and retains no password or ASK. It consumes
the prepared request, wipes its verifier/payload buffers and permanently retires
the source preparation. Closing the retired preparation cannot close transferred
keys. Failed validation retains all original cleanup obligations; a failed release
after a successful transfer belongs to the destination and must be retried there.
Borrow, transfer and Close remain serialized native operations.

This transfer is not evidence that an invitation was redeemed: it also works
before dispatch, and never performs SQL, writes trust or grants admission.
Tests verify both request states, identity and derivation drift, corrupted device
storage, cancellation, closed owners and uncertain release. A real PostgreSQL test
prepares an account with an ASK, transfers it and verifies that the invitation
remains available. The application orchestration described above publishes an
independently protected initial startup selection before dispatch, reconciles
uncertain joins and persists verified active trust before exposing a shared
workspace.

New initial selections use format 3. Alongside the encrypted device container,
the independently OS-protected selection keeps the sealed connection setup and
pending enrollment. Both additional records require the password-derived device
trust root; OS protection alone cannot authenticate them. The snapshot contains
no password, ASK, invitation code, verifier, account master or private keys.
Format 3 also includes the sealed continuation described below. Existing format 2
snapshots remain readable and recover missing staging without invitation replay.
Canonical format 1 records remain readable and retain their original requirement
for complete ordinary staging files.

After password/ASK authentication, enrollment recovery can reconstruct missing
format 2 or 3 staging files under the trust-file lock. Existing files must authenticate
as the same device, connection and prepared capsule. Replaced, malformed,
redirected or conflicting state is preserved and rejected. Active trust and a
normal startup anchor have their own recovery: the initial snapshot cannot create
a new pending intent over them. Every restoration durably confirms the snapshot,
including after an earlier directory-sync failure with matching visible files.

Authenticated policy, account and TLS observations are mirrored to the initial
snapshot before updating the ordinary pending intent. Recovery compares complete
monotonic observations, including records several revisions apart, and restores
the newest intent before any remote proof. It never merges individual fields or
erases a previously observed revocation. An incompatible stronger policy can
prevent recovery while retaining its floor. Admission still needs a fresh native
device/capsule proof, active trust publication and ordinary online admission.
The recovery operation never authenticates with or resubmits an invitation.

Tests cover all eight combinations of missing staging files, wrong factors,
competing records, monotonic revocations, failed directory synchronization and
retry. A disposable real PostgreSQL fixture interrupts after commit and recovers
from four persisted prefixes; independent SQL requires exactly one Join audit,
a consumed invitation, a disabled temporary login and one confirmed device.
Missing files or failed device authentication cannot establish that a remote
transaction was never submitted. Ordinary enrollment recovery never retries it.

The native continuation primitive now preserves a prepared request separately
from its submission. `PreparedInvitationCommit.SealContinuation` stores a compact
password-root-encrypted record with the public invitation, original pending
certificate, device name, encrypted key capsule and encrypted key copies. It
stores each certificate/copy once, fits the existing bounded envelope format,
and retains no password, ASK, code, master or SCRAM verifier. Opening authenticates
the independent device binding, original certificate/capsule and all key copies
against the unlocked account master. It returns an opaque native owner, not an
executable mutation or admission authority.

`Session.ResumeInvitationContinuation` consumes that owner on success or failure.
It requires the separately delivered code again, applies authenticated policy
before opening a fresh temporary enrollment connection, authenticates a fresh
bootstrap and matches the original manifest and public certificates. Its mandatory
native callback must durably persist signed policy/account observations before
they are used or cause denial. A signed policy floor is retained even when its
API window prevents continuation; this observation grants no compatibility or
admission. Ordinary admission keeps its existing strict API-window checks.

If an authenticated TLS floor has already advanced, the native caller must supply
the exact current verified bundle from protected staging. Before SCRAM, the
continuation validates its organisation pin, sequence, digest and permitted hosts;
managed roots replace the invitation's historical CA. A missing, stale, foreign,
unobserved or incompatible bundle fails before connection. TLS still requires
channel binding, including the temporary enrollment login, and its borrowed login
proof is erased immediately after the open operation returns.

Only successful revalidation recreates a verifier from the unlocked master and
returns the original device/capsule/copy mutation. The method does not submit SQL.
The caller must confirm durable staging before one explicit commit, and reconcile
an uncertain result through fresh device/capsule proof. The existing single-use
server transaction rejects a second prepared continuation even when both passed
fresh revalidation before the first commit. A real PostgreSQL regression retires
the original native preparation, unlocks new owners, exercises that race, and
confirms the resulting device through the normal native proof.

The application builds the format 3 selection, device, transport and pending
records in a private sibling directory. OS protection binds the selection to its
final pathname. File data and names, any signed TLS cache, and the containing
directory are flushed before an exclusive atomic directory publication. The
parent publication is flushed before SQL. A pre-publication interruption exposes
no incomplete shared selection; existing selections are never replaced.

The protected recovery window offers an explicit invitation-code choice only
when native startup reports a format 3 continuation. Password/ASK and code pass
through the isolated preload to the fixed `shared-continue-enrollment` operation;
the application renderer receives only public admission flags and main's validated
transport mode.
The startup hint indicates stored capability, never proof of an unused invite.
Fresh code/certificate validation and durable staging confirmation precede one
single-use server submission. Confirmation and ordinary device admission then
publish the normal startup anchor and release account derivation roots. The
native operation has a five-minute overall limit and Electron allows its full
multi-stage budget.

Continuation never acquires discard authority over existing staging. A failed
proof, consumed invite, altered file, cancellation or uncertain remote result
preserves it for independent reconciliation. Only the still-live original owner
may discard its authenticated, never-submitted preparation. Cleanup checks native
filesystem identities and exact contents; unknown or replaced files survive.
Cleanup errors retain the owner and workspace lease until a confirmed retry.
Legacy format 1/2 selections cannot invent a missing continuation or code proof.

Tests exercise atomic publication, partial writes and durability errors, directory
replacement, cleanup retries, overlapping factor views, stale windows and timeouts.
Real PostgreSQL fixtures verify five interrupted prefixes, including before SQL;
the actual protected Electron continuation then reopens through ordinary device
admission. Independent SQL still requires exactly one Join and a confirmed device.
The live application matrix covers Default with Off, Encrypted and Verified TLS for both
initial Join and protected continuation, followed by ordinary device reopen.
The verified fixture enforces TLS server-side. An untrusted CA or hostname is
refused before local staging and leaves the invitation unused. A server CA replaced
without a trusted update also denies protected continuation, preserves the pending
selection and records no Join or device activation. Other profile/ASK matrices,
managed workspace-CA onboarding and deployment-wizard interoperability remain
separate roadmap work.

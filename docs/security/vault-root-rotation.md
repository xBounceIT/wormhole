# Native local root rotation

The native engine prepares a separately rotated vault, and a native controller
can publish it through an encrypted recovery journal. Interrupted transitions now
resume from application startup through a protected new-factor prompt. Existing
local vaults can initiate the transition from Settings > Security > Change vault
password and recovery key. For an OS-only local vault, **Protect now** starts
the isolated upgrade from the startup screen or the open workspace.
See [Local OS-only custody](vault-unprotected.md).

## Existing-owner enrollment

Main first holds application authorization and quiesces sessions, browser storage,
transfers and native protocol helpers while retaining the original Go vault owner.
Uncertain cleanup retires the owner and exits without automatically relaunching.
The dedicated sandboxed recovery window receives only current slot hints. The
ordinary renderer supplies no factors, paths, recipients or confirmation groups.

The user proves the current password or recovery code and chooses a replacement
password. Go verifies that current factor against the resident owner before
allocating replacement material. It immediately erases old-factor copies and
keeps only the new root and formatted recovery code in locked native memory.
An HPKE packet delivers the code to the protected window's one-use recipient.
Two randomly selected groups must be confirmed within five minutes. Wrong
current factors or groups have a three-attempt limit; cancellation and expiry
erase pending replacement material without publishing a transition journal.

After valid confirmation Go rechecks the exact source document, prepares the
rotated graph and journal, and refuses further ordinary service operations.
The input deadline is separate from the thirty-minute native preparation limit.
Main confirms native exit and restarts into the isolated new-factor continuation
described below. Cancellation before confirmation also restarts because sessions
have been quiesced. Neither the old owner nor prepared enrollment grants ordinary
application access after a potentially interrupted confirmation.

This path currently accepts protected local Default/Standard vaults. It changes
both password and recovery key and rotates the complete encrypted key graph;
it cannot be used for shared workspaces or as an OS-only upgrade exception.

The separate native `rotation-upgrade-context` / `rotation-upgrade-begin` path
requires an isolated maintenance launch and no resident source owner. It provides
only a vault-ID hint and accepts only a replacement password and display public
key. It rechecks the source, pending journals and selection after acquiring the
workspace lease. No old OS factor or source database is opened until the user
confirms the two new recovery groups through the shared confirmation operation.

After confirmation, a one-use `UnprotectedRootUpgrade` scope authenticates the
OS-only source and its stored policy solely for forward staging. It validates the
protected target against current policy before and after the graph rewrite;
ordinary `Open` continues to reject an OS source that cannot satisfy Standard.
The scope returns no ordinary Owner and retains even partial root/store allocations
for cleanup retry. Keys are consumed before database IO, and close joins in-flight
input consumption. Confirmation holds workspace ownership through native exit and
then uses the existing new-factor journal continuation. Tests cover an authenticated
Standard user floor without changing this host's machine-managed policy.

## Native staging and recovery

The owner authenticates the current slot document, policy, catalog and known
rollback floors, then freezes its mutex for the entire stage lifetime. It rejects
active browser/import/transfer capabilities and known cleanup failures. A separate
native file reservation receives a consistent SQLite ciphertext snapshot; an
existing file is never overwritten or repaired.

The snapshot codec accepts only the supported schema and key graph. It derives
column shapes from the same embedded versioned DDL used by initialization and
migrations. Unknown tables, views, triggers, columns, key families, ownership or
resolver/header versions cause refusal. Native fields are read individually with
bounds; the database is not accumulated as an in-memory export.

One target transaction installs a fresh root version, independently generates a
new DEK for every current secret and rewrites every encrypted value and key copy.
It authenticates and reseals credentials, nodes, tunnels, local state and policy,
including deleted records, removed-field tombstones and standalone fields. Domain
revisions, configuration versions, field manifests and migration provenance remain
unchanged. Historical copies and retired keys are removed. The target uses secure
deletion, a ciphertext rollback journal truncated at commit and VACUUM compaction.
It switches the finished target back to DELETE journal mode before publication.
Any transaction failure rolls back the target; the original vault is unchanged.

A separate read-only pass authenticates the complete result with the new root.
Retained SSO archive headers, known revisions and deletion floors are checked;
archives survive rotation without changing their binding or payload. Authenticated
source observations remain in the old owner even when a later check rejects the
rotation. The native controller must checkpoint those observations before denial.

The stage returns a detached authenticated slot document with the new password
and recovery slots, root version, slot sequence and file epoch. Four slot
sequences are reserved: three source barriers precede the final new-root document.
The caller must
have confirmed those factors before preparing the stage. A native-only recovery
envelope can wrap the old root under the new root, with both complete slot
documents bound to its authenticated context. No plaintext root is serialized.

The source stays frozen until the stage is closed. Closing an unpublished stage
allows the unchanged original to continue unless the controller has already
closed its databases for durable fingerprinting. In that case closing the stage
also retires the resident owner, including on failure; the unchanged original
files remain unlockable after restart. Explicit source retirement closes its
store, runtime capabilities and native key memory; the controller may call it only
after durable target and recovery-journal preparation. This method deletes no
database, slot or OS key. Failed target cleanup remains an error on later close
attempts and requires service retirement.

The controller retains the caller's workspace ownership throughout preparation
and recovery. It closes both databases while keeping the source write lease and
root, flushes and fingerprints the exact closed files, and atomically publishes
a new-factor bootstrap plus encrypted native journal. Private paths, source/target
documents, fingerprints and the source-recovery envelope stay inside that journal.
Its decoder bounds the envelope count before allocating the unauthenticated
array and rejects noncanonical, duplicate or case-aliased JSON.

An authenticated v3 source-slot marker blocks ordinary opens, reauthentication,
checkpoint writes and slot updates. A journal routes startup to recovery even
before that marker exists. A missing journal cannot bypass a remaining marker. The new
password/recovery document authenticates journal recovery; the old database is
never opened during resume. V1/v2 readers remain supported by the v3 decoder, and
ordinary SSO updates continue to use v2 unless the vault is already v3.

Prepared, retiring and publishing phases advance through separate journal and
source-barrier writes. Recovery rejects an older journal than the source barrier.
It authenticates every present copy before advancing and audits all target values
with the new root. Root-relative no-replace moves preserve the old source until
the target is verified. Native link/unlink crash duplicates are accepted only
with the expected file identity and fingerprint. Unrelated copies are preserved
and cause refusal. Old-copy removal precedes final slot publication; journal
removal comes last. A lost final acknowledgement authenticates and audits the
published new epoch again. Protected sources keep their v1 journal. An exact
single OS-only v3 source uses a v2 journal and a distinct encrypted custody record;
the database retiring phase never substitutes for an OS-deletion receipt.

The custody record binds the canonical source and slot identity, native platform,
bounded original factor ciphertext and its length/digest. A durable intent must
precede platform-key deletion. A key-retired receipt follows the checked native
adapter acknowledgement; a file-retired receipt follows exact rooted-file removal
and directory sync. Windows never deletes the OS DPAPI master key: its platform
step has no Wormhole-owned key, so exact ciphertext-file removal retires custody.
Keychain/Secret Service require explicit not-found acknowledgements and reject
unavailable stores or substituted keys. Receipts and absence are rechecked before
publication. An absent file/key without a prior authenticated intent cannot
authorize retirement. Interrupted deletion resumes with new-root escrow, without
reopening the lost old OS factor. An unacknowledged journal write cannot leave an
in-memory intent that authorizes deletion on retry.

Startup projects only the new v3 slot descriptors and a pending-rotation flag.
Before Chromium readiness, the native startup probe selects an isolated profile.
The application can open a protected factor window; it cannot submit paths,
recipient keys, quiescence or factors through the ordinary resume IPC. Main
captures the operation and descriptor, admits only one request at a time, and
publishes app authorization after the backend owns the completed new epoch.
Cancellation or loss of document trust retires an adopted owner before another
session can use it.

The native resume operation requires the isolated maintenance launch, authenticates
new factors before opening any database, and keeps the borrowed root in locked
memory. It acquires workspace ownership before factor opening and retains that
ownership with the published owner. Failed temporary-memory release is retained
as a cleanup obligation: shutdown retries it and cannot release workspace exclusion
until cleanup succeeds. Cancelling an in-flight resume retires the service.

Tests use real SQLite and native AES/HMAC/Argon2id to reopen the target with the
new password, reject the old root, preserve live/deleted domains, multichunk state,
SSO and provenance, and exercise rollback, stale facts, malformed callbacks,
unknown schemas, cancellation, ownership and cleanup quarantine. Storage-only
fixtures use opaque synthetic ciphertext and are not cryptographic evidence.
Controller tests interrupt every durable publication boundary and resume using
real SQLite and cryptography, including missing source windows, authenticated
duplicates, tampered files/journals, stale phases, cancellation and locked slots.
These are deterministic interruption tests; they do not emulate a power failure.
An end-to-end Electron test also runs the actual startup probe, isolated Chromium
profile, protected prompt and Go backend through cancellation, a wrong password
and successful publication. Random roots remain in Go and encrypted files.
Existing-owner tests create a native vault in its real protected window, then
enroll replacement factors through the compiled root setup preload and renderer.
They verify confirmation, cancellation, parent navigation and adoption after
restart with the replacement password. Transport tests also pin stale replies,
concurrent operations, buffer ownership and uncertain cleanup. With Windows DPAPI,
the Electron test also opens an OS-only workspace, requests **Protect now**,
confirms the recovery groups and verifies retirement after restart.
The new isolated enrollment and forward-admission tests use real crypto/SQLite,
prove ordinary source opening stays denied and preserve the stored Standard floor.
Additional native tests interrupt every OS
retirement boundary, exercise missing/unavailable/substituted custody and verify
that the new root preserves the secret graph after old-factor removal. Windows
uses real DPAPI; portable failure seams model loss between deletion and receipt.

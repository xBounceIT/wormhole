# Native vault Bitwarden browser storage

This native Go storage component is a prerequisite for issue #495. It is not yet
connected to the Bitwarden extension in the application. Vault web browsers still
skip the legacy extension reader. Sealed extension transport and the exact-document
endpoint are implemented. Protected extension hosting, installation/settings, Chromium
lifecycle wiring and actual extension relock remain open. See the
[transport and hosting requirements](vault-bitwarden-transfer.md).

## Ownership and data flow

The local vault owner now provides `ReadBitwardenBrowserState`,
`CaptureBitwardenBrowserState` and `CloseBitwardenBrowserProfile`. They are native
Go APIs, with no ordinary renderer or general IPC endpoint. A borrowed snapshot
cannot be JSON-marshalled: its marshaler rejects the operation. Its native consumer
must seal its bytes to the owning extension before exposing a transport result.
Input buffers are consumed on every return path; borrowed output bytes are wiped
when the callback returns and must not be retained or modified.

Hydration requires the extension's actual local/session capture as a witness. A
revision marker alone does not prove that a restarted background still has its
state. The owner returns the shared desired snapshot and keeps an encrypted base
of what the context actually supplied. After conditional restore, the controller
must capture the resulting state to acknowledge what really applied.

Captures merge changed top-level keys against that context's actual prior capture.
Concurrent shared values win conflicting refreshes. Explicit deletion wins over a
simultaneous token refresh. The owner never treats its outgoing desired snapshot
as an already-applied base: a failed conditional restore can leave newer stale
tokens in Chromium, and that must not make them appear to be a new login later.

The logical revision advances for either local or session changes. A successful
result reports the accepted revision for its next capture. Failed delivery keeps
the prior context base for retry, while preserving already committed shared state.
The sealed transport binds receipts to their native owner lifetime and
browser/context identities, as well as their revision.

## Persistence and volatile state

Local state uses the existing authenticated `LocalState`/`SecretValues` chunk store
and workspace scope `bitwarden-browser`. Its record remains compatible with the
migrated legacy primary record (`SchemaVersion`, `Revision`, `LocalJson`). Malformed,
duplicate, unknown or invalid records fail closed. The separately archived legacy
backup remains intact; this component does not silently select it as a fallback.

Only local JSON changes write a new durable record. Session-only bookkeeping does
not create or rewrite persisted account/vault snapshots. Runtime revisions may
therefore be newer than the last durable revision. A new owner starts from that
durable revision with empty session state; a runtime revision is not a persistent
rollback checkpoint across owner restarts.

Shared session state and per-context merge bases stay encrypted in owner memory.
They use the existing AEAD primitive and a distinct HKDF purpose,
`wormhole/v1/browser-state-stage`. Each chunk is bound to workspace, file, cache
identity, profile/workspace scope, area and chunk index. Moving a cache between
profiles or between local/session areas fails authentication. Closing a profile
wipes its encrypted bases; closing the owner wipes all volatile caches and retires
the root key through the existing lifecycle.

Every operation re-authenticates local policy and the current OS floor. The
current owner supports Default and Standard; unsupported Hardened/Paranoid
protection remains rejected by the existing security gate. Empty session JSON on
cold start alone is not proof that a real Bitwarden extension has relocked; the
native extension adapter must implement and verify that behavior.

## Bounds and verification

Each JSON area is limited to 8 MiB and 65,536 top-level keys. Invalid UTF-8,
non-object JSON, duplicate decoded keys and trailing input are rejected. Numeric
values retain their exact JSON representation. Encryption uses chunks no larger
than the existing 4 MiB secret limit.

The owner retains at most 32 context bases and 64 MiB of encrypted cache payload
and nonces. This is a retained-cache budget, not a bound on the process's transient
parsing/crypto allocations. Capture admission checks both the successful result
and the state retained if acknowledgement fails; it cannot spend memory that would
only be freed after successful delivery.

Tests use protected temporary SQLite workspaces and synthetic data. They cover
cold restart, absence of session bytes on disk, consumed/borrowed buffer erasure,
concurrent edits, stale refresh after logout, partial restore and rehydration,
explicit new login, failed acknowledgement, policy floors, persistence failure,
malformed migrated records, revision limits/regressions, chunk authentication and
substitution, exact large numbers, maximum payloads and retained-cache capacity.
These tests do not establish actual Bitwarden login, relock or extension-version
compatibility. The sealed native transport and synchronization coordinator now have
separate interop coverage; installed-extension application integration remains open.


## Authenticated installation metadata

The native owner provides `ReadBitwardenInstallation` and
`SaveBitwardenInstallation` for a workspace-scoped, encrypted and authenticated
installation record. It contains the enabled flag, a canonical installation UUID,
the extension ID and a content SHA-256 digest. It contains no arbitrary filesystem
path. Initial absence disables the extension; an authenticated disabled record keeps
its revision. Observed deletion/rollback, tombstones, malformed records and failed
policy authentication reject access rather than importing legacy settings.

Writes use the existing atomic LocalState revision check and require all native
Bitwarden transfer stages and browser profiles to be retired. Reads retain an
owner-lifetime revision floor and accept a caller's minimum revision. This floor is
not a persistent anti-rollback checkpoint across owner restarts.

The native folder mutation and verified read-only plan operations are described
below. Application settings and picker integration remain unfinished. The installation controller must verify the actual installed content and
authorize the action before saving this record; a caller-provided digest alone does
not prove trust. Protected extension hosting and the complete application lock
lifecycle remain required before native vault browsers can enable Bitwarden.


The native content verifier now reads the selected installation UUID beneath a
native-owned `os.Root`, rejects symlinks and nonregular files, and checks an exact
content digest. Its versioned encoding binds file/directory types, UTF-8 paths,
lengths and bytes. This digest is distinct from legacy directory and ZIP hashes.
It requires `manifest.json`, rejects ambiguous case/path names, and bounds total
bytes, path depth/length, entries and directory-read batches. File changes and
filesystem errors reject verification without publishing paths or file contents.

This pre-load integrity check is not an extension-manifest compatibility check,
a signed publisher provenance check, or protection against same-user malware
changing files while the application is unlocked. The native controller connects these checks to the authenticated record. Application
loading must still connect its verified plan to the exact-document endpoint.


A native controller now activates an already prepared UUID package only after
checking its manifest, deriving its extension origin and hashing its files. The
CAS write of the authenticated installation record is its commit point. It rejects
replacement of the current directory, stale revisions and active transfers/profiles;
preparation and explicit mutation authorization remain responsibilities of its caller.

The Go service's main-only `bitwarden-installation-plan` operation binds the unlocked
workspace and a minimum revision, reauthenticates the record and verifies the current
package before returning its UUID, origin ID, version, popup and background page.
It returns no arbitrary paths, hashes, keys or storage contents. Disabled initial
state returns no installation. The typed Electron client snapshots requests and validates exact bounded response
metadata. Its host rejects results after the captured backend, workspace or caller
authority changes. No renderer IPC accepts workspace or revision inputs for this operation. The
pathless settings read uses the current native workspace. Automatic downloads and protected Chromium hosting remain unfinished.

Origin derivation follows Chromium's
[`id_util.cc`](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/crx_file/id_util.cc):
the manifest key bytes, or the normalized native installation path when no key is
present, determine the extension ID. This identifies an origin; it does not establish
the package publisher's signature. Actual platform runtime interoperability remains
part of the forthcoming native loading integration.


## Native folder installation

The Go service now exposes a main-only `bitwarden-install-folder` operation. It
binds the selected absolute source directory, workspace and expected revision. At
Standard it requires fresh authentication for that exact action; the previous unlock
does not authorize the mutation. Cancellation retires the service operation.

Go validates the source package and hashes its contents, copies bounded regular
files into a new staging directory, syncs and publishes that directory without
replacing an existing target, and compares the final contents with the source digest.
The authenticated record update is the commit point. Existing installations remain
intact. Failed stages are removed only when ownership is confirmed; files potentially
referenced by an uncertain commit are retained for subsequent authenticated inspection.

The typed main-process client snapshots and validates the folder-install request and
requires an exact next-revision receipt. The host captures the original backend and
workspace, checks caller authority before and after the operation, and uses the
protected fresh-authentication dialog contract at Standard. Authentication factors
are wiped on rejection and completion; the dedicated dialog names the installation
action. No renderer IPC accepts an installation path. The zero-argument
`vault:bitwarden-install-folder` channel opens the coordinated native folder picker,
requires the current trusted main document and authorization epoch, and delegates
to the host. The host serializes selections and captures its original backend,
workspace and authenticated revision before opening the picker. Cancellation makes
no mutation; lock/reunlock, navigation or backend replacement invalidate the choice.
A successful mutation is followed by a content-verified installation plan.

This implements native folder installation and its client/host contract, including
the native picker and settings panel. In encrypted workspaces the
Extensions settings tab reads authenticated public package metadata and offers the
native folder selection; it does not show the legacy CLI/extension controls. Lock
unmounts the panel and late reads or mutation results cannot update its replacement.
A pathless read channel shares the same document/epoch lifetime guard as installation.
If installation acknowledgement fails, the panel clears its displayed version instead
of claiming the previous package is still current. Automatic downloads and extension
hosting remain unfinished. Obsolete package retention and interrupted
staging recovery still need lifecycle work. Platform publication adapters are present;
Windows tests do not establish macOS/Linux execution or power-loss recovery behavior.


## Native ZIP import

The pathless `vault:bitwarden-install-zip` UI action uses the native file picker.
Go receives an exact fresh-authenticated `bitwarden-install-zip` action at Standard,
with the source file, workspace and expected revision bound together. Folder and ZIP
choices share the same host selection guard and document/authorization lifetime.
The settings panel offers both formats; neither activates an extension runtime.

Only bounded single-disk ZIP32 packages with stored or deflated entries are accepted.
Archive and expanded contents are capped at 512 MiB; the central directory is capped
at 32 MiB and validated before the standard ZIP reader allocates its entries. A
private snapshot of the central directory and end record prevents concurrent source
metadata changes from replacing those bounds. Traversal, nonportable paths, links,
other special files, encryption and duplicate/case-colliding names are refused.

The archive filesystem feeds the same bounded hash/copy/publication pipeline as
folder import, including exact sizes, native-confined file creation, final digest,
manifest validation and authenticated revision CAS. There is no second extraction
root or plaintext credential storage. Invalid archives leave the active installation
unchanged; uncertain commits preserve possibly referenced packages. Interrupted-stage
and obsolete-package cleanup, downloads and protected hosting remain unfinished.


## Repairing missing or damaged packages

Picker preflight uses the main-only `bitwarden-installation-revision` operation.
It authenticates the workspace policy and installation record and returns only the
workspace and revision; it makes no claim that old package files are usable. This
allows folder or ZIP replacement after files have been removed or corrupted. The
normal installation plan continues to reject such files, and the replacement still
requires action authorization, full validation, revision CAS and a verified new plan.
There is no revision-only renderer channel or extension-admission fallback.


## Database-scoped package directories

New installations use `vault-bitwarden-installations/db-<sha256(database basename)>`
beside the database. The encrypted installation record uses version 2 and layout 1;
version 1 records retain their original shared-root interpretation. Unknown layouts,
inconsistent record versions and noncanonical encodings are rejected. Replacing a
legacy package commits the scoped record only after the usual package verification
and CAS, and preserves the old shared directory.

The basename namespace separates databases in the same parent directory and survives
moving that parent together with its contents. Renaming a database (including using a
different spelling through a filesystem alias) requires package repair if its scoped
assets are not at the new expected location. There is no search or fallback into a
shared or neighboring database directory. The revision-only repair flow remains
available when the files are missing. Directory names and layouts remain Go-owned.

This layout is a prerequisite for package lifecycle cleanup, not authorization to
delete directories. Obsolete and interrupted packages remain retained until an
authenticated ownership/retirement protocol is implemented; legacy shared packages
must never be collected based only on UUID-shaped directory names.


## Authenticated retirement journal

Replacing a database-scoped package now records its previous ID in the same
encrypted CAS that selects the new active installation. Records with pending retired
IDs use version 3; version 1 and 2 records remain readable. The public installation
plan still returns only the current package and revision. Legacy shared-root IDs
are never added to the journal.

The journal accepts at most 64 distinct canonical nonzero UUIDs and cannot contain
the current package. A retired ID cannot be reactivated. Disabling the current
package while preserving its ID does not retire it; clearing or replacing that ID
does. Replacements that would exceed capacity fail without modifying either the
active record or its journal. Records remain bounded to 4096 bytes and are validated
again after restart; malformed authenticated records cannot be silently overwritten.

The native `bitwarden-cleanup` operation accepts only workspace and expected revision.
It reauthenticates the full record while holding the owner lock, rejects active
profiles/transfers and removes only journaled IDs through the database-scoped root.
It never enumerates directories to infer ownership. Shared and unjournaled packages
are preserved. Standard requires fresh action authentication; cancellation retires
the serving native process if the action cannot finish promptly.

Missing retired directories are safe to retry, but their parent is still synchronized
through the platform durability adapter before acknowledgement. An unexpected file
or link, unavailable root, cancellation or partial deletion preserves the journal.
Only after all removals succeed does one CAS clear it, preserving the active package.
A lost CAS acknowledgement is safe whether the cleared or original journal survives.
Even an empty cleanup advances the revision once, keeping the mutation receipt exact.

The unlocked native settings panel exposes “Clean old packages”. Its pathless preload
and main-process IPC accept no renderer arguments, bind the initiating main document
and authorization epoch, and invalidate on navigation, renderer loss or destruction.
The host captures its original backend/workspace, authenticates the current revision,
serializes cleanup against package selection, and requests fresh confirmation when
required by the security profile. The client consumes and clears the factor. A
successful cleanup preserves the displayed installed version; failures show a fixed
message without native details, and retired UI lifetimes ignore late results.
Interrupted staging is reconciled using the authenticated intent described below.


## Interrupted installation intent

Before creating a new stage, native folder and ZIP import persist one encrypted
`bitwarden-install-intent` record scoped to the workspace. It binds the generated
package UUID, database basename namespace, expected installation revision and phase.
It has its own CAS revision, so phase updates do not consume the installation revision
expected by the client. Canonical records are bounded to 1024 bytes; an observed
rollback, malformed record or tombstone fails closed. A pending intent cannot be
silently replaced by another import.

The installer confirms `prepared`, then `created` after stage creation and directory
synchronization, then `published` after the no-replace publication and synchronization.
Normal completion reconciles and clears the intent after the existing file cleanup
or active-record commit. An authorized cleanup or the next import also attempts
reconciliation, under the owner lock and without active browser profiles/transfers.
The serving protocol serializes complete operations, including filesystem copying.

Recovery only removes a stage confirmed as created when there is no final directory.
A confirmed published final directory can be removed only when it is neither active
nor recorded as retired. Active and retired packages are preserved. Missing directories
are synchronized before clearing intent; errors and cancellation keep the record.
A prepared intent with existing files, a created intent with a final directory, or a
published intent with a new stage are uncertain outcomes: files and evidence remain
untouched. The implementation does not infer ownership from a UUID or stage prefix.
Thus a crash between a filesystem operation and its phase acknowledgement can require
manual reconciliation; it is not silently treated as an empty or disposable package.
A database namespace mismatch, including a rename, also preserves the intent and files.

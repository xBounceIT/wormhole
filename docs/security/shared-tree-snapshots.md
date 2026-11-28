# Shared tree snapshot transport

Migration `0017_tree_snapshot.sql` upgrades exactly schema 16 in a transaction
under the workspace migration lock. It adds the complete `NodeMetadata` field
set, boundary and Ed25519 seal references, and reserved encrypted-metadata
columns. Runtime roles receive no table writes. Enrollment roles receive no
access to the new tree endpoint.

`get_tree` requires an audited device capability. It returns only nodes with
View, ordered by UUID, in pages of 1–32 nodes. NULL inheritance values, explicit
false/empty/zero overrides and 64-bit sort order survive the projection. No
passwords, private keys or ciphertext secret fields belong in this projection.

The first page carries workspace identity, user identity, epoch, change sequence
and resolver version. Continuations bind to that epoch and sequence. Statement
triggers on nodes, grants, groups, group membership and users increment the
sequence before writes and issue a transactional notification containing only the
workspace UUID. A reader holds a shared workspace lock for its transaction;
contention fails promptly. A changed snapshot requires starting again, rather
than combining pages from different permission or hierarchy states.

`Session.TreePage` uses a fixed parameterized query and the existing bounded
native transport. It checks identity, versions, ordering, permission bits,
boundary and signer references, signature length and complete typed metadata.
Duplicate, missing and case-aliased JSON fields are rejected. Invalid responses
retire the connection. Temporary capability encodings and wire buffers are wiped.

The return type is deliberately `UnverifiedTreePage`: the transport does not
verify signatures, writer authority, key boundaries or persistent revision
floors. It cannot authorize a connection or secret release. Provisioning and
signed mutation APIs are still required. Unprovisioned seals fail closed;
encrypted metadata also fails closed until its dedicated reader exists. Reserved
columns do not implement the Paranoid profile.

The separate `UnverifiedTreeNode.VerifyMetadata` operation verifies a full
metadata seal through `internal/sharedcatalog`. Its caller must supply trusted
workspace/node/boundary identity, author key binding, organisation signing key
and certificate/node revision floors. These inputs must come from authenticated
key-graph state and persistent client state, not from the page being checked.
`UserKeyCertificate` binds the author's Ed25519 key to the pinned organisation.
The caller must additionally establish current key status and revocation; a
historical certificate alone is insufficient. This operation does not certify
the database permission mask, page completeness or authority to release secrets.

`VerifyCurrentMetadata` additionally verifies `UserKeyState` against the pinned
organisation and the author's stored sequence floor. It requires an active state,
uses its signed signing-key selection, and applies the larger of the signed and
stored certificate floors before checking the node. A revoked state is rejected
even when its historical certificate and node signature remain valid.

This operation returns authenticated revision observations alongside its error.
A valid revocation returns its sequence even without a certificate; an invalid
state returns no observation. A valid certificate may advance its own revision
even if the node fails verification. The owner must merge these observations
durably before publishing metadata, including on rejection. State sequences are
scoped to the author, certificate revisions to the selected key reference, and
node revisions to the node. These are distinct namespaces.

`TrustState.AdvanceCatalog` authenticates the observation and merges these floors
into the existing encrypted device trust record. Each entry also retains a
SHA-256 digest, rejecting different signed content at the same revision. Writers
cannot delete or lower existing entries. Updates to policy, TLS, account state,
enrollment and password-root transitions preserve the catalog floors. A revocation
of the logged-in author also updates the login account anchor.

`acceptSharedCatalogObservation` persists the updated record before returning
either accepted metadata or an authenticated revocation error. It uses the
existing exclusive lock, expected revision and atomic writer; an uncertain write
requires authenticated confirmation and successful synchronization. Storage
failure blocks publication. Records contain up to 8192 combined author/key/node
entries and have a 2 MiB encrypted size limit; exceeding a bound fails closed.
The startup anchor size allowance includes this bounded state. These are local
rollback floors, not a hardware monotonic counter: restoring the entire device
state and its external anchor remains outside this guarantee.

After catalog persistence, `refreshSharedCatalogAnchor` can advance the
OS-protected startup trust revision using the controller's native root. It works
after the password-slot owner has closed. It authenticates the exact expected
trust file under the workspace file lock, requires an existing valid startup
anchor, preserves slot selection and transport, and refuses rollback or pending
enrollment/password transitions. Equal-state writes confirm durability without
incrementing the anchor revision. Missing protection, cancellation or uncertain
synchronization cannot produce a successful refresh. The catalog controller must
complete this refresh before publishing its first verified metadata page.

Migration 18 adds `node_author(capability,node,epoch,change_seq)`. It requires View
and the exact tree snapshot, returning the node signer's public certificate and
organisation-signed account state. Hidden and missing nodes receive the same
refusal. Keys and account-state writes now also invalidate the tree sequence.
An absent certificate produces a state-only result, so authentic revocations
remain observable. This endpoint never returns account capsules or private-key
material. Its opaque signed-state bytes still require client verification.

Native `Session.NodeAuthor` bounds and validates the response, binds it to the
requested workspace/node/snapshot, and retires the connection on malformed data.
Its `UnverifiedNodeAuthor` result is suitable for the separate current-metadata
verifier; fetching does not authenticate it.

Native `sharedAdmissionController.CatalogPage` now connects these steps. It requires
an unlocked owner, checks fresh signed account state, obtains the page and each
author at the same snapshot, authenticates metadata and accumulates observations.
It writes one aggregate local revision per page, confirms the OS-protected anchor,
then returns display metadata only. Authenticated observations are persisted even
when a later row fails or revocation denies the page; partial pages are never
returned. A changed account key selection retires the owner because its resident
private keys belong to the previous selection.

The operation shares the controller gate and lifetime cancellation. Read,
verification or persistence failure retires the owner; retry currently requires
fresh admission, including after a stale tree snapshot. Lock cancels an in-flight
read and waits for deterministic cleanup. This native operation is not yet exposed
through the app service or renderer and does not authorize protocol connections.

Shared node seal suite 2 signs the UTF-8 bytes
`wormhole/v1/shared-node-metadata` followed by NUL and the Go typed JSON encoding
of `{workspaceId,boundaryId,suite,metadata,seal}` in that order. `metadata` is the
complete `NodeMetadata` projection in its declared field order. `seal` contains
format version, signer reference, revision and a NULL signature; capability ID is
currently required to be NULL. Explicit NULL inheritance is retained. The signer
then attaches the Ed25519 signature. The separate domain rejects signatures made
for the older routing-only `ResolutionRecord`. Changing this representation
requires a versioned format transition. Local HMAC seals are unchanged.

The `shared-catalog` application service now exposes verified pages through a
typed Electron client, admitted-session host gate, trusted-document IPC and
preload. It returns only nine display fields after native signature verification
and durable trust publication. Epoch, change sequence and sort order use decimal
strings to preserve 64-bit precision. Requests contain exactly `after`, `epoch`,
`changeSeq` and `limit`; continuations bind to the previous snapshot. Owner loss
discards the result; native read failure retires the session.

After shared admission, the startup screen displays the verified catalog one page
at a time. Next page retains the snapshot cursor; Refresh starts a fresh snapshot.
Only the current page is held in the list. Errors, sign-out and page disposal clear
its DOM contents, and late responses cannot restore them. Server-provided strings
are rendered as text, never as markup or executable links.

Migration `0019_catalog_changes.sql` adds `get_changes_since(capability,epoch,seq)`.
The capability must belong to an admitted device. It returns one consistent header
and up to 32 changed node IDs filtered by current View permission. These are
invalidation hints only: callers must retrieve and verify signed metadata before
publishing changes. Empty responses retain a header with a NULL node ID.

The private journal coalesces repeated writes to each node and holds at most 4096
entries after each statement. Overflow, more than 32 visible changed nodes, or a
cursor predating a reset requires a fresh snapshot. Deletions, permission/group/
user/key changes, and changes to node identity, parent, kind or personal owner
invalidate the whole snapshot, exposing no removed or hidden node IDs. Journal
updates, sequence changes and NOTIFY hints commit or roll back with the write.
The workspace row lock prevents readers from observing incomplete changes.

`Session.ChangesSince` validates identity, resolver, numeric bounds, header
consistency, ordering and reset semantics. Invalid responses retire the native
session. The admission controller revalidates the current signed account state
before fetching hints, persists any newer state and refreshes the protected startup
anchor before returning. Revocation or resident-key replacement retires the owner.
The shared page and change paths use the same lifetime, trust and cleanup gate.

The application calls `shared-changes` after admission and then polls every 30
seconds after each completed read. Only one page or polling request runs at once.
Unchanged results preserve the current page; a changed sequence, reset or changed
node reloads a fresh, verified first page. Errors and disposal clear the display
and stop polling. Every IPC request is bound to its originating main document and
admitted backend owner.

When the native change policy selects LISTEN, the existing second connection is
subscribed before admission completes. The TLS monitor also handles deployments
without a signed TLS bundle and coalesces hints at one-second ticks. Only hints
matching this workspace mark the catalog dirty; they carry no trusted metadata.
An unlocked owner emits the bounded stdio event
`{"version":1,"id":0,"event":"shared-catalog-changed"}`. Events do not complete
pending requests or reset the heartbeat deadline. Electron accepts only this exact
payload-free event and forwards it to owned application windows. The renderer
queries authenticated changes immediately, retaining one pending refresh when a
read is already running. Disposal removes the listener. Periodic polling remains
active even with LISTEN, covering lost or withheld hints. Transaction-mode poolers
and native policies above 300 concurrent devices select polling without LISTEN.

The editable workspace tree, committed use tickets and secret release remain
separate work. This catalog view does not authorize connection actions and never
falls back to the local catalog.

Regression coverage includes real PostgreSQL migration rollback/replay and ACLs,
View filtering, native first/continuation pages, empty pages, snapshot
invalidation across every relevant table, lock contention, encrypted-metadata
rejection and malformed server responses. Unit tests exercise parser boundaries,
numeric precision, duplicate fields, invalid cursors and session lifecycle.

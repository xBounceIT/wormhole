# Provisional connection resolver v1

The local vault and the shared PostgreSQL workspace implement resolver v1 for
issue #495. The local owner uses `internal/resolver`. PostgreSQL computes the
shared release plan and the Go client verifies it against signed catalog
records. Legacy connection paths record the effective credential and run the
Go resolver in shadow mode. Migration pins a changed path to its previous
choice until the user selects the new result.

## Inputs and trust

`Resolve` takes a complete leaf-to-root sequence of node metadata, with at most
128 entries, and an optional explicit credential override ID. Every node has a
canonical UUID and valid metadata; the leaf is a connection, all ancestors are
folders, parent links match the supplied sequence, the terminal root has no
parent, and duplicate IDs fail. A missing ancestor is an error, never a partial
resolution. At least one node must explicitly provide a supported protocol.

The pure resolver verifies shape and computes choices; it does not authenticate
records, grant permission, read storage or decrypt anything. Its result is not a
capability. The owner authenticates each node and selected credential/tunnel
before allowing a native consumer to borrow plaintext. Shared mode must also
verify membership, capabilities and effective Use/Reveal grants, including Use
on the selected credential boundary for an override. In a shared workspace the
client verifies the signed slot, its per-user assignment when present and the
selected credential. Credential slots require a shared workspace.

## Inheritance and identity

Traverse from the connection toward the root. NULL inherits; an explicit false,
zero or empty string stops inheritance for that property. Trim surrounding
whitespace from resolved textual values. An explicitly empty host is invalid;
it does not fall back to a different host higher in the tree.

Credential selection uses the first applicable choice:

| Condition                      | Choice and boundary                                                                      |
| ------------------------------ | ---------------------------------------------------------------------------------------- |
| Inline enabled on the leaf     | Leaf inline password; stop identity at the leaf; SSH, SFTP and RDP only                  |
| Mode 0                         | Continue; ignore any legacy CredentialId on this row                                     |
| Mode 1                         | Stop credential inheritance with no stored credential; identity may continue             |
| Mode 2                         | Select CredentialId; stop identity above this row                                        |
| Mode 3                         | Select CredentialSlotId; stop identity above this row; catalog resolution still required |
| NULL mode with CredentialId    | Treat as saved mode 2                                                                    |
| NULL mode without CredentialId | Continue                                                                                 |

Read Username and RdpDomain from a row before applying its identity boundary.
The nearest non-NULL values at or below that boundary win. After a saved
credential is authenticated, its username/domain fill empty resolved components.
An explicit credential override replaces any inline/saved/slot choice and owns
both username and domain; connection identity is not combined with the override.
The chosen credential's protocol must match the connection. The provider-backed
Bitwarden path needs a later native identity/secret lookup; this implementation
refuses plaintext release from a provider-backed record.

## Protocol, port and route

The connection protocol is its nearest explicit protocol. A port or inherited
credential has the protocol context of the row where it was selected, looking
upward from that row. When that context differs from the connection, discard the
port/credential choice; do not search for another credential above its boundary.
SSH and SFTP share one protocol family for these two comparisons. A missing port
context imposes no additional restriction, but credential metadata must still
match the resolved protocol.

Zero or absent port chooses 22 for SSH/SFTP, 3389 for RDP, 80 for HTTP, 443 for
HTTPS and 5900 for VNC. Serial has no network port or stored credential. Endpoint
normalization and protocol-specific host/path validation remain mandatory in the
launch adapter; this metadata plan is not a network connection request.

TunnelEnabled and TunnelConfigId inherit independently. False disables the route;
true without a tunnel ID fails. A serial connection with an effective enabled
tunnel fails rather than silently discarding the requested route. The owner must
authenticate the selected tunnel even when releasing a connection credential;
it never substitutes a direct connection if a configured tunnel is unavailable.

The nearest non-NULL SSH host-key fingerprint and auto-sudo preference apply to
SSH/SFTP only. HTTPPath inherits for HTTP(S). Ignoring certificate errors is
HTTPS-only and requires the leaf's explicit true value; a folder cannot enable it.

## RDP gateway and system client

Gateway method, hostname, same-credentials flag and credential ID inherit
independently. Method 0 disables gateway credential use. Method 1 requires a
nonempty hostname. If same-credentials is true, the gateway uses the connection's
selected identity/secret, including an explicit override or an inline password.
Otherwise it uses its independently authenticated RDP credential. An unused
gateway reference is not a source of plaintext.

On Windows, either the external-client preference or a final AzureAD identity
requires the system client. AzureAD means an explicit domain equal to AzureAD or
an `AzureAD\` username prefix, case-insensitive. Ordinary connection/gateway
release is denied for that client; explicit Reveal is a distinct operation.
Linux and macOS ignore the mstsc preference and retain their native RDP adapter.

## Local owner and release lifetime

`ResolveConnection` loads and authenticates the complete chain under the owner
mutex and checks every ancestor against node floors copied from the authenticated
slot file at open. It returns exact node revisions and selected aggregate
metadata. No secret is read. The exclusive SQLite connection and owner mutex
prevent concurrent production mutations during this operation.

`WithConnectionSecret` re-resolves immediately before each release. It accepts a
connection ID, optional credential override, protocol path and supported field;
it accepts no caller-supplied resolution result or free-standing secret owner ID.
SSH/SFTP, RDP, RDP gateway, VNC and Reveal paths are checked against the resolved
protocol. Inline selection can release only its password. Saved field reads
must exactly match the authenticated credential manifest revision.

`WithConnectionTunnel` likewise re-resolves and checks the exact authenticated
configuration revision. Both methods keep the owner mutex through the synchronous
consumer callback and wipe borrowed plaintext afterward, including callback
failure. Consumers cannot reenter the owner, retain bytes or convert them to
immutable strings. No Electron/native wire operation exposes these callbacks.

Persisting new observations and credential/tunnel high-water marks remains work
for the checkpoint transaction. Replaying an entire matching authenticated
workspace/slot snapshot is not prevented here. These methods do not replace
profile enforcement, fresh authentication, protocol-child pinning/replay tracking,
tunnel leases or the sealed protocol handoff.

## Conformance and rollout

`internal/resolver/testdata/conformance-v1.json` is a language-independent fixture
corpus of full metadata chains, optional credential metadata/overrides, complete
expected plans and fixed rejection categories. The Go and PostgreSQL integration
tests compare both implementations with the same expected results. Additional Go
tests pin maximum depth, input immutability and platform-specific RDP policy.

Intentional differences from some legacy paths include explicit empty identity/
host handling, the inline identity boundary, complete ancestor requirements,
the shared port/credential context rule, zero web port defaulting, serial tunnel
rejection and consistent override priority. The legacy adapter captures SSH,
SFTP, VNC, RDP, RDP gateway and Reveal separately. Its live shadow comparison
logs IDs for differences. Migration preserves the legacy result for each
changed path and lets the user retain the pin or adopt the new resolution.
The local owner persists each changed path in its encrypted resolver migration
record. Shared import carries the retained choices into the destination.

### Legacy observations and comparison

Migration `0022_effective_credential_snapshot` adds the legacy SQLite table
`EffectiveCredentialSnapshot`, keyed by NodeId and ProtocolPath. Each row records
the selected credential/inline owner ID, username, domain, source kind, resolver
version 0 and observation time. It contains no password, key, token, endpoint,
notes or provider payload. Username/domain remain identity metadata, as they are
in the existing node and credential tables; they are not diagnostic output.

Successful default legacy resolution records its actual result. The shared SSH
walk records both SSH and SFTP, including SFTP opened on an SSH node. VNC records
the credential actually found by its existing secret lookup and no username,
because VNC does not use one. RDP records connection and gateway identities in
one transaction, including inline/same-credential/separate-gateway/system-client
choices. Reveal records the identity selected by its own existing walk. Explicit
manual credentials and per-attempt credential overrides do not replace the
configured connection observations. Metadata-only VNC inspections do not create
an observation of a secret that was never resolved.

Observation is best effort and cannot fail an existing connection. It accepts at
most six validated rows and uses a short context deadline. SQLite's busy handler
can exceed a Go deadline, so the writer pins its connection, temporarily disables
busy waiting and restores the original setting on return. A busy database skips
the observation. Ignored/failed rows roll back the whole group; RDP and gateway
cannot publish half an observation. No observer creates schema.

Reveal retains its query-only reader. Its separate short-lived metadata writer
opens the existing legacy file with `mode=rw`, refuses a `.slots` marker and
never creates a missing file. This legacy bridge must disappear at the single-
owner application cutover.

`CompareSnapshots` and the Go legacy-table comparison reader compare resolver 0
with resolver 1 and return IDs, protocol path and change flags only. The result
never includes either username/domain. Missing, malformed or corrupt baseline
rows reject the complete requested comparison. Database reads are bounded in
bytes and preserve embedded NUL so validation cannot be bypassed by SQLite text
truncation. No renderer comparison endpoint is connected yet.

After a successful observation write, the legacy adapter automatically resolves
the same node/path with the new resolver. It reads only the node fields needed
for credential resolution and selected local credential identity metadata, all in
one read transaction. Plans and credentials are reused within the observation
batch. SQL projections bound bytes, preserve NULL/empty/NUL and reject ambiguous
case-insensitive IDs. The complete ancestor chain is required, with the same
128-node limit as the candidate resolver. Protocol identity formatting preserves
SSH/SFTP's lack of domain, VNC's lack of username/domain, RDP domain splitting,
gateway composition and Windows system-client selection; Reveal stays distinct.

Differences are written through the native application logger as
`resolver_shadow_difference` followed by the ID/boolean-only DTO. Unavailable
comparisons emit only `resolver_shadow_unavailable` at Debug level. Nothing goes
to protocol stdout, and neither raw database errors nor identities are logged.
Missing, corrupt, unsupported or dynamic-provider inputs reject the entire batch;
an unavailable candidate is never reported as equivalence. There are no extra
secret reads, decryptions, provider requests, or changes to the active connection.

The shadow reader shares the observation's 250ms context and temporarily disables
SQLite busy waiting on its pinned connection. Both reader and writer explicitly
roll back before restoring the original busy timeout. A busy database skips the
comparison. These deadlines bound database work; they are not hard real-time
guarantees for filesystem writes or native logging.

These rows are observations of individual requests, not proof that all nodes were
resolved against one coherent current database state. They may become stale after
edits or outlive a deleted node. The candidate read is internally coherent, but
the preceding legacy walk can race an edit; a live difference is diagnostic, not
proof of a resolver regression or permission to pin. These observations must not
authorize automatic migration or
silently pin a never-observed result. The coherent capture below computes the
per-path comparison in one source state. Migration still must bind that state,
preserve intentional differences and record the selected pins before switching.

### Coherent legacy capture and comparison

The active SSH/SFTP metadata walk and Reveal selection/composition now live in
shared Go helpers, separate from reading a password or private key. Their legacy
inheritance and error behavior is preserved. In particular, inline SSH continues
to inherit the historical ancestor username, and Reveal retains its distinct
protocol/provider/kind rules. The eventual migration must pin such differences
before switching to resolver version 1.

`captureLegacyResolverSnapshots` executes shared active helpers for every current
connection in one SQLite read transaction. It captures Reveal plus applicable
SSH/SFTP, VNC or RDP/gateway paths, including connections without runtime
observations. The active VNC and RDP wrappers supply their normal credential
readers; capture supplies identity metadata and callbacks that never return a
password. Gateway composition, inline credentials, overrides and Windows system-
client semantics remain in the shared runtime walks.

Capture loads the node maps once, caches profile metadata within the transaction,
and orders results by node ID. Its query adapter passes the caller context into
all existing loaders. Missing/cyclic/over-depth chains, ambiguous or invalid IDs,
discarded database rows, an omitted applicable path, unavailable required metadata
and cancellation reject the entire capture; no partial result is returned. The
capture neither writes observations nor depends on them.

VNC distinguishes an absent secret row from an empty password. Capture checks
only row presence using `SELECT 1`; even a present but invalid ciphertext remains
subject to the separate secret-authentication gate. Independent VNC selections
are checked for profile ambiguity even when Reveal chooses a different source.

`captureLegacyResolverBaseline` captures legacy results and compares each node's
path group with resolver v1 inside that same transaction. It returns snapshots
and ID/boolean-only differences. A concurrent WAL edit between the two walks does
not mix states or invent a difference; a later baseline sees the committed edit.
An unavailable candidate rejects the entire baseline, including earlier valid
differences, rather than certifying equivalence or a partial migration.

This API returns native identity metadata only. It does not inspect secret values,
decrypt passwords, read private keys, contact providers or certify secret
availability. Secret authentication/import is a separate required migration gate.
The result describes a past database snapshot. The native migration-plan guard
below rechecks identities while reserving the source. Migration still needs to
apply stored per-path choices and expose its report/choices.
No app-facing endpoint activates this capture
or switches the workspace resolver. Dynamic provider identities that require a
provider lookup are unavailable to this metadata-only capture; they are not
guessed from cached identity fields.

### Migration plan and source reservation

`prepareLegacyResolverMigration` captures both legacy and candidate identities in
one source transaction. `resolver.BuildMigration` returns a versioned native plan
with one entry per changed node/path, defaulting to `keep`. `Decide` accepts only
`keep` or `new`, requires the preview fingerprint, and returns a copy; duplicate,
unknown or invalid choices reject the entire batch. `Report` projects IDs and
change flags only. Identities stay native and no secret values are read.

The version-1 fingerprint is SHA-256 over the following canonical byte stream:

1. ASCII `wormhole/v1/resolver-migration-identities` followed by one NUL byte;
2. workspace ID, prefixed by its big-endian uint64 UTF-8 byte length;
3. big-endian uint64 snapshot-pair count;
4. every pair sorted by canonical node ID plus `:` plus protocol path, legacy
   first then candidate. Each snapshot writes node ID, protocol path, credential
   ID, username, domain and source kind as length-prefixed UTF-8 strings using
   uint64 lengths, then the resolver version as one byte.

Unchanged paths are included in the fingerprint even though they have no plan
entry. Reordering inputs does not change it. The validator rejects duplicate or
incompatible path groups; the complete native capture remains responsible for
enumerating every applicable path. A reveal-only group cannot establish whether
its source node was web or an incompletely captured SSH/RDP node.

`withLegacyResolverMigration` takes an SQLite `BEGIN IMMEDIATE` reservation with
busy waiting disabled, sets its pinned connection to query-only, captures a fresh
complete baseline and rechecks the fingerprint and exact entry identities before
calling the native import callback. Source writers cannot change the captured
database state during that callback, including in WAL mode. The callback uses the
provided reader rather than reentering the pool. It must not issue transaction
control statements or retain the reader. Cancellation or invalid metadata rejects
the operation without publishing a partial baseline.

Cleanup explicitly rolls back and restores the original query/busy policies.
An ambiguous BEGIN result, failed rollback or failed policy restoration discards
the connection instead of returning unknown state to the pool. In particular, a
driver cancellation error does not prove that BEGIN or a PRAGMA had no effect.

This fingerprint detects identity drift; it is neither authentication nor a hash
of routes, secret values, or the database file. The source reservation protects
SQLite transactions, not hostile raw file replacement. The eventual importer
must authenticate every secret, bind destination pins to sealed node manifests,
and complete its recovery journal before publication. No migration UI,
import/cutover or app unlock is activated by these native planning helpers.

### Authenticated storage of per-node choices

The local owner can import, read and change a node's migration choices through
native-only APIs. The importer supplies only that node's changed entries (at most
three), retaining the complete source plan's fingerprint as provenance. It must
recheck the complete source plan under the source reservation before staging any
records; a per-node subset cannot replace that full recheck.

`resolverMigration` is a reserved encrypted node field in `SecretValues`, using
its own DEK. Its presence and exact revision are authenticated in the same node
manifest as notes and the inline password, and written atomically with the node.
Deleting or substituting the encrypted record cannot silently turn a pin off.
Reads authenticate the node, check revision floors and validate a canonical,
bounded domain payload. Username/domain values in this record are never written
in plaintext. The three-field aggregate follows the existing ciphertext-only
schema; ordinary node-editor requests still accept only notes and inline password.

The initial import cannot overwrite an existing migration record. Choice changes
require both the node's expected revision and the source fingerprint, preserving
provenance while preventing lost updates. A `keep` choice to a saved credential
requires that credential's authenticated live record. Credential deletion and
protocol changes scan authenticated node records in bounded pages and reject any
remaining `keep` reference. Password rotation remains allowed. Selecting `new`
releases that historical reference; node or subtree deletion atomically retires
the migration field together with all other fields.

The owner now applies these records during native connection resolution and
secret release. `ResolveConnectionPath` selects SSH, SFTP, VNC, RDP, RDP gateway
or Reveal independently. A `keep` entry uses its exact historical identity;
`new` and paths without a changed entry use the current candidate. Kept settings
are explicit leaf choices; unchanged candidate choices retain their original
inheritance owner. Password rotation still uses the credential's current
authenticated field revision, without replacing the pinned username/domain.

The returned `Account`, `Plan` identity/credential and `Credential` describe the
requested path. `GatewayAccount` describes the separately resolved RDP gateway;
consumers must use these resolved identities rather than rebuilding them from
credential-profile usernames. Gateway choices that differ from the main account
are not collapsed into “same credentials”. `ResolveConnection` selects the
protocol's default path. All operations authenticate the complete current chain,
candidate dependencies, any selected pinned credential and the selected tunnel;
secret callbacks re-resolve under the owner lock and retain exact field-version
checks and wiping.

Explicit credential overrides bypass the primary path's pin. They also supply
the gateway when the configured route uses the same credentials; a separately
configured gateway retains its own pin. Historical Reveal can intentionally
select another protocol's credential, without changing SSH/RDP/VNC selection.
A `none` choice never falls back to another credential. System-client choices,
and Windows RDP identities requiring that client, never release a password to
the native protocol consumer. Reveal remains a separate path.

Missing or malformed migration records, failed seals and incompatible kept paths
reject resolution. Changing the node protocol requires selecting `new` for kept
paths that no longer apply. This native resolver work does not switch the app:
there is still no app IPC for migration planning/choices, legacy secret import
and cutover are incomplete, and existing workspaces keep their current runtime.

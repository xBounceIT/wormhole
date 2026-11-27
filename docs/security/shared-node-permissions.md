# Shared node permission foundation

Deployment migration `0016_node_permissions.sql` upgrades exactly schema 15 under
the workspace migration lock. It creates private `nodes`, `groups`, `group_members`
and `grants` tables. Migration 17 expands the node table with connection metadata
and seal references; see [tree snapshots](shared-tree-snapshots.md). No runtime
table privileges or mutation endpoints are granted.

Permissions are additive independent bits: View=1, Use=2, Write=4, Reveal=8 and
Manage=16. A user receives the union of their direct grants and group grants on a
node and all its ancestors. Administrator status does not implicitly grant node
access. A personal owner on any ancestor confines the subtree to that user; a
direct grant cannot override that restriction. Ownership alone does not create a
grant. Provisioning must explicitly grant the owner's intended permissions.

The Go evaluator in `internal/permissions` requires a complete target-to-root
chain. It rejects invalid IDs, unknown permission bits, malformed grant subjects,
cycles, incomplete chains, connection ancestors and more than 128 nodes. Inputs
are borrowed and unchanged. Membership/grant inputs are bounded to 8192 entries.
The caller is responsible for supplying an authenticated snapshot, including any
required signatures. The evaluator itself neither fetches nor verifies keys.

PostgreSQL's private `effective_permissions` uses the same ancestry and union
rules. Shared row locks keep each observed parent link and personal owner stable
until the transaction ends. Contention fails promptly instead of using a partial
chain. Grants and memberships are read together in one statement snapshot.

The public `node_permissions(capability, node)` API derives the user from the
existing audited device proof. Neither a bare database login nor an enrollment
role can use it to bypass that proof or select another user. Native
`Session.NodePermissions` supplies its protected capability to a fixed SQL
statement, validates a canonical mask in 0..31 and retires the connection on a
malformed response. Capability encodings and returned byte buffers are erased.

This result describes current database policy. It is not a secret-release ticket
or proof against a malicious DBA, and must not be cached as authority for a later
operation. Shared `begin_use`, committed audit tickets, `fetch_secret`, signed
resolution chains, key boundaries and client high-water marks remain separate
requirements. See [native connection planning and SSH release](shared-connection-planning.md)
for the metadata-only planning API and separate audited release.

### Editing and moving catalog items

Starting with schema 88, members with View and Write can edit connections and
folders in the shared catalog. A rename needs those two permissions. When an
edit changes where a credential would be used, the service checks Reveal on
the resulting credential, including credentials selected by another member.
The same checks apply to connections that inherit changed folder settings.

Schema 89 adds **Move to folder…** to the editor. The user selects a writable
folder or the workspace root. The backend checks the source and chosen folder
at the displayed catalog revision. PostgreSQL serializes moves, rejects cycles
and changes to personal confinement, and requires Manage on the source when
inherited grants would change. Both moves and scalar edits check stored private
credential selections even while their owner is suspended. Standard asks for
fresh account authentication before a move.

On success, the database returns the signed node and its field manifest, when
present. The device checks both against the records it signed and records their
revisions locally. This also works when the move removes the writer's inherited
View permission. Later reads use the permissions at the new location.

Tests compare Go and PostgreSQL for every nonempty mask, inherited/direct/group
unions, membership removal and personal confinement. They also exercise malformed
chains, cycles, the exact depth limit, migration rollback/replay, table/function
ACLs, direct SQL without admission, real SCRAM and audited session use, contention,
disabled accounts and a malicious response. Go coverage for the new evaluator,
native method, decoder and migration generator is 100%. PostgreSQL behavior is
tested against a real server; Go coverage does not measure SQL statements.

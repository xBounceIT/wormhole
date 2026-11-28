# Shared inline password release

Schema 39 adds a private `node_secret_manifests` table. A node field manifest is
signed as a `node-fields` selection, with a distinct signature domain. Its node
ID, canonical field/version/presence list, deletion state, boundary and revision
are authenticated by the current member certificate and organisation-signed
account state. It leaves the existing node metadata seal format unchanged.

Both PostgreSQL and the native decoder require the manifest boundary and seal
revision to match the requested leaf node. Native verification retains a
`node-fields/<node-id>` high-water mark and a digest, detecting lower revisions
and conflicting signatures at the same revision. Tombstones advance their floor
before refusal. A signature proves authorship; the database independently checks
Use on the connection and its secret boundary. Paranoid capability certificates
and shared write/admin APIs remain separate roadmap work.

Saved credential releases retain graph format 2. Inline releases use format 3,
which adds exactly `nodeFields` and an `inline` account section. The field-version
manifest admits only `inlinePassword`; notes are not included in a Use release.
Every encrypted value binds `SecretValues/node`, the node ID, field and version,
and its own DEK. Existing certified key copies, boundary manifests and current
account checks remain required. Schema 40 adds signed tunnel profiles and release
graph format 4 for selected tunnels; see [Shared tunnel release](shared-tunnels.md)
for its verification, selective opening and current integration boundary.

The native owner obtains a committed `begin_use` audit ticket, fetches and
verifies the complete graph, and publishes the protected trust state and startup
anchor before opening a key or password. `CredentialReleaseValues.Inline` keeps
node fields separate from saved profiles. Borrowed buffers are wiped after every
callback, including failure, cancellation and panic, and never serialize to JSON.
The owner seals the SSH/SFTP frame to the main-owned recipient immediately.

The resolver's existing inline protocols are SSH, SFTP and RDP. Shared direct and authenticated tunneled
SSH/SFTP accept a nonempty signed inline password. Existing SSH framing and
authentication reject empty or absent credentials; this change preserves that
behavior and never substitutes a saved account. The shared graph can authenticate
and open RDP inline material, while shared RDP session integration remains pending.
VNC continues to use saved credentials or its protected temporary-password flow.

Tests cover signatures, scope/field/revision/boundary substitutions, strict wire
shapes, rollback/forks, persisted trust, deletion observations and buffer wiping.
Real PostgreSQL 16.15 tests cover migration rollback/replay, private table/function
ACLs, invalid manifests, revision/owner mismatches, committed audit, independent
Use permissions and the nontransactional ticket replay guard for inline releases.
Native handler-to-recipient tests use a signed shared graph and real SSH/SFTP TCP
servers, including closure on lock. These native socket tests inject the database
session at the graph boundary; they do not claim live PostgreSQL-to-SSH end-to-end
admission. The PostgreSQL and native transport checks prove their respective
boundaries separately.

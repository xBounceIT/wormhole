# Shared tunnel release

Schema 40 introduces private `tunnel_profiles`. A member-signed `TunnelRecord`
contains the public ID, name, provider kind, configuration version and deletion
state. Its `wormhole/v1/shared-tunnel` signature domain also authenticates the
workspace, boundary, signer and row revision. The configuration version is a
positive integer no greater than the signed row revision. A name-only edit may
retain the configuration version while advancing the row revision.

The native verifier records a `tunnel/<id>` revision floor and signature digest.
It retains authenticated deletion and revocation observations before denying use.
The connection's signed resolution chain selects the tunnel ID; missing,
unrelated, unsigned or mismatched profiles cannot turn that route into a direct
connection. Tunnel authors participate in snapshot sequence consistency checks.

Connection metadata format 2 adds exactly one selected tunnel projection and its
boundary manifest. Existing direct metadata retains format 1. The returned native
plan exposes only verified public tunnel metadata, after the owning controller
commits its trust observations. Its revision digest includes the tunnel profile.
No ciphertext, key copy, audit issuance or key opening is needed for planning.

A tunnel release uses graph format 4, with an explicit nullable `nodeFields` and
a final `tunnel` account section. Direct saved and inline releases keep formats
2 and 3. The tunnel has one encrypted `settings` field, bound to its ID,
configuration version and its own DEK. Current/previous boundary roots and
certified key copies remain authenticated as part of the complete graph.

The public PostgreSQL APIs independently require Use on the connection, primary
or inline account, optional gateway, and selected tunnel boundary. All settings
and key material must be available before `fetch_secret` claims the committed
`begin_use` ticket. Missing settings cannot consume its sequence generation;
replaying a completed release remains forbidden. Runtime user/admin/enrollment
roles receive neither table access nor access to private projection helpers.

The owner must durably publish the verified trust state before opening keys.
`WithTunnelValues` opens settings only; `WithValues` opens primary, inline and
gateway accounts only. Both share one atomic single-use gate. Borrowed values do
not serialize to JSON, and independently owned buffers are wiped on success,
callback failure, cancellation and panic, even if the callback deletes map entries.
Each later release requires a new audited ticket and current verification.

Native handoff now supports shared tunnel settings and routed SSH/SFTP/VNC,
including protected temporary VNC passwords. Go derives the route binding from
the current signed graph and the native owner's authenticated startup FileID.
Each release checks the complete binding (workspace, file, node, session, request,
native admission epoch, destination, provider, row and configuration version) before borrowing the
account private key. Only canonical IPv4 loopback SOCKS endpoints are accepted.
An outdated route or missing/invalid tunnel is an error; it cannot become a direct
connection. Direct protocol bundles still refuse any selected tunnel.

Settings are sealed with the tunnel-specific HPKE purpose to the route process.
Protocol credentials use the routed-protocol purpose, which also authenticates
the exact SOCKS endpoint. A packet cannot be opened as a direct bundle or against
a different listener. Tunnel names for HTTP/HTTPS come from the common native
protocol mapping, separately from the resolver's credential-release intents.

The existing Electron route broker owns and pools native tunnel processes and
leases. Every consumer obtains a fresh authenticated binding. The broker may
reuse a process across metadata-only edits while the configuration version stays
unchanged; later credential release still checks that consumer's current binding.
Native protocol sessions stop on route loss, and existing lock/close barriers
release their leases. Routed manual VNC wraps the protected document's opaque
password envelope after audited authorization, without opening stored passwords
or settings. Shared SSH host plans check the current route before probing and
require the signed host-key pin for credential release. Starting with schema
87, accepting a new SSH or SFTP host key requires Write on the connection.
The device signs the new leaf and any inline-field manifest at the same
revision. PostgreSQL rechecks permissions and the plan snapshot, then commits
both signatures and the audit entry together. Standard requires fresh account
authentication. Before acknowledging the change, the client reads back the
signed connection and its field manifest. It checks the new fingerprint and
revision against the requested edit. If a credential, ancestor, tunnel,
boundary manifest, account state or policy changed in the meantime, the app
rejects the pending confirmation. A new connection reads the current plan.

Fortinet SSL SSO now uses a separate one-use cookie recipient and a native-only
launch witness. Only a fresh gateway-issued HttpOnly cookie-store commit can
complete its isolated browser flow; cached bearer values do not bypass login.
The same original-owner and boundary authorization rules apply. See the
[SSL authentication flow](vault-fortinet-ssl-flow.md) for remaining retention and
fallback work.

Remaining integration includes shared RDP/web sessions and the other write/admin
and security-profile roadmap work. Automated native tests use synthetic sidecars;
real provider-specific VPN authentication still needs interoperability validation.

Tests cover strict shapes and cross-role substitutions, signature tampering,
rollback/forks, tombstones and revocation persistence, selective opening, wiping
and concurrent replay. Real PostgreSQL 16.15 tests exercise migration rollback
and replay, private ACLs, independent boundary permissions, saved/inline/gateway
combinations, metadata-only planning, actual settings opening and ticket audit
and replay behavior. Native tests additionally exercise real loopback SOCKS5 and
SSH/SFTP/RFB
handshakes, VNC saved/temporary/empty passwords, original target preservation,
and native tunnel/SSH closure and settings wiping on app lock. The original
hosts in routed tests cannot be reached directly. Database sessions are injected
at the signed graph boundary for these socket tests; they do not establish a
live PostgreSQL-to-provider VPN admission flow.

## Fortinet IPsec metadata

Migration 41 (`FortinetIPsecMigration`) upgrades schema 40 by extending the signed
provider enum through kind 9. It checks workspace identity and exact previous
version under the migration lock, changes only the kind constraint and schema
version, and preserves table/function grants. Existing signatures and ciphertext
are unchanged. Both native metadata verification and HPKE route binding recognize
the new kind; unknown providers still fail closed. Runtime availability is narrower
than storage support; see [the IPsec flow](vault-ipsec-flow.md).

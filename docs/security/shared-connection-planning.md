# Shared connection planning and native protocol release

Schema 37 adds `wormhole_api_v1.connection_plan(capability, node)`. It derives
the current user and device from the admitted session, requires Use on the node
and selected credential boundaries, and returns one bounded metadata snapshot.
It does not read encrypted values or key copies, issue an audit ticket, or
consume a pending ticket. Enrollment roles cannot execute it. The later audited
release independently resolves and authorizes the connection again.

The format 1 payload has exactly `formatVersion`, `profile`, `account` and
`metadata`. The profile is the current signed workspace policy; account state
and resolution records come from the same workspace snapshot. Native decoding
checks receipt identity, versions, shape and bounds. Verification authenticates
the profile, current account, member certificates, resolution seals and boundary
manifests, recomputes the plan, and checks protected high-water marks. Any nonzero
observations must be retained even when verification refuses the operation.

`sharedAdmissionController.PlanConnection` publishes those observations to the
protected trust file and startup anchor before returning public metadata. Its
revision digest binds all authenticated resolution inputs, including parent and
credential revisions, independently of whether the effective endpoint changed.
Planning cannot open private keys or turn its result into a release capability.

The native shared handlers admit metadata-only `connection-route`,
`ssh-host-plan` and `vnc-plan`, plus `ssh-bundle` for a direct, pinned SSH/SFTP
connection and `vnc-bundle` for direct VNC. RDP adds `rdp-bundle` and
`rdp-route-bundle` for audited saved connection release; the routed bundle binds
the exact native tunnel revision and loopback endpoint.
`SealSSHConnection` obtains a new committed audit ticket, fetches the encrypted
graph, and validates the actual release snapshot before opening fields. It
checks node, protocol, route, host, port, username and canonical host fingerprint.
The child session/request IDs, recipient public key and lifecycle epoch remain
bound to the HPKE packet. The child epoch is independent of the PostgreSQL
snapshot epoch.

After durable trust publication, credential bytes are borrowed only within the
native callback, encoded into the SSH frame and immediately sealed to the
main-owned protocol child. After the audited operation begins, failures return
zero packet output and retire the failed owner. Plaintext, roots and temporary frames are wiped. An earlier
direct plan never authorizes bypassing a newly configured VPN. Raw credential
override IDs and shared host-trust writes remain refused until their signed
selection/write paths are implemented.

Each handler re-reads the machine profile floor. Any stricter effective profile,
including Default to Standard, retires the previous admission before private
use, so main-owned controls must be reactivated. Unsupported Hardened and
Paranoid profiles continue to fail closed.

Schema 38 adds `runtime_state(capability)`, a bounded current signed workspace
policy and own-account state projection. Native verification retains authentic
high-water marks and publishes the protected trust file and startup anchor
before returning a public security profile. Revocation, changed account keys,
policy rollback/fork, and newer authentic policy retire the admitted owner. A
stronger machine floor requires re-admission; removing a floor cannot relax the
controls of an already admitted owner. This read never issues a use ticket or
retrieves encrypted values or key copies.

Main activates its lock monitor from `shared-runtime` before publishing the
unlocked PostgreSQL workspace ID. The device slot file's `vaultId` remains the
startup/unlock identity and is independently checked against the selected file;
it is not the protocol workspace identity. Application authentication is marked
unlocked only after the protected dialog closes and its parent document is
revalidated. Password-change recovery does not activate application authentication.
The monitor's main-only `security` read revalidates the current remote policy
and own-account state. Failure retires the native owner and triggers application
locking through the existing monitor.

Shared startup now lazily mounts a catalog and owned SSH/SFTP/VNC/RDP session tabs after
native admission. The catalog exposes only an authenticated public `canUse`
presentation hint; folders and View-only nodes cannot open sessions. Opens send
only node/session identifiers, mode and terminal dimensions or measured RDP
surface bounds. Native planning and
audited release independently authorize each connection and reconnect.
Connections that inherit their protocol use a narrow `shared-connection-context`
read. Go resolves the signed chain under current Use authorization and publishes
only the requested node ID and effective protocol. It neither issues a Use ticket
nor opens account keys or ciphertext. Cancelling or retiring a pending read
cannot create a protocol child; reconnect resolves inherited context again.
The later native host plan and audited release independently reauthorize it.

This shared Connect flow supports pinned, direct SSH/SFTP with saved local
credentials or [signed inline passwords](shared-inline-fields.md), plus direct VNC with a saved local password or no credential, and saved RDP
through its native credential handoff. Existing xterm and file-browser surfaces retain output
acknowledgements, native clipboard paste, editor support and file transfers.
Renderer controllers bound session counts, request correlation and transfer
rows. Pending admissions and unconfirmed closes reserve their original IDs;
reconnect requires confirmed cleanup and uses a fresh ID. Observed permission
loss bypasses a pending edit-close confirmation. Lock, sign-out and renderer
failure retire the session controllers; stale lazy modules cannot replace a
newer admission. Device-local editor preferences authenticate current shared
policy/account state before filesystem access and never open SQLite.

Shared VNC authenticates and audits its current resolution graph before opening
saved fields, preserving absent and explicitly empty passwords. A
password-required failure can instead open the existing protected password
document. Public planning opens no saved keys; manual authorization verifies and
audits the current graph, durably publishes trust, then seals only the opaque
manual envelope to the main-owned recipient. The native manual-only recipient
cannot fall back to a saved password. Changed destinations, new VPN requirements,
cancellation, uncommitted trust and malformed envelopes produce no output.

The VNC surface subscribes before native opening and stays mounted across tab
selection. Inactive tabs release held keys/buttons, discard queued pointer moves
and suppress further input. The session controller keeps authentication failures
until confirmed cleanup, uses fresh IDs for reconnect and sends only identifiers
and an optional manual-mode intent. Failed native/process/route shutdown keeps
its admission barrier; an explicit retry rechecks the original resources before
allowing replacement. No failed close is silently treated as confirmation.

Native tests join a signed shared graph through the native RPC and sealed CLI
recipient to a TCP RFB server, covering saved, temporary and explicitly empty
passwords, framebuffer output and controls. These tests inject the PostgreSQL
session at the graph boundary; they do not establish live PostgreSQL-to-VNC or
external-server interoperability. Chromium tests exercise the real shared VNC
surface through an injected bridge, separately from the native socket tests.

Shared RDP uses the existing desktop surface with main-owned native geometry,
certificate confirmation and owner lifecycle. The measured mount gate precedes
admission; inherited protocol 1 is resolved in Go, not inferred by the renderer.
Early failure waits for its close receipt and reconnect requires a fresh ID.
Hide persists through native Connected/LoginComplete/AutoReconnected events,
including inactive tabs that have not connected yet. No recipient, ciphertext
or password API is added to the ordinary preload. Actual-source and Chromium
tests complement the native Go/ActiveX checks; a successful real remote account
or RD Gateway login is not claimed. Protected temporary RDP accounts now use a dedicated sandboxed document, an
opaque primary envelope and gateway-only secret borrowing. Retries use a fresh
prompt and never fall back to saved credentials. Unsaved Quick Connect still
requires an authenticated target flow. See [the RDP flow](vault-rdp-flow.md).

Shared writes and host-trust changes, remaining protocols, provider-specific
signed tunnel support and offline edit-recovery UI remain separate requirements. Catalog
pages do not establish that a missing node was revoked; every new connection
still reauthorizes natively. Chromium tests use an injected bridge to exercise
real terminal/file surfaces and lifecycle ordering. They complement the native
and PostgreSQL tests, rather than proving live PostgreSQL-to-SSH interoperability.

Tests include real PostgreSQL 16.15, deletion of fixture ciphertext/key copies
while metadata planning continues, independent permission gates, pending-ticket
preservation, malformed receipts and protocol limits, cancellation/close races,
durable trust ordering, and native handler-to-HPKE-recipient SSH/SFTP round trips.
SQL behavior is tested against PostgreSQL; Go coverage does not instrument SQL.
Runtime-state tests also cover disabled users, revoked devices, missing current
account state, main activation failure, parent navigation, late owner responses,
and separate slot/workspace identities. Hardware/provider and other-platform
runtime checks remain separate from these automated tests.

An admitted native owner verifies account and device access independently of
catalog polling in the renderer. Workspace notifications are hints to
recheck PostgreSQL. Native polling every 30 seconds covers lost notifications
and transaction-mode poolers. If the admission fails verification, the
backend retires its keys and exits. Electron then runs the vault lock and
closes active application sessions.

The vault-client test command runs its native fixture files sequentially, matching
the coverage runner. These fixtures own Electron windows, precise profilers and
Argon2 memory arenas; concurrent runs produced intermittent native deadlines.
The same cases, assertions, timeouts and coverage thresholds are retained.
Immutable helper executables are compiled before the local lifecycle fixture
opens live vault owners, and reused across its slot scenarios.

# Encrypted vault and shared workspace: implementation status

Tracking specification: [issue #495](https://github.com/xBounceIT/wormhole/issues/495).
The private report and work that depends on it are excluded at the maintainer's
request. The public P0 OpenVPN capability check and matching provider UI gating
are implemented: the backend probes the sidecar before starting vendor
authentication, and the editor hides unavailable OpenVPN-based
providers. A failed probe never switches the connection to a direct route.

## Current boundary

The active-vault updater accepts signed Ed25519 release manifests. Standard
also checks the native publisher. [Managed updates](vault-managed-updates.md)
use an exact machine-approved manifest and locally staged installers. Hardened
can use that source or receive public notifications. Paranoid checks the
managed source exclusively.

Shared PostgreSQL schema 85 adds monthly audit partition maintenance for the
DBA. The retention period defaults to 400 days. The desktop recovery window
accepts backup summaries from the supported source schemas 49 through 87.
See [audit partition maintenance](vault-shared-postgresql-deployment.md#audit-partition-maintenance).

Schema 86 adds a live list of registered devices with an unencrypted PostgreSQL
connection to the protected administration window. See [Unencrypted clients](vault-shared-postgresql-deployment.md#unencrypted-clients).

Schema 87 adds audited SSH and SFTP host-key confirmation for members who
hold Write on the connection. See [shared tunnels](shared-tunnels.md).

Shared setup checks the database's function bodies, execution settings and
access grants after deployment and before preparing the first administrator.
See [fresh database deployment](vault-shared-postgresql-deployment.md#fresh-database-deployment).

The self-hosted wizard exports workspace-scoped `pg_hba.conf` rules for the
DBA’s IPv4 and IPv6 allow-list. **Check deployment** reports how PostgreSQL
responds to plaintext startup from this client and which logging settings may
expose statement text or parameters. See [client access rules](vault-shared-postgresql-deployment.md#client-access-rules).

A Hardened or Paranoid machine floor checks the installation before startup
or vault service launch. The backend binds the running Electron and Go images
to the same protected package. Windows verifies ownership and DACLs on the
local drive. Linux checks root ownership and permissions on a supported local
filesystem and uses a confined procfs lookup to verify the initial user
namespace. Deploy a root-owned DEB or RPM package for this check. AppImage
mounts through FUSE do not qualify. macOS checks a root-owned app bundle on
APFS or HFS+, including extended ACLs. Relative framework links must resolve
inside their bundle. A Paranoid machine floor also verifies the
[signed installation proof](vault-installation-proof.md) against the release
key built into the backend. Production deployments and workspace-profile
admission are pending verification.

The [shared PostgreSQL transport foundation](vault-shared-postgresql.md) now
enforces SCRAM, explicit TLS modes, and consistent fallback-host policy in native
Go. A [versioned identity migration](vault-shared-postgresql-deployment.md) now
creates isolated roles and private identity tables. Native shared foundations
now include account admission/enrollment, signed catalog verification and audited
credential release. The shared startup screen mounts the authenticated catalog
and owned terminal/file/desktop tabs for pinned direct SSH/SFTP with saved local
credentials or signed inline passwords, direct VNC with saved, absent or protected
temporary passwords, saved-node RDP with saved or protected temporary accounts,
and saved serial nodes. Each open and reconnect reauthorizes in Go. Shared administration,
other connection flows and the later security stages remain incomplete. See
[shared connection planning](shared-connection-planning.md) for the exact current
boundary and verification limits.

The protected [initial invitation flow](vault-invitation-enrollment.md) now joins
an empty workspace and supports explicit password/ASK plus invitation-code
continuation after interruption. Format 3 publishes the encrypted preparation as
one complete directory before SQL; ordinary recovery never replays an invitation.
Real Electron/PostgreSQL tests cover initial admission, pre-submission continuation
and normal device reopen at Default with Off, Encrypted and Verified TLS against a
pinned test CA. CA/hostname rejection and an untrusted CA change during continuation
leave the invite unused. The application displays a permanent transport warning
for Off or unverified encrypted TLS, using native admitted state. Other profile/ASK
matrices, managed workspace-CA onboarding, later security profiles and shared
administration remain separate work.

The [shared deployment wizard](vault-shared-postgresql-deployment.md) deploys or
reconciles schema 87, verifies offline recovery custody and admits the first
administrator through ordinary Join. From an unlocked local vault, it stages
the admitted device in a separate directory and selects it for the next launch.
Electron/PostgreSQL tests cover direct Standard deployment with ASK, DBA-applied
SQL under Default, and switching from an existing local vault without changing
its database or slot file. The same wizard signs a server-generated CSR for
self-hosted PostgreSQL. It verifies the installed certificate before bootstrap
and carries the organisation-wrapped CA into the server's recovery capsule and
the offline kit. Default and Standard also support a device-local encrypted
server-key package with optional removal after the exact certificate is
verified on PostgreSQL. An enrolled administrator can renew the server
certificate from a CSR against the same CA. The Electron/PostgreSQL test
reloads the new certificate and opens the workspace with the original device
enrollment. The app can also publish a signed two-root overlap and retire the
old root after verifying the installed certificate on each configured
endpoint. The initiating device checkpoints the signed bundle, closes its
PostgreSQL session and releases its keys before Electron acknowledges the
change and locks the workspace. An already unlocked peer that observes the
change also checkpoints its new trust floor before disconnecting.
An enrolled device that missed the transition can import the signed
trust update at protected sign-in and reuse its enrollment. After CA retirement,
a Default or Standard administrator can write an updated offline recovery kit
that opens with the original recovery code. Custodian rotation remains pending.
The native source for optional local data import checks SQLite foreign keys,
then captures the authenticated catalog and effective accounts. The destination
plan defaults each item to personal, remaps the graph and flags shared items
that depend on personal items. It compares resolver results before upload and
accepts explicit choices for individual changed paths. Before lending an exact
secret field to native staging, the source rechecks its fingerprint and wipes
the borrowed value after use. Go prepares a signed import document in memory.
Each field has a fresh DEK wrapped to the signed secret root for its personal or
shared destination. The stage rewrites Fortinet IPsec fallback IDs, rejects a
shared tunnel that depends on a personal one, and keeps notes outside the
inline credential manifest. Schema 55 adds a native PostgreSQL transaction for
an admitted writer with Write on the selected boundaries. It inserts the graph,
ciphertext, import receipt and audit entry atomically. A retry with the exact
signed document reconciles the existing receipt. Recovery archives retain the
signed node data for notes and pins. The native metadata reader verifies the
attachment against the node seal. The app uses path-bound release for SSH,
standalone SFTP, RDP and VNC, with the actual path in the committed audit and
one-time ticket. RDP verifies the desktop and gateway choices together and can
keep distinct historical identities. Manual RDP opens only an independently
selected gateway value. Supported pinned nodes retain authenticated tunnel
settings and IPsec-to-SSL fallback. Schema 56 wraps new imported notes to the
boundary view key. The shared catalog opens them in the protected notes window
after an audited, revision-bound View on the node and its boundary. Go verifies
the signed attachment and seals the note to the window's ephemeral recipient.
Schema 57 provisions the first administrator's default personal boundary with
distinct view and secret roots and certified organisation escrow. PostgreSQL
commits the signed manifest, owner grant, key copies and audit event together.
The backend resolves personal and shared destinations independently. Schema 58
connects the optional import to the protected Electron setup wizard. It
previews per-item destinations and dependencies, collects resolver choices,
and requires a current review before import. PostgreSQL commits the signed
approval receipt with the encrypted data. A retry of the same approved setup
reconciles it before selecting the workspace for restart. Schema 48
adds native break-glass on Default or Standard. Schema 57 supports personal
boundaries with complete organisation custody during recovery. It authenticates
the offline kit and the signed TLS bundle, uses the workspace's deployer login,
and creates an audited invitation for a new administrator. Ordinary certified
Join consumes that invitation. From the app's initial workspace screen, the
protected **Recover shared workspace access** wizard selects the offline files
through native pickers and saves the encrypted checkpoint before publication.
The same wizard resumes that issuance and confirms the new device. Schema 49
adds an audited native recovery backup. The native owner checks custodian
authority and signed workspace state, then writes the persistent graph using
the Wormhole backup encryption envelope and a generated recovery password.
Eligible administrators can export from the shared workspace screen. Main owns
the picker and the isolated window shows the password once. A fresh app
installation can open the archive in a protected window and save the deployment
SQL for the original workspace identity. Schema 50 imports the persistent
graph into an untouched matching cluster over archive-verified TLS. The
transaction preserves account identities, records an audit entry and supports
retry by archive digest. Schema 51 adds signed copies of the enrolled account
keys, encrypted to a certified organisation recipient during native unlock
under escrow policy. Accounts that have completed the deposit carry their
copies into subsequent backups and restores. Schema 52 adds native reset
issuance and lets recipients open the original keys using a fresh code and ASK.
Schema 53 adds atomic native redemption, old-device revocation and
reconciliation of the new device after an uncertain reply. The app's native
startup layer stages the encrypted reset before submission and can reconcile
or continue from that selection on restart. The protected Electron recipient
screen opens a `.whreset` offer from a native picker on a fresh local
destination. It collects the separate code and new ASK and lets the user
resume a pending reset. The protected custodian screen verifies fresh factors
before issuing a reset. It saves the signed offer and displays the code and new
ASK only after PostgreSQL confirms issuance. Schema 54 adds a paginated list of
accounts, batch selection and persistent handover status for each offer. The
custodian goes through each selected account in order and delivers its separate
file and factors. Pending offers can be marked as delivered after reopening the
screen. The batch flow has no combined export. The Windows Electron wizard test
against PostgreSQL 16.15 issues two separate offers, closes the window and then
records the pending handover after reopening it. A separate PostgreSQL test
checks both accounts' handover state after an archive restore to a new cluster.

Schema 59 adds a protected, read-only workspace administration window for
accounts, devices, recorded sessions and audit. It applies with or without
organisation recovery escrow. Go verifies current workspace policy and account
state over verified TLS. PostgreSQL checks current administrator authority and
the audited device capability for each bounded page. The session list shows
recorded admissions, including historical sessions.

Schema 60 adds group administration to the same window. Administrators can
create and rename groups, edit membership by exact account, and delete empty
groups without grants. Each write checks the group revision and the current
signed workspace policy and account state, invalidates permission snapshots,
and records the group and member IDs in the transaction's audit event. The
existing node evaluator applies membership changes to inherited grants.
Groups with boundary grants, group keys, or existing signed membership require
a key-aware membership workflow.

Schema 61 adds direct account and group grants on shared folders and
connections. The isolated **Grants** section selects from the authenticated
catalog. PostgreSQL checks administrator status and effective Manage on the
target and binds every edit to the reviewed node, grant and catalog revisions.
Administrators can delegate permission bits they hold on the target. Changes
invalidate permission snapshots and audit the subject and the previous and new
masks. Folder grants apply to descendants. Boundary permissions and access to
cryptographic key copies are evaluated separately.

Schema 62 lets an organisation custodian issue the initial group encryption
key from the protected **Groups** section. The review shows certified enabled
recipients and binds confirmation to the exact roster. Go verifies the signed
account selections and issues a signed group manifest and recipient-bound
HPKE copies, including the organisation recovery copy. PostgreSQL publishes
the manifest, copies and audit atomically and preserves them in recovery
archives. A keyed group requires the separate key-aware membership workflow.

Schema 63 supports group-wrapped View and Secret roots in the existing audited
note, connection credential and VPN fallback release paths. PostgreSQL
requires current membership and the matching grant on the same shared
boundary. Go verifies the organisation-signed group manifest and both key
copies, and requires the committed group generation before opening. Existing
direct copies still work. PostgreSQL integration tests exercise release
through a group and reject Secret release to a View-only group even when a
separate account grant authorizes Use.

Schema 64 adds **Boundary keys** under **Grants → Group grants** for a shared
catalog item. The selected item's authenticated boundary names the scope of
the grant. An administrator with boundary Manage and the permissions being
delegated can review View, Use or both and see who received the certified group
key. Go checks the reviewed boundary and group manifests and uses temporary
organisation escrow keys to wrap the new roots. PostgreSQL publishes the
grant, key copies and audit record together. The workflow supports adding
permissions.

Schema 65 adds **Rotate boundary keys** to the same group grant panel. A
custodian can review and reduce or revoke one group's View or Use grant on
a shared boundary. The transaction publishes the next signed root generation,
keeps the certified recipients who still hold the affected permissions, rewraps
the existing DEKs and retires the previous root and its copies. Stored credential
and note envelopes stay unchanged.

Schema 66 adds removal of a member from a keyed group. **Groups** reviews the
remaining certified recipients and the exact affected boundary roots. PostgreSQL
commits the new group generation, membership revocation and rotation queue in one
transaction. Affected roots cannot be used for new writes until their boundary
rotates. The custodian can use **Resume key rotation** after reopening the group.
When the last enabled member leaves, the new roots go to the other authorised
recipients and the group's configured grants are retained.
Windows Electron and PostgreSQL 16.15 tests cover the full flow on one shared
boundary. Native tests rotate two shared boundaries independently and verify
that a restore on a second cluster preserves the pending queue and write guards.

Schema 67 extends the existing break-glass wizard to multiple active shared
boundaries at Default and Standard. Go verifies each signed boundary manifest
and both organisation escrow copies before it prepares the administrator's
certified invitation. PostgreSQL ties publication to the reviewed graph. A
pending root can be rewrapped through the scoped recovery invitation and its
one-time Join role. Ordinary writes under that root remain frozen until it
rotates. The recovered administrator receives boundary custody. Access to each
node follows its existing grants. Earlier single-boundary checkpoints can still
be resumed. PostgreSQL 16.15 tests recover a new administrator, resume an
archived job on two shared boundaries and open their replacement roots. The
Electron emergency recovery test confirms the new device and delivers two
account reset offers.

Schema 68 adds certified members to keyed groups from **Groups**. The review
matches the account to its enrollment certificate and shows how many shared
boundaries the group can open. Go verifies that the signed previous roster gains
exactly the reviewed account. PostgreSQL commits the membership, next group key,
member copies, current boundary wraps, audit entry and retry receipt atomically.
Adding the first member to an empty keyed group restores key access for its
configured boundary grants. The existing View and Secret roots and stored
envelopes stay at their current versions during addition. Pending removals must
finish before membership can expand. PostgreSQL 16.15 tests cover additions to
both empty and populated groups, opening the current roots with the new member's
keys across two boundaries, and rollback of a substituted wrap. The Electron
test confirms re-adding the last removed member through the protected panel.

Schema 69 resumes pending member rotations after a certified roster changes.
**Groups** shows the affected group, the current certified recipients and the
number of boundaries that need new roots. Confirmation advances the group key,
retires its prior recipient copies and queues the roots held by that generation,
including any boundary already rotated during the same job. Roots in the queue
keep their actual retired holder generation through backup and restore. When two
jobs share a root, the worker verifies both recipient sets and publishes one
replacement root with audit entries for each job. PostgreSQL 16.15 tests cover
disable and re-enable, overlapping jobs and a restore with multiple retired
generations.

Schema 70 adds account suspension and device revocation over Verified TLS.
Administrators review and confirm access changes from **Accounts** and
**Devices**. Members can list and revoke their own devices under **My devices**.
Suspension invalidates existing admissions and unused reset offers. Re-enabling
an account requires a fresh admission. Device revocation clears the PostgreSQL
role's password, sets `NOLOGIN` and invalidates its admission in the same
transaction as the audit entry. PostgreSQL denies subsequent API calls on
already open connections.

Schema 71 captures direct and group-wrapped boundary keys when an account is
suspended, including roots in pending group rotations. It records references
to encrypted passwords under those roots in the same transaction. On a
suspended account, **Review access at suspension** shows both lists. Entries
are restricted by the viewing administrator's current boundary permissions.
Encrypted workspace archives preserve the recorded scope. A suspension
created before this schema is shown as having no recorded inventory.

Schema 72 lets an organisation custodian rotate a captured View or Secret root
of an escrowed shared boundary from the suspension inventory. The captured
generation freezes writes while the account is suspended. Publication signs a
new root, retains eligible recipients and rewraps the existing data keys in one
transaction with audit. The inventory reports the old root as retired. Related
group jobs can retire that root together through **Groups**. Each related
group can queue its change before the worker publishes a single replacement
root.

Schema 73 extends the suspension inventory and manual rotation to the
suspended account's personal import boundary under signed organisation
escrow. A verified custodian sees the captured key coordinates. Personal
password references stay restricted. The custodian can rotate each root and
rewrap its data keys, keeping the replacement root in organisation custody.
The old root freezes writes until rotation. Enabling the account before
rotation remains available. Once either root is retired, enabling the account
requires a fresh certified enrollment and owner copies of both current roots.

Schema 84 adds **Persistent web sessions** to **Review access at suspension**.
Each device reports the target under its current View generation before saving
a checkpoint and withdraws its report after erasing the local archive. A saved
archive from an earlier schema is reported when it is next read or saved.
The suspension transaction captures one entry per reported target before
retiring the account's live generations. An interrupted save may leave a
conservative report. The administrator needs current View on the target and
View and Manage on the captured boundary to see its name and identifier.
Encrypted workspace backups preserve these suspension reports. Cookies stay
in the encrypted device-local archive.

The shared catalog opens saved HTTP and HTTPS connections in the isolated
browser. Go requires the current shared admission, verifies the signed
resolver chain, and commits its trust observations before handing the target
to Electron. A configured tunnel uses its authenticated route. Shared browser
state stays in memory and a catalog update that withdraws Use closes the
browser. Schema 82 lets HTTP(S) connections with retained Reveal accounts
use a signed web plan and the same local archive flow. The server requires
Use and omits the retained account, and Go independently checks the signed
target and ancestry. Schema 83 extends this to VPN routes. The web route
uses a dedicated one-use ticket with a committed audit entry. The graph
carries the tunnel settings only. An IPsec fallback still requires its own
audit and Go verifies the encrypted reference from the primary settings
before opening the fallback. PostgreSQL 16.15 integration tests cover both
releases, permission denial, and ticket reuse.

Go can now keep a device-local encrypted web session archive for a saved
target in Default or Standard. The archive is bound to the account, vault
file, target, certificate policy and exact tunnel configuration. Each access
revalidates the current plan and shared admission. Electron main can retrieve
an archive through a one-use encrypted response and update or erase it by
revision. Local integration tests verify a 1 MiB round trip and restart with a
configured tunnel.

Local saved targets restore first-party cookies into a fresh in-memory
Chromium profile before navigation. Electron preserves their source port,
path, expiry and first-party partition key. A cookie change invalidates the
prior saved revision and a new snapshot records the current jar. A normal
close reads the jar while the original browser owner still has authorization,
including when Chromium has yet to deliver its change notification. If all
tabs have left the target origin, closing retires the previous snapshot.
Restoring a snapshot consumes it before inserting cookies, so an
interrupted restore can require signing in again. Only one live browser per
node holds the archive lease. Other Chromium storage remains pending.

The shared personal cache locates each archive from its encrypted device,
account and node coordinates. Go can erase archived nodes absent from the
confirmed range of a verified View-filtered catalog page. The native write
uses the archive revision so a stale observation cannot erase a newer
checkpoint.

Schema 81 tracks a random generation for each account and node that opens a
web archive. PostgreSQL retires that generation when the last effective View
grant disappears or the account is disabled. A later grant issues a new
generation, even if the client was offline throughout the revocation. Another
grant that still confers View keeps the original generation. The registry
contains only authority metadata and stays with the live database.

Go binds shared archive reads and writes to the current generation and
reconciles encrypted records in bounded batches during authority polling.
This covers nodes beyond the catalog pages opened by the renderer. Electron
restores cookies for eligible shared targets. It checks active browsers after
catalog changes and every 30 seconds, closing the affected browser and clearing
its in-memory partition if the grant is revoked or cannot be verified. A Windows
Chromium test with PostgreSQL 16.15 verifies cookie restoration after restarting
and readmitting the native shared vault. PostgreSQL and Electron tests separately
cover access revocation and affected-partition cleanup.

Schema 74 adds **Groups at suspension**. The report lists each captured group
whose shared boundary is visible and manageable by the administrator. It shows
whether the suspended member remains in the group, a job is queued, a different
member's job is in progress, or the membership was removed. Opening a listed
group uses its current revision and the existing reviewed removal flow. A
queued entry resumes the exact job for that account. Returning to the inventory
refreshes all captured groups, so related removals can be queued before
resuming their shared boundary work.

Schema 75 binds group removals opened from the suspension inventory to the
recorded revision of that suspension. PostgreSQL checks the account's
suspension and captured group at review and at publication. Re-enabling or
suspending the account again invalidates an open review. A committed job keeps
its suspension revision so the exact confirmation can reconcile a lost reply.

On a supported shared workspace with verified TLS, confirming **Disable
account** also saves the account ID and the resulting suspension revision in
the administering device's encrypted trust file. While that administrator
is signed in, the Go backend reads the captured inventory, rotates eligible
View and Secret roots, and removes the suspended account from eligible keyed
groups. Each publication checks the reviewed key, group or recipient roster.
Restarting the device and unlocking the workspace resumes the confirmed
suspension. Re-enabling the account ends that work. A later suspension has
its own revision.

Restricted entries stay pending for a custodian with access. An overlapping
rotation that requires decisions about another group can be reviewed under
**Groups at suspension**. Other devices can use the protected inventory to
review outstanding work.

Schema 90 publishes an organisation-signed suspension receipt when the
administrator has custody of the signing key on a TLS-required workspace.
Another signed-in custodian can then discover and continue the rotation over
verified TLS. A Windows Electron test uses separate device profiles, stops the
issuing administrator's process, and checks that PostgreSQL records the other
administrator as the actor who retired the captured key. See the
[shared admission controller](vault-shared-admission-controller.md).

A second Standard test uses three accounts. One administrator suspends a
group member and exits while PostgreSQL holds the original group key active.
After the lock is released, the surviving member signs in on their own
administrator device. The database audit identifies that device's account
as the actor for the group change and the dependent View and Use rotation.

Schema 76 preserves the previous public enrollment certificate when the
account's signing key changes. Rotation workers can authenticate old data-key
copies against that certificate. Encrypted workspace archives retain the
history. Restore checks that the recorded signing key belongs to its account.

Schema 77 records the enrolled signing and encryption keys and signed account
state at suspension. After a personal root has rotated, Enable requires newer
account state, a different enrolled key pair and organisation-signed copies of
both current roots for the new owner. Workspace recovery retains the captured
enrollment. Restore of an earlier archive reconstructs it from the enrolled
keys and account state present in that archive.

Schema 78 lets a custodian review both rotated personal roots and publish the
two encrypted copies to the certified replacement enrollment in one database
transaction. **Restore personal keys** in the protected suspension inventory
shows the replacement enrollment and collects fresh local factors for the
confirmation.

Schema 79 adds the signed replacement offer and a restricted temporary SCRAM
role. The offer pins the suspended account and recorded suspension. Its code
and ASK open only new bootstrap keys. The recipient generates the replacement
key pair locally and certifies it from that bootstrap.

Schema 80 registers the replacement keys and device atomically. The protected
suspension inventory lets a custodian issue the offer after both personal roots
have rotated. The recipient saves a protected local checkpoint, registers the
device and waits for the custodian to restore the roots and an administrator to
re-enable the account. The recipient can resume from the same checkpoint after
restart. Windows Electron and PostgreSQL 16.15 covered issuance, rejection of
wrong custodian factors, registration while suspended and sign-in after
reactivation.

An admitted shared vault now checks its own account and device in Go while
the application is idle. PostgreSQL change notifications prompt an
authenticated check. The 30-second fallback runs with or without LISTEN,
including behind a transaction-mode pooler. An unauthorised device, a suspended
account, or a newly signed account revocation retires the native owner.
Electron uses its normal vault lock to close the application's active sessions.

This is an **incomplete implementation of #495**. Existing legacy workspaces use
their existing secret stores and app lock until the user opts into
[workspace migration](vault-legacy-migration.md) in Settings > Security. The
application detects an existing
native vault before legacy startup, mounts the password/recovery unlock screen and
loads its authenticated workspace after unlock. First launch on an empty local
workspace offers protected creation in a dedicated recovery dialog. Password
and recovery slots are published after confirmation of two random groups.
At Default, **Skip for now (Unprotected)** creates an OS-protected slot. The
workspace shows a warning and a **Protect now** action until the user upgrades it.

Native tree deletion, movement, connection duplication and folder/connection creation and editing are connected to
the app at Default and, with per-action authentication, Standard. Native credential
creation, editing, deletion and protected credential reveal are also connected. Tunnel creation, editing and deletion
now use a dedicated protected document and revision-checked native mutations.
SSH terminals, standalone SFTP connections, shared SFTP tabs, VNC connections and saved local/shared RDP connections use native credential handoffs
directly or through supported native VPN routes. SSH/SFTP include native first-use
and changed-host-key confirmation. Vendor authentication/cache adapters,
other protocol flows, remaining legacy stores and parts of shared administration
remain unfinished. Full Hardened/Paranoid workspace admission is pending.
Existing-workspace conversion is opt-in, requires confirmed
recovery and a fresh password/recovery unlock after restart. The native staged
copy, authenticated retirement and atomic publication are now connected to this
flow; the vault is still not a complete replacement for every daily workflow.

The following building blocks are implemented and tested:

- [Local root-factor replacement](vault-root-rotation.md) is connected to Settings
  and the protected enrollment/recovery windows. Main quiesces sessions while
  retaining the resident Go owner; current password/recovery verification and
  two replacement recovery groups precede journal preparation. Native exit and
  isolated startup require the new factors before adopting the rotated graph.
  Cancellation, stale replies, concurrent confirmation and retained/full shutdown
  are tested, including actual Electron/Go flows. The native v2 journal now also
  records explicit OS-custody intent and key/file receipts; Windows tests resume
  that journal through the actual protected prompt and remove the old DPAPI file
  before owner adoption. A separate isolated native enrollment now confirms new
  factors before a one-use scope can stage an OS source under a stronger policy;
  ordinary source opening remains denied and partial cleanup stays reachable.
  **Protect now** opens this workflow from startup or from an open workspace.
  The desktop-client test reopens an OS-only vault in a new process, rotates its
  root and uses the replacement recovery code after a second restart.

- [Native VPN retirement](vault-tunnel-retirement.md) now keeps the original
  sidecar/controller ownership through OS-confirmed exit, including failed
  startup, with configuration wiping before retirement. Main quarantines an
  unconfirmed controller and blocks replacement configuration/provider attempts.
  The [fallback source API](vault-tunnel-fallback.md) binds the exact primary
  and secondary sources to a distinct attempt. Local Go planning and sealing now
  resolve the encrypted reference, authenticate both sources and persist denial
  observations before publication. PostgreSQL migration43 now provides a
  separately audited, purpose-bound secondary release and a strict native
  ciphertext decoder. Shared Go verification, protected trust/anchor publication
  and source-reference validation now participate in native stdio planning and
  sealing. Strict main codecs/client/host and a separate native SSL recipient now
  exchange the exact source pair. Secondary startup, cookie challenges and
  OS-confirmed cleanup are tested independently. Main now joins original IPsec
  controller/authentication retirement before creating a separate SSL recipient.
  Pooled leases retain each consumer's logical primary and require independent
  target Use; both source configurations identify the pool. All four production
  brokers propagate the pair. Pair-aware retained SSL SSO source admission and main browser
  adapters now reauthorize both sources for each archive action, with native
  checkpoint/receipt guards. Real Chromium/Go storage tests cover local/shared
  fallback sources. Ordinary launch guards remain enabled; the explicit primary
  actor removes only the authenticated fallback control field in Go. Real Go
  primary/secondary recipients and slow synthetic sidecars pass through the
  production broker. Real provider interoperability remains unverified.

- [Personal VPN SSO archive custody](vault-vpn-sso-state.md) now provides encrypted
  Go-owned archive storage with binding/revision checks, borrowed-buffer wiping,
  bounded native attempt reservations and authenticated deletion. Native browser
  capture/restore is connected for supported Fortinet SSL and IPsec SAML storage
  in local and shared workspaces, with personal/device custody for shared sources.

- [Native VPN SSO archive transfer](vault-vpn-sso-transfer.md) now connects
  independently purpose-bound HPKE chunks to Go custody, with original attempt
  binding, restore acknowledgement, source-floor checks, one-use commit and
  joined key cleanup. Independent Node-to-Go interoperability is tested. Native
  browser storage/recipient adapters now participate in owned Chromium sessions.

- [Native SSO admission and checkpoints](vault-vpn-sso-native.md) connect local
  and shared Fortinet SSL/IPsec source re-resolution, authenticated slot-container v2 high-water
  marks and six bounded production stdio operations to an original-process
  Electron capability. Denied source deletions retain their observations, and
  repeated native cleanup is safe. The authentication browser uses this capability
  before navigation and returns a fresh authentication result after archive commit.

- [Native browser recipient and origin storage](vault-vpn-browser.md) provide a
  disposable Go recipient and binary archive channel, plus an isolated Chromium
  DOM/IndexedDB serializer that preserves structured types and key generators.
  Real Go/SQLite and Chromium round trips pass for local/shared SSL and IPsec.
  The session driver binds cookies and storage partitions to the original actor.
  Workers, service-worker/cache state, nonextractable keys, real provider testing
  and a single live PostgreSQL enrollment-to-browser deployment remain unfinished.

- [Fortinet SSL SSO](vault-fortinet-ssl-flow.md) now uses an isolated native browser,
  a fresh Go-owned recipient and a purpose-bound cookie handoff across all four
  route brokers. Completion requires a fresh HttpOnly gateway response and its
  matching native cookie-store commit. Saved bearer values cannot bypass login.
  Supported provider SSO is retained through the native encrypted archive. Actual
  IPsec-to-SSL fallback now has connected native actors and broker authorization;
  real provider interoperability remains unverified.

- [Fortinet IPsec](vault-ipsec-flow.md) now has authenticated local/shared metadata,
  encrypted legacy transfer, a protected editor and PEM import, and sealed native
  handoff for noninteractive PSK/certificate authentication with disabled or saved
  user authentication. Multi-file imports accumulate atomically in one encrypted
  editor-owned stage. PostgreSQL migration 41 extends the provider enum without
  changing grants. Prompted login uses a dedicated protected document and a
  one-use native HPKE recipient, with original-owner cancellation and confirmed
  cleanup across all four route brokers. SAML now uses a separate native recipient,
  Go-owned UID/callback and an isolated browser with cipher-only token handoff.
  It requires a fresh login result after encrypted provider SSO restore/retention;
  SSL fallback now has connected native actors and broker authorization. Shared catalog deployment requires
  migration 42 for final enrolled author proofs and recipient key selection.

- [Saved RDP connections](vault-rdp-flow.md) now use node-only vault admission in
  main/preload, local App sessions and shared catalog tabs. Go owns authenticated
  resolution, passwords and the native process; main owns HWND geometry, owner
  lifecycle, certificate confirmation and route leases. Pending cancellation,
  reload/destruction, lock and shutdown retain reservations until native cleanup
  is confirmed. The existing surface waits for measured bounds; hidden background
  sessions remain hidden across native connection/reconnection events. Unit,
  actual-source, Chromium and actual ActiveX tests cover these paths above the
  80% coverage threshold. Protected temporary RDP accounts now use the dedicated isolated document and
  manual-only native authorization, including direct/VPN bindings and independent
  gateways. Local unsaved RDP Quick Connect now admits public target metadata into
  a bounded Go-owned ephemeral registry, uses protected temporary entry and joins
  original-owner target retirement with native shutdown. Real vault RPC tests
  verify cipher-only handoff and an unchanged catalog. Shared Quick Connect,
  Windows external/AzureAD execution and profile-specific session policies remain
  open. No successful real remote account or RD Gateway login is claimed.

- [Local SSH/SFTP Quick Connect](vault-ssh-flow.md) now uses the Go-owned
  nonpersistent target registry and protected temporary account/key/certificate
  entry. Saved-key passphrase replacement uses the same isolated document,
  including an explicit empty override without stored-passphrase fallback.
  Terminal and SFTP aliases share one native cohort; the target stays reserved
  through process, route and document shutdown. Preauthorization reservations
  and generation checks fence cancellation, reload and queued terminal/file
  commands. Actual App/main tests, Chromium document tests, Go interoperability
  and real direct/routed SSH/SFTP servers cover this boundary. Shared temporary
  SSH targets and later session/security policies remain incomplete.

- Native VNC credential handoff now has a bounded binary format and an
  authenticated owner API for direct and routed bundles. Absent, empty and raw
  password bytes remain distinct; the decoder borrows the frame and callers wipe
  it after use. Native resolution and secret borrowing hold one owner lock, so
  concurrent connection edits cannot mix host and credential. HPKE authenticates
  workspace, node, session, request, protocol, destination and exact VPN
  configuration/endpoint; a routed connection cannot request a direct fallback.
  Exact native request schemas reject renderer-style password/host/key overrides.
  Codec, substitution, absence/empty, malformed input, native entry and concurrent
  edit tests cover this boundary. The native `vnc-sealed` recipient now consumes
  one ephemeral X25519 key and accepts only its authenticated opening and bounded
  pointer/key/close/lock controls. EOF, malformed controls and lock close the
  socket and join the worker before clearing its frame. Native RFB authentication
  handles 3.3/3.7 (negotiated as 3.3) and 3.8, including explicit empty passwords
  and the mandatory 3.8 None security result. Password bytes are consumed once;
  server error reasons are never allocated or forwarded, desktop names are
  capped at 4096 bytes, and dimensions are checked before parser allocation.
  A bounded replay of public handshake metadata lets the existing parser retain
  its framebuffer and input behavior without handling plaintext credentials.
  Real CLI/socket tests cover authentication, frames, input, connected lock and
  failure of a VPN proxy without a direct fallback. Electron now has a main-only
  VNC relay and strict direct/routed bundle methods on its native vault client and
  authenticated host. The relay binds each ephemeral key to its own process,
  bounds input/output, checks PNG headers/dimensions, drops stale owners and
  releases VPN leases on termination. Unconfirmed shutdown retains session
  identities and blocks further opens. Real process tests authenticate against
  a fake RFB server through both a direct socket and a native VPN sidecar while
  the vault owns SQLite; Electron receives ciphertext only. These tests are in
  the vault CI/coverage suite. Saved VNC connections are now wired into the app's
  existing command bridge with exact vault schemas and one main-frame owner.
  Input and events cannot cross windows; reload/destroy retires the owner, and
  rapid reconnect joins the old native recipient before admitting a replacement.
  Both application lock and general shutdown await VNC/route exit confirmation.
  The VNC surface sends only node/session/credential identifiers in vault mode,
  preserves the legacy command projection outside vault mode and suppresses its
  ordinary password/Bitwarden entry fields for vault sessions. A real Chromium
  test measures the component above 80% V8 block coverage, including keyboard,
  pointer, reconnect, failures and vault/legacy projection. A password-required
  failure now offers “Enter password securely”, opening a separate sandboxed
  password document; no password enters ordinary app state. Its ephemeral input
  is cleared before encryption, only ciphertext crosses the dedicated preload,
  and cancellation, navigation, lock and tunnel loss retire the document.
  Unconfirmed document destruction prevents successful lock acknowledgement.
  The native temporary-password flow is connected to this document: the
  `vnc-plan` operation returns public context without fetching a saved password;
  `vnc-manual-bundle`/`vnc-manual-route-bundle` re-resolve that context and wrap
  only an opaque envelope supplied by the isolated password document. A distinct
  `vnc-manual-sealed` recipient requires both owner authorization and the
  purpose-bound password envelope. It cannot fall back to saved credentials.
  Direct/routed, substitution, explicit-empty, malformed-input and real RFBAuth
  tests cover the native layer. A real sandboxed Chromium document using the
  actual preload encrypts a synthetic password that Go independently opens.
  Local unsaved VNC Quick Connect now uses the same bounded Go-owned target
  registry and isolated password document. Main reserves and joins authorization,
  late registration and original-owner retirement; input is bound to one admission
  generation. Public manual intent survives disconnect, surface remount and tab
  duplication, with fresh password entry and no saved fallback. Saved VNC catalog
  tabs and protected RDP/VNC copies use canonical native IDs. Actual App creation
  and real Go/RFB tests cover saved/unsaved, saved/manual and direct/VPN variants
  without adding catalog nodes for unsaved targets. Shared Quick remains pending.

  Direct and native VPN relay tests authenticate with a temporary password
  different from the saved credential, stream frames and exercise controls.
  The ordinary app supplies only an explicit mode flag and public identifiers;
  the manual-only recipient prevents any saved-password fallback. The protected
  password document and VNC surface each have a measured 80% V8 block gate.
  Native shutdown also handles delayed Windows exit notifications through a
  secret-free Go kernel-wait proof for the exact owned child/PID. Signal-zero
  ESRCH and an early exit code are insufficient: Windows may still report an
  unsignaled process handle. Access/wait/close failures remain unconfirmed.
  App/SSH/RDP owners retain and quarantine uncertain processes, block replacement,
  and permit verified cleanup retries. Old app-process callbacks cannot stop or
  corrupt a replacement. Native, failure-path and actual-source lifecycle tests
  measure the new code above the required coverage gate.

- Bitwarden now has a shared Go/browser sealed-transfer format and isolated
  capture/restore helpers. Context binds workspace/file/profile/request/transfer,
  epoch/policy/action/revisions and both recipient keys. Up to 8 MiB per JSON area
  streams as five bounded packets; ordinary main receives ciphertext and public
  receipts only. One-use binding, ordering, malformed/retagged packets, partial
  cancellation and immediate clearing during asynchronous apply are tested.
  Real Go/Node interoperability covers the maximum payload, and sandboxed Chromium
  verifies the same code without Node/app access. Production Go staging/RPC now
  owns bounded expiring ephemeral keys and encrypted packet staging. An isolated
  extension adapter/controller handles actual MV2 background memory or MV3 session
  storage, conditional per-key restore, cancellation and byte clearing. The normal
  build packages its browser-only IIFE. An original-client coordinator validates
  opaque exchanges and captures actual resulting state after restores, with a
  bounded checkpoint loop and retryable, positively acknowledged cleanup.
  The exact installed-document endpoint now validates native frame/session identity,
  sandbox provenance, bounded calls and cancellation generations. Native Windows
  tests exchange sealed state with Go through a real extension background. Safe
  hosting remains open: stock Electron rejects nonpersistent extension sessions,
  while diagnostic persistent profiles write storage to disk. Installation/settings
  and app lifecycle remain open; the vault Bitwarden button is not enabled.

- The native owner now has a Bitwarden browser-state component, using its existing
  encrypted local-state store for compatible migrated primary records. Only local
  JSON changes write durable snapshots; session-only updates and per-context merge
  bases stay encrypted in owner memory and disappear on close. Hydration takes an
  actual captured witness, and merges retain submitted state rather than assuming
  conditional restore succeeded. Tests cover stale refresh after logout, partial
  restore/rehydration, failed delivery, cold restart, policy/record tampering and
  bounded profiles/cache (including the state retained after acknowledgement fails).
  No ordinary IPC endpoint can serialize these borrowed secret snapshots. Native
  extension installation/settings, application wiring and verified Bitwarden relock
  remain open; the vault app still skips the legacy extension flow. The sealed
  transport/controller/coordinator are covered by real Go/SQLite interop, including
  maximum-size state and actual acknowledgements across profiles. See
  [the transfer boundary](vault-bitwarden-transfer.md).

- Native HTTP/HTTPS target planning now uses the authenticated vault owner.
  `web-plan` resolves inheritance, protocol-specific ports, leaf-only certificate
  rules and exact tunnel revisions under one owner lock. It reads public routing
  metadata only, including no tunnel settings or migration/credential secrets.
  The existing Go URL/path normalizers remain authoritative; saved paths still
  omit query and fragment. Exact typed client/host parsers bind workspace, node,
  session, request and authorization epoch, reject metadata/URL/route substitution
  and drop replies after owner loss. No general renderer endpoint exposes this
  native API. Same-revision metadata tampering, inherited port/certificate rules,
  malformed requests and real SQLite/stdin interoperability are tested. The
  `VaultWebConnections` preparation component now owns a native route lease per
  browser, rechecks target/path/certificate and all route revisions after VPN
  startup, and rejects changes or a direct fallback. Cancellation/timeout reject
  immediately while late native work is discarded/released. Unconfirmed exit
  reserves identity and blocks replacement. Saved HTTP/HTTPS connections now use
  this native flow in the application browser. Main-frame IPC and window/generation
  ownership reject foreign or stale opens; one nonpersistent Chromium partition
  and lease serve every tab. Main applies direct/SOCKS policy before navigation
  and omits endpoints from renderer responses. Lock/quit await actual view
  destruction and cookie/storage/cache/connection cleanup as well as route exit.
  Real Chromium tests confirm shared routes, no direct fallback and cookie removal.
  Local HTTP/HTTPS Quick Connect now reserves its document/browser owner before
  authorization and registers one Go-owned temporary target per browser. Go
  normalizes pasted URLs, IPv6, explicit ports and ephemeral query/fragment data;
  only the authenticated temporary plan can retain that URL context. Quick targets
  never become catalog rows. Saved and duplicated vault tabs have canonical IDs
  so protocol edits can retain their tab identity. Route shutdown runs alongside
  forced view/profile cleanup; target retirement follows positive confirmation of
  both. Failed cleanup retains ownership and permits an explicit confirmed retry.
  Reload, cancellation, lock and destruction join late registration, including
  after the owner window is already destroyed. Real Go and Chromium tests cover
  direct/routed admission, shared tabs, cookie retirement and unchanged catalogs.
  See [the web flow](vault-web-flow.md). Shared Quick Connect still requires audited
  server admission. The native Bitwarden/SSO adapter remains open; vault browser
  startup skips the legacy extension store.

- The tree's Show credentials action now resolves native local passwords and SSH
  passphrases through the authenticated `reveal` path, including inherited and
  migrated account choices. `credential-display` verifies the selected node
  revision and requires a fresh one-action unlock at Standard. The native owner
  encrypts identity and the selected secret to the isolated window's one-use
  X25519 key under `wormhole/v1/credential-display`; private keys are not exported.
  The fixed binary payload bounds identity fields to 2048 UTF-8 bytes each and
  the password/passphrase to 16384 bytes, matching the native credential editor.
  Main relays ciphertext only. The protected document clears on close, lock,
  navigation, parent loss and its five-minute deadline; authentication is parented
  to that document. The ordinary app state receives no revealed credential.
  Existing notes reuse the same protected window lifecycle while retaining their
  distinct cryptographic purpose. On Windows, explicit Copy buttons send only a
  field identifier to main; Go resolves the exact node revision again and writes
  the selected username, domain or password/passphrase through its own hidden
  message window. Standard requires fresh authentication for each copy. Go keeps
  an ownership ticket rather than plaintext and attempts expiry after 30 seconds
  (Default) or 20 seconds (Standard), retrying temporary clipboard contention.
  An OS-locked owner/sequence comparison prevents clearing another application's
  replacement; lock/shutdown also attempts bounded cleanup. Windows history and
  cloud-sync exclusion formats precede text under the clipboard lock, following
  [Microsoft's clipboard-format contract](https://learn.microsoft.com/en-us/windows/win32/dataxchg/clipboard-formats).
  The exclusion hints do not prevent arbitrary third-party monitors, and cleanup
  cannot be guaranteed after a crash, forced process termination or persistent OS
  contention. macOS now uses a Go-owned AppKit adapter with current-host-only
  preparation plus the TransientType and ConcealedType
  [pasteboard markers](https://nspasteboard.org/). Expiry replaces only its UTF-8
  representation with empty data: AppKit's
  [conditional setData contract](https://developer.apple.com/documentation/appkit/nspasteboard/setdata%28_%3Afortype%3A%29)
  refuses a changed owner, avoiding the race in a check followed by clearContents.
  The native adapter copies borrowed Go bytes synchronously, wipes its mutable
  native buffer and confines Objective-C exceptions to fixed error codes.
  A private-pasteboard AppKit harness and LLVM coverage gate run on macOS CI;
  their native results have not been verified on this Windows development host.
  Linux now has a sealed backend-to-main release endpoint and a one-use main
  recipient: HPKE binds the selected field, workspace, node, request and revision;
  the authenticated payload carries a native policy TTL and only the chosen
  UTF-8 value. Standard requires fresh authentication for each release. Identity
  copies do not decrypt the saved password. Mutable plaintext buffers are wiped
  after consumption, and the decoder borrows bytes without creating a JS string.
  The shared recipient utility now lives with the Electron contracts so both
  main and isolated documents compile against the same implementation.
  Linux copy is now wired through main, using Electron 44.10.1's
  [atomic multi-format clipboard API](https://www.electronjs.org/docs/latest/api/clipboard).
  A single item publishes raw UTF-8 targets, the `x-kde-passwordManagerHint=secret`
  exclusion hint and a random ownership marker. Raw targets avoid Chromium's
  automatic text mirroring to PRIMARY; the selection clipboard is not touched.
  Expiry and lock cleanup inspect only that marker, retain no password, retry
  transient OS failures and serialize with subsequent copies. In-flight release
  recipients and mutable plaintext are invalidated on lock. Older timer callbacks
  cannot erase newer copies. The app displays only the native TTL acknowledgment.
  History exclusion is cooperative. Electron exposes no atomic compare-and-clear:
  a different process can replace clipboard content between marker inspection
  and clearing, so preservation of external writes in that race is not guaranteed.
  Crash/termination and persistent OS contention have the same cleanup limits
  described above. The isolated Xvfb test checks real formats, PRIMARY isolation
  and replacement preservation on Linux CI; it has not run on this Windows host,
  and Wayland desktop verification remains pending. Native Bitwarden reveal is
  still unfinished. Electron's asynchronous terminal paste now rechecks the same
  authentication epoch before forwarding input. Its lazy binary installation is
  completed before parallel vault tests start.
  Legacy workspace reveal retains its existing behavior.

- The sealed SSH process and its main-owned relay accept bounded SFTP browsing,
  file operations and uploads/downloads on the existing authenticated transport.
  Commands have exact per-operation fields and strict nested transfer items;
  session substitution, credential/route overrides, unscoped editor commands and
  arbitrary control messages retire or reject the request. The sealed child
  admits at most 32 background file jobs and eight transfers, closes admission
  before shutdown, cancels transfers and joins file work before returning.
  Listings truncate visibly before exceeding the relay's frame budget, including
  directories containing thousands of individually legal long paths.
  Main checks the trusted owning document after asynchronous authorization and
  sends file events only to that session's window. Tests exercise actual encrypted
  handoffs, SSH/SFTP upload/download over direct and synthetic VPN routes, conflict
  cancellation, malformed messages, work limits and oversized listings.
  The native process now also implements bounded external-editor commands and
  recovery prerequisites. Trusted startup paths select settings and a private
  working-copy directory; the authenticated handoff selects its workspace/node
  scope. An OS file lock prevents concurrent processes from owning the same
  scope, and another workspace or connection gets a different directory.
  Recovery matches server, account, host key and the authenticated VPN file,
  configuration ID, provider and configuration version. Shared SFTP tabs retain
  this identity; transient SOCKS ports and session IDs do not alter it. Native
  retirement joins editor work and watchers before releasing ownership, retains
  unsent edits, and requires explicit recovery after a disconnected session.
  Oversized editor snapshots fail as a whole so close preflight cannot hide
  pending edits. Tests cover sealed handoffs, automatic upload, missing owner
  configuration, native CLI paths, concurrent ownership and retirement.
  External-editor working files are private OS-protected files, not encrypted
  vault records, and remain available for recovery after lock. The Electron
  relay now supplies trusted startup paths and forwards strictly validated editor
  commands and owner-scoped events. The existing editor UI can open, upload and
  recover working files after reconnecting to the original node. File-transfer
  settings use the unlocked native vault owner rather than legacy startup, with
  bounded exact schemas, preservation of unrelated preferences and rejection of
  oversized encoded responses before a write. Close preflight is scoped to the
  closing window (or all active tabs on quit), deduplicates pending copies and
  fails on incomplete responses. Empty tabs do not acquire another process's
  cache lease. Pending requests are bounded, bound to a session and rejected on
  retirement. Tests launch a synthetic external editor through the production
  relay/native path and verify uploaded and recovered bytes on direct and VPN
  routes, including shared SFTP tabs and reconnecting from an SSH node.
  Settings → File transfer now includes a native vault recovery panel: it lists
  retained archives without reconnecting, resolves current public connection names,
  pages through connections and records, refreshes inventory, opens private copy
  folders and discards an explicitly confirmed copy. Busy archives direct the user
  to the active File transfer tab; disconnected copies can be managed directly.
  Upload still requires reconnecting to the original server/account/host key/route.
  Late replies cannot overwrite a newer selection or revive an unmounted panel.
  The trusted IPC checks its submitting document before and after native work, and
  the isolated preload carries only typed public metadata and selected actions. Native
  offline scope discovery is implemented as a read-only, workspace-scoped,
  bounded scan with 64-node sorted pages. Its native owner API now derives the
  workspace from the authenticated owner and accepts only a canonical cursor.
  Trusted startup paths propagate from main to that owner; the client validates
  ordered, unique pages and rejects replies after lock or owner replacement. The
  owner also exposes per-node offline record pages (at most 32 records and 256
  KiB), folder reveal and confirmed discard under the same exclusive native
  scope lease used by active transports. Busy scopes return no records or
  mutations. Requests cannot choose filesystem paths, and malformed or foreign
  manifests are omitted; client replies are bound to the selected node and copy
  only declared public fields. The App selects the vault panel from its
  authenticated mode, while legacy workspaces retain the existing recovery
  component. Chromium tests exercise both flows, confirmation, busy/error/empty
  states, pagination, stale selection and unmount, including the shared Settings
  entry point.
  Linux/macOS GUI editor behavior has not been verified on this Windows host.
  The existing File transfer action now opens independent shared SFTP tabs from
  an authenticated SSH or SFTP tab, without another credential read, dial or route
  lease. Each tab owns its subsystem; closing its source preserves the remaining
  tabs and the VPN until the final tab closes. Go owns the session registry and
  transport references; main owns tab/window bindings and routes events by ID.
  At most 32 active tabs share a transport, with 1024 lifetime identities reserved
  against late-message reuse; main also bounds the total active tab reservations
  to 128. Closed native objects are released while only their identities remain.
  Cancelling a pending subsystem cannot revive a tab or close a healthy sibling.
  An unconfirmed forced shutdown rejects pending close calls and retains ownership
  until process exit is actually observed. Disconnected tabs can complete the
  editor-free close preflight without obtaining file-operation authority.
  Saved standalone SFTP connections now resolve their own authenticated protocol
  path, including migrated account choices, and open only the SFTP subsystem.
  No shell, PTY or auto-sudo is started. Host confirmation, encrypted handoffs and
  VPN leases are bound to that protocol; terminal commands and cross-protocol
  substitutions are rejected. Real-process tests cover direct and synthetic VPN
  transfers, shared tabs after source closure, and VPN loss.
  File tabs originating from SSH can reconnect without changing to the SFTP
  account path: their native handoff explicitly authenticates file-only mode while
  preserving the stored node protocol and selected credential override. Reconnect
  revalidates the host and route; direct and VPN process tests reconnect a second
  transport and read previously uploaded files without opening a shell. Saved-node
  duplication preserves explicit overrides and starts only one connection.
  External-editor recovery and automatic native retry still require vault integration. No legacy credential/database startup is enabled to
  bridge those missing paths.

- Native `tunnel-edit` applies bounded, provider-allowlisted settings patches to
  the encrypted configuration. Omitted fields stay native; explicit null removes
  a field; provider replacement discards the old configuration. Go owns provider
  normalization, preserves omitted password/TOTP bytes, clears unused SSO factors,
  and commits against the opening row revision. SSH pins are retained only for
  the same semantic target identity; this editor cannot establish new trust.
  Standard requires one-action authentication. Only the committed ID/revision
  is returned. The typed Electron client and main-owned host now support edit,
  delete and fresh-authentication retries, with owned patch buffers cleared on
  completion, rejection and owner loss. Ordinary-renderer tunnel commands accept
  only a public selection/revision (or a new draft), never settings or recipients.
  Native profile imports are connected through the same protected document; runtime
  cache/lifecycle integration remains unfinished.

- `tunnel-editor-display` authenticates the exact tunnel revision and its encrypted
  settings under one owner lock, projects only allowlisted display fields, and
  seals the result to the isolated editor's X25519 recipient. Its domain is
  distinct from notes, recovery and protocol bundles; workspace, tunnel, request
  and revision are authenticated together. Existing passwords, keys, PEM files,
  imported profiles, tokens and unknown legacy fields never enter the projection;
  known stored factors are represented only by field presence. Plaintext is
  bounded to 512 KiB and cleared after sealing or failure. The Electron transport
  checks the same binding and bounds its response to 768 KiB. Native Go/Electron
  interoperability covers fresh create/delete, edits, redacted display decryption
  and stale-revision failures. Saves also verify projection size, lossless integer
  bounds, NUL exclusion and Unicode compatibility before committing. Renames
  borrow the exact configuration once to check the changed display size, preserving
  its encrypted record and DEK; unchanged metadata-only writes need no secret read.

- The main-owned tunnel window controller, minimal sandbox preload and one-use
  WebCrypto recipient are implemented. Main captures a tunnel/revision or a new
  draft; the child cannot substitute an item, revision, workspace or recipient
  after its first read. Save is unavailable until the existing projection has
  been fetched, and concurrent saves are rejected. Cancellation destroys the
  document immediately and, during a mutation, waits for confirmed native owner
  shutdown before releasing the dialog reservation. Navigation, parent loss,
  renderer crashes and the five-minute deadline close the window. Patch copies
  are cleared immediately after IPC serialization and after main ownership ends.
  Notes and tunnel recipients share HPKE mechanics while retaining distinct
  domains, response validators and plaintext policies. Tests cover actual
  sandboxed preload copies and native Go ciphertext through the production
  recipient. The Tunnel page now opens this document, refreshes the authenticated
  workspace after commit and never loads legacy tunnel settings in vault mode.
  Workspace tunnel summaries carry their exact row revision. App lock and shutdown
  cancel the editor along with fresh-authentication windows.

- The protected form shares provider labels, sections and defaults with the legacy
  editor. Stored factors are represented by presence only; keep/replace/remove are
  explicit and failed submissions require re-entry of replacements. Changing
  provider clears temporary inputs; returning to the original provider restores
  the stored redacted configuration. Explicit removals survive mode switches that
  hide a field. SSH references contain only public identities/names and pins can
  only be forgotten. Native OpenVPN capability probing fails closed and hides
  unavailable providers. Its CLI path is metadata-only and runs before any legacy
  database access; it is the sole exception to the vault's legacy-operation guard.
  Profile-file imports now use the native picker described below; Azure's server
  key remains import-owned. Chromium tests exercise actual HPKE opening, DOM inputs,
  save/error/cancel races, reference validation, capability gates and disposal.
  Provider interoperability and live VPN sessions still require the later runtime
  work and native platform validation.

- Protected tunnel imports support OpenVPN profiles (OpenVPN, WatchGuard and
  Stormshield), WatchGuard bundles, Azure XML and Cisco AnyConnect XML. Main owns
  the file picker and never accepts a renderer-supplied path. Go parses bounded
  regular files without publishing legacy auxiliary keys. The temporary snapshot
  is encrypted in the native owner, bound to workspace/file, editor, import ID,
  provider, opening tunnel revision and expiry; at most eight stages exist, one
  per editor, for five minutes. Replacement is atomic, failed saves can retry and
  successful saves consume the stage. Close, lock and provider changes discard it;
  cancellation during an operation retires the owner before releasing the editor.
  Expiry is enforced on access and expired ciphertext is pruned lazily.

  Only an HPKE-sealed redacted preview reaches the isolated document, using the
  separate `wormhole/v1/tunnel-import` domain. Main injects the active import ID
  into the final edit; the document cannot substitute that ID or opening revision.
  Explicit field edits/removals override imported fields. Imported WatchGuard
  manual mode supersedes the legacy SSO display flag as well as its native alias.
  Invalid decrypted previews close the editor, preventing an old form from saving
  a different staged snapshot. Tests cover Go/TypeScript HPKE interoperability,
  deleting the selected source before commit, actual sandbox preload calls,
  native-picker wiring and Chromium import/error/cancel/provider-change flows.
  These imports store configuration only; VPN runtime integration and live
  provider validation remain outstanding.

- The native `tunnel-bundle` endpoint and main-only typed client/host now release a
  recipient-sealed route configuration. Callers select a connection and optional
  credential override; they cannot supply a tunnel, host or route configuration.
  Go resolves the current authenticated chain and borrows its tunnel under one
  owner lock, including inherited routes and migration choices. Disabled routes,
  unsafe destinations, external RDP paths and invalid context fail closed. The
  bundle binds workspace/file, destination, session/request/epoch, tunnel ID,
  provider and exact row/configuration revisions. The new HPKE domain cannot be
  opened as a credential or editor bundle. The SSH controller now consumes this
  handoff through the shared route broker; vendor authentication/cache adapters
  and the other protocol controllers remain to be implemented.

- `--operation tunnel-sealed` now owns a single ephemeral recipient and VPN
  sidecar without opening a database or initializing legacy caches or logging.
  It decrypts exactly one authenticated route bundle, passes provider configuration
  through stdin, wipes borrowed buffers and returns only a loopback endpoint to
  its native parent. EOF, lock, malformed commands, replay and child exit retire
  the route; blocked startup writes are cancellable. Provider stdout is drained
  and stderr discarded, including when legacy diagnostic debugging is enabled.
  WireGuard, OpenVPN, Fortinet password authentication and Cisco can use this
  native launcher; OpenVPN still requires a successful engine capability probe.
  Fortinet SSL SSO and IPsec SAML now use separate native browser/factor purposes
  and one-use launch witnesses. Retained vendor SSO/cache restore and unsupported
  SSH jump routes remain gated. The application's SSH Connect action reaches this launcher.
  Tests use synthetic sidecars; real VPN-provider interoperability remains unverified.

- Native `tunnel-plan` resolves and authenticates the current destination and
  tunnel revisions without reading its encrypted settings. Its exact metadata
  schema is main-only; it is not a secret-release capability. The typed client
  and host reject stale ownership before and after the native request. The
  `SealedRouteBroker` uses these plans to share one child across up to 128 leases
  (32 processes maximum), keyed by workspace/file, authorization epoch, tunnel,
  provider and configuration revision. Every consumer is resolved independently;
  metadata-only edits can reuse a running configuration. New children receive
  only a matching, freshly resolved sealed bundle, and their endpoint never
  crosses renderer IPC. Final release, lock, malformed output or child failure
  retires the route; all dependants receive closure. An unconfirmed process stop
  remains fail-closed. Native integration tests cover sharing and cancellation
  with a synthetic sidecar. SSH now pairs its credential bundle with an exact lease
  and loopback endpoint before starting the native SSH handshake. Other protocol
  controllers still require integration.

- Native `connection-route` returns authenticated route metadata or explicit `null`
  for a direct connection. Errors never authorize a direct retry. The main-owned
  SSH controller prepares the VPN before starting the SSH recipient deadline.
  `ssh-route-bundle` re-resolves the route under the vault owner lock, checks the
  lease context and exact revisions before borrowing credentials, and binds the
  loopback endpoint into a separate HPKE purpose. The SSH child receives only
  ciphertext through stdin and uses the authenticated SOCKS endpoint. Route loss,
  owner revocation and session closure retire SSH and release its exact lease;
  late callbacks cannot close a replacement session's route. Integration tests
  reach a real local SSH server exclusively through a synthetic VPN sidecar and
  verify that sidecar failure closes SSH without falling back to a direct dial.

- The credential page and the connection editor's SSH-key shortcut use native
  `credential-edit` and revision-checked `credential-delete`. Replacement passwords
  and passphrases stay in temporary DOM inputs and mutable IPC/stdin buffers.
  Main resolves one-use, sender/authorization-epoch-bound file selections; Go reads
  bounded regular key/certificate files, validates key/passphrase/certificate
  compatibility and atomically saves the aggregate. Metadata-only edits preserve
  existing secret manifests and provenance. Standard requires one-action fresh
  authentication for both writes. Failed replacements require secret re-entry or
  file reselection; refresh failures after commit are reported as committed saves.
  Deletion binds the revision observed when its confirmation opened. Generic
  credential reveal and external Bitwarden secret resolution remain unavailable.

- The app's existing folder dialogs use a typed native `folder-save` operation.
  The editor sends only the public folder fields and the revision captured when
  it opened. Go generates new IDs, appends new folders using authenticated paged
  sibling positions, validates references/cycles, and performs a revision-checked
  write. Updates preserve hidden settings, ordering, creation provenance and
  encrypted fields. No notes or passwords cross this bridge. Duplicate form
  submission is suppressed; a refresh failure after a successful native save
  closes the editor and reports the committed save in the tree. Standard requires
  the main-owned fresh-authentication dialog before each mutation.

- The saved-connection editor uses a separate typed `connection-save` operation
  for all supported protocol metadata. Password and note replacement values live
  only in temporary DOM inputs and mutable IPC/stdin buffers, with clearing on
  submission, cancellation and lock; they never enter the native editor's React
  state or public metadata DTO. Native general fields remain mounted across tab
  and protocol changes. An empty note input preserves stored notes; an explicit
  clear action removes them. “View stored notes” opens a main-owned sandboxed
  dialog. Go authenticates the exact node revision and seals notes to its one-use
  non-exportable X25519 recipient. Main relays ciphertext only; plaintext is
  rendered as literal text in the dedicated DOM, never in the main React tree.
  Absent notes display an authenticated empty value. Lock, parent navigation or
  crash, dialog reload and a five-minute limit destroy the display. Copy is
  disabled pending the vault-owned clipboard flow. Capture exclusion is required
  on Windows/macOS; Linux displays its existing platform limitation. Notes use
  local View authority after unlock and do not expose credential Reveal.
  Go shares the legacy protocol/RDP normalizer, authenticates the proposed parent
  chain and credential/gateway references, enforces Windows AzureAD external RDP,
  then atomically commits metadata, secret changes and seals against the opening
  revision. Hidden settings, ordering, creation provenance and untouched secret
  fields are retained. The host verifies the active owner before and after work,
  and a stale dialog response cannot close a newer editor. Standard mutations
  use the same one-action authentication flow as folders and deletion. Connections with a keep-legacy
  resolver choice are refused until the user explicitly accepts new resolution;
  already accepted new choices retain their encrypted migration provenance.
  The saved-connection editor now loads a versioned migration report and lets the
  user keep previous credentials or use current inheritance per protocol action.
  The report contains IDs, change flags and choices; native identity snapshots
  never cross IPC. Decisions bind the exact node revision and original comparison
  fingerprint, reject partial failures atomically, and preserve unselected paths.
  The native profile permits choices at Default/Standard, with fresh authentication
  required for Standard and mutation admission rechecked in Go. The panel shares the editor mutation guard and updates
  its revision after a successful choice even if the subsequent tree refresh fails.
  Active read/write failures refresh the workspace tree without changing the open
  form or its revision, so reopening can recover from an outdated selection.
  This is the per-connection choice editor; the workspace-wide migration report,
  migration publication/retirement and credential reveal remain outstanding.

- Native SSH handoff: `ssh-bundle` resolves the current authenticated account,
  route and field versions under one owner lock and seals a bounded binary payload
  to a child X25519 key. `--operation ssh-sealed` announces that ephemeral key on
  its first stdout line, consumes it once, and calls the database-free native SSH
  dialer. Account name and the mandatory host-key pin are inside the ciphertext;
  workspace/session/request/node/host/port/epoch are bound by HPKE. The child has
  no vault database access, legacy startup, credential reload or MCP. Optional
  trusted settings/user-data paths enable the scoped SFTP editor journals.
  EOF, malformed commands, lock, output failure and remote
  disconnect retire it; authentication has a 30-second deadline. Regression tests
  connect the vault producer to a real local SSH server, including wrong-host
  rejection before password authentication. Electron's connection broker now
  selects this entrypoint for an unlocked native vault, before legacy Bitwarden
  resolution or VPN acquisition. Main binds the announced key to one child and
  checks workspace/node/session/request/lock epoch on the returned bundle. The
  request owner's document and authority are rechecked after asynchronous work;
  no recipient key or ciphertext reaches preload. The host never starts a new
  vault owner to satisfy a sealed request. Session IDs remain reserved until
  confirmed child close; application lock and shutdown await sealed SSH cleanup.
  Startup now reaches this path for existing native vaults. The new path
  accepts pinned SSH terminal sessions directly or through supported native VPN
  leases. First-use and changed-host-key verification now use the native flow
  described below. Local SFTP, reconnect and temporary credential entry now use
  [the owned SSH/SFTP flow](vault-ssh-flow.md). External providers and
  profile-specific session retention remain to be integrated.
  The decrypted mutable frame is wiped after dialing. Go's SSH/HPKE libraries
  still create temporary heap objects; this is not a claim of hardened memory
  handling for all protocol credentials.

- SSH Connect obtains a native `ssh-host-plan` before borrowing credentials.
  Its revision commits to the authenticated node chain, selected credential and
  tunnel revisions. A separate `ssh-host-probe` process performs key exchange and
  aborts in the host-key callback, before any user authentication. It has no
  database, agent or credential input and uses the main-owned SOCKS endpoint when
  routed. Missing or changed keys open a native confirmation with Cancel as the
  default. Standard additionally requires fresh authentication for this exact
  `ssh-host-trust` action. Go re-resolves and compares the complete displayed plan
  under the owner lock, then writes a revision-checked leaf pin without changing
  an inherited parent. A stale plan or replay is rejected. Probe responses are
  bounded and tied to the current child/request; confirmed process exit precedes
  credential release. The subsequent credential bundle must still match the
  verified destination, and the actual SSH handshake checks the saved pin again.
  Closing the attempt, lock, route loss or owner loss prevents late connection and
  aborts its confirmation. Native tests verify direct and SOCKS probes never reach
  server authentication; Electron-to-Go integration exercises first-use trust and
  the later real SSH login. In Default and Standard shared workspaces, the
  controller checks Use and Write and verifies the signed host pin and its
  credential binding before acknowledging the confirmation. Standard also
  requires fresh authentication to save the host key. See
  [shared tunnel and SSH behavior](shared-tunnels.md).

- The packaged backend and the development build cache use the exact Go patch
  selected by the backend `go.mod` (currently `go1.26.10`). The encrypted SQLite
  VFS checks the sizes and offsets of the native file, VFS and I/O method fields
  it uses against the pinned modernc SQLite and libc layouts at compile time.
- AES-256-GCM envelopes bound to workspace, table, owner, field, key and version.
- Serialized Argon2id presets, cancellation before/after derivation, immediate
  post-derivation memory reclamation, and purpose-separated HKDF derivations.
- Password and recovery wrapping primitives, optional ASK mixing, grouped
  recovery codes with checksums, and key-check generation/verification.
- Authenticated local slot files, bounded strict parsing, monotonic updates,
  atomic durable replacement and a pre-unlock descriptor without key material.
- Ciphertext-only secret storage interface and SQLite key graph with foreign keys,
  a pinned exclusive connection, atomic key/value version changes and optimistic
  concurrency. This new database schema is not a migration of the app database.
- Local key owner: slot-file authentication before opening SQLite, native-memory
  root key, independent DEKs per secret field, fresh DEKs on writes, authenticated
  records and bounded plaintext callback lifetimes. An encrypted-file flag fails
  closed until the authenticated VFS is implemented.
- Credential aggregate storage: authenticated metadata and a field manifest,
  atomic metadata/DEK/value changes, versioned field removal, bounded listing,
  per-owner name uniqueness and logical deletion. Protected app editors and
  native SSH/SFTP resolution use this owner API; legacy migration publication
  remains required.
- Tunnel aggregate storage and native list/read/save/delete: authenticated
  metadata, one encrypted provider configuration, revision checks and atomic
  replacement/deletion. Native provider validation is reused; responses contain
  no configuration, endpoint, pin, cache or secret in ordinary renderer results.
  Supported native VPN leases use protected configuration handoffs; vendor SSO,
  runtime caches and legacy migration publication remain unfinished.
- Node aggregate storage and native list/read/save/delete: nullable inheritance,
  authenticated metadata and references, independently encrypted notes/inline
  passwords, cycle/depth checks, atomic field changes and deletion guards for
  referenced credentials/tunnels. Folder editors and tree deletion are connected
  to the app; connection editors use the typed operation above and atomic moves use
  a revision-bound operation. Connection duplication now also uses a protected native operation. A separate native subtree operation deletes descendants and their
  encrypted fields in one transaction; the leaf API still rejects children.
- A common Go connection resolver and language-independent conformance fixtures:
  complete-chain validation, identity/port/credential context, gateway/tunnel
  selection and override isolation. The local owner authenticates the chain and
  selected aggregates before borrowing a connection secret, checks stored node
  floors and re-resolves under its mutation lock. See [the provisional resolver
  contract](resolver-v1.md). The legacy paths now persist metadata-only runtime
  observations for SSH/SFTP, VNC, RDP, gateway and Reveal. Successful observations
  run the candidate resolver against a single current metadata read transaction;
  differences are logged with IDs and change flags only. Migration pinning,
  PostgreSQL and shared permissions still need integration. Dynamic provider identities are unavailable to this
  metadata-only shadow path, never guessed or fetched as a side effect.
  Shared active legacy selectors now capture SSH/SFTP, VNC, RDP/gateway and Reveal
  and compare with the candidate in one read transaction, including never-opened
  connections. The baseline reads no secrets and rejects incomplete paths or
  unavailable candidates. A native migration plan defaults changed paths to the
  legacy choice and binds all old/new identities with a canonical fingerprint.
  Immediately before native import work, a source writer reservation prevents
  concurrent SQLite edits while a fresh complete baseline is checked. This is
  identity drift detection, not authentication or a full-content hash. The owner
  stores per-node choices in a reserved encrypted field anchored to the node's
  authenticated manifest, with revision-checked choice updates and credential
  reference guards. The owner applies the choices separately for all six paths,
  preserves inherited source nodes and keeps explicit overrides and RDP gateway
  choices isolated. Secret rotation retains the pinned identity and borrows the
  current authenticated value. Report/choice UI, app integration and full migration
  orchestration remain.
- A bounded native legacy credential reader transfers password/passphrase/key/
  certificate bytes to a borrowing sink, preserves empty versus absent fields,
  validates metadata and rejects pending recovery journals or ambiguous IDs.
  Buffers are cleared on success, error and cancellation. Real Windows DPAPI and
  Electron safeStorage fixtures transfer into the authenticated owner without
  changing source rows or protected key files. The caller must reserve the source
  database and private-key lock and use an unpublished migration stage. This
  reader is composed by the native staging coordinator below; remaining secret
  categories and app cutover are still required. Native create-only import
  APIs preserve credential creation times and node/tunnel creation/update times.
  Credential provenance is authenticated and immutable across ordinary edits;
  pre-v5 records retain unknown times and their existing authentication tags.
- The native node reader transfers all current legacy node settings, encrypted
  destination notes and inline passwords. It validates the complete parent graph
  before secret reads, visits parents first, preserves nullable inheritance,
  normalizes UUID references and timestamp instants, and wipes borrowed buffers.
  Missing active passwords stop import. Unused inline/provider values are copied
  into the separate encrypted orphan archive below, without reactivating them.
  Indexed metadata reads avoid a full
  source-table scan per node. Real Windows DPAPI and reserved-source fixtures
  exercise the transfer into the owner. Publication and source-secret
  retirement still belong to the unfinished full migration controller.
- The native tunnel reader transfers protected files and early Electron SQLite
  payloads with their source flags and original times. All nine provider types
  share the native configuration validator; validation leaves imported bytes
  unchanged. VPN payloads use their 4 MiB bound while passwords retain 16 KiB.
  Corrupt files never enable fallback, and simultaneous file/row sources must
  match before import. Borrowed plaintext, replaced validation-map values and
  Windows DPAPI output/key buffers are cleared after use. The local-state reader
  below archives provider caches and tokens; source retirement remains separate.
- A native coordinator now reserves the canonical source, tunnel files and private
  keys, rechecks the complete resolver plan, then imports credentials, tunnels,
  parent-first nodes and encrypted resolver choices into an unpublished vault.
  It authenticates readback and preserves source timestamps, including when pins
  are sealed. A slot-file journal binds the source path and complete choices;
  both `copying` and `domains-copied` reject ordinary unlock. After interruption,
  only an authenticated matching stage can be rebuilt, including torn SQLite
  sidecars. Before advancing the journal, the coordinator now closes/reopens the
  destination, authenticates its policy, catalog, every manifested secret and
  local-state chunk, and compares domain counts with the imported inventory.
  After closing and flushing it, a keyed digest binds the exact database bytes to
  workspace/file/root identity and the source/choice commitment. The slot-file MAC
  covers this snapshot. Verification rejects changed length/content or any SQLite
  journal/WAL/SHM sidecar, and authenticates the slots before reading database bytes.
  Older copied markers without a snapshot remain rebuildable but cannot verify
  as publication checkpoints. The audit currently uses the existing 8 MiB native
  catalog bound; exceeding it fails without retiring source data.
  Source rows and protected files remain unchanged. These phases do not
  certify a complete workspace migration: remaining source inventory and Chromium
  SSO inventory, source quiescence/retirement, atomic publication and app
  integration remain required.
- Staging also records a native-only `migration-source-inventory` inside sealed,
  workspace-scoped local state. It inventories all `CredentialSecrets` rows and
  the protected files used by the credential, tunnel and provider-cache importers,
  including orphan files and the Bitwarden backup. File classes/scopes select
  allowlisted native paths; public slot metadata and renderer responses never
  contain paths, OS references or these commitments. Keyed, length-framed digests
  bind each protected file and each row's encoding, exact external-store reference,
  nullable timestamp and decrypted value. A value changed under an unchanged
  keychain reference is therefore detected. Captures before and after the copy
  must match; only then is the bounded 32 MiB inventory encrypted and read back.
  Closed-database integrity checking includes this extra aggregate before the
  snapshot is sealed. Link/non-regular file inputs, invalid references, source
  additions/removals, read failures and cancellation leave the stage unpublished.
  This inventories the currently implemented native import sources; it neither
  retires them nor inventories Chromium SSO partitions/remaining OS stores. The
  version-two inventory additionally commits to all SQLite table rows, schema,
  user version and application ID with a domain-separated keyed digest. Reads use
  the reserved source transaction, including committed WAL contents. Type-tagged,
  length-prefixed values distinguish NULL, text, blobs, integers and floats;
  declared DATE/BOOLEAN conversions cannot hide changes. Verification after
  reopening the stage detects source changes outside the resolver, such as notes
  and credential names. Old inventories require restaging. Virtual/generated
  tables are refused; scanning is bounded to a 128 MiB source and encoded input,
  512 tables/views, 128 columns and 500,000 rows per query. A changed row order
  can conservatively require restaging. The
  final cutover must validate the inventory again under source quiescence and a
  durable retirement journal. In particular, a prior copied checkpoint alone is
  not authority to delete anything, and does not freeze external writers.
- Legacy CLI processes hold a shared native ownership lock for their full process
  lifetime, including the interval after cancellation of background workers.
  Native initialize/unlock and staging require an exclusive lock before opening
  data; contention fails with `workspace_owner_unavailable`. The lock covers the
  data directory because sibling databases share protected files. Parent-directory
  aliases converge on the same lock; database-file symlinks are rejected.
  Failed unlock and completed staging release ownership, while an unlocked vault
  retains it until close. Metadata requests coexist with legacy processes.
  This coordinates updated Go processes only: older binaries, Chromium writers,
  complete source inventory, retirement and the application cutover remain to be
  handled before migration can be exposed to users. A completed copy is still an
  unpublished stage and does not freeze the source after the coordinator returns.
- SQLite v6 adds sealed `LocalState` aggregates for device-local tokens and caches.
  Payloads up to 64 MiB use at most sixteen 4 MiB independently encrypted fields.
  Length, order, presence, versions, kind and scope are authenticated together;
  updates/deletions are atomic, and every chunk verifies before any callback.
  The staging coordinator now archives the MCP token, Bitwarden CLI session,
  primary/recovery browser storage, current/legacy Azure/WatchGuard/Stormshield
  caches (including files with no current tunnel), and pending Azure import keys.
  Original bytes and distinct recovery copies are preserved. These are native
  archive records: runtime consumers still need vault routing and format/expiry
  checks. Ordinary generic secret APIs cannot bypass their sealed manifests.
  Source identity/locks use the physical path, while protected-file keyring names
  and path-hashed Azure import directories retain the selected logical path.
  Both paths are bound into the migration commitment when an alias is used.
- The coordinator additionally archives orphan `CredentialSecrets` rows, unused
  inline/provider values, and protected SSH key/tunnel files with no active
  consumer. Rows retain their original ID spelling, encoding, protected reference,
  nullable update time and decrypted value inside a versioned encrypted archive;
  files retain the selected logical path and exact decrypted bytes. The four
  `legacy-*` local-state kinds are not runtime credentials or configurations.
  Active identities are loaded once; metadata is paged and orphan payloads use
  indexed exact-ID reads. Case-ambiguous IDs, unknown source identities, malformed
  metadata, corrupt files and failed decryptions stop the unpublished stage.
  Every archive is read back through the owner before the journal can advance;
  failure leaves it non-openable and retry rebuilds from the reserved source.
  Source rows/files/keyring entries remain intact. Temporary/recovery files and
  Chromium SSO inventory, authenticated retirement and final publication remain
  separate requirements. Linux legacy secret-tool errors now clear partial output
  before returning; dedicated Linux runtime regressions are in the OS CI matrix.
- HPKE bundles bound to a protocol session, request, lock epoch and destination.
- Ed25519 profile signatures, local HMAC and shared Ed25519 resolution seals,
  high-water checks, and strictest-profile selection at admission.
- Authenticated local profile persistence in `WorkspaceMeta.SignedProfile`, bound
  to the workspace, file and root-key epoch. Native open refuses a missing,
  altered or stale document; only authenticated pristine initialization creates
  the initial Default policy. Updates compare the previously authenticated bytes,
  advance the change sequence atomically and reject incompatible personal KDF/ASK
  floors. Initialization and the protected personal Standard action checkpoint
  the authenticated profile sequence in the slot file.
- Native machine-policy floors are read from HKLM, the managed macOS plist or
  `/etc/wormhole/policy.json`. A malformed or unreadable configured policy fails
  closed. Native open and domain requests check the authenticated effective
  profile, API version and password/recovery/KDF/ASK requirements. Unsupported
  Hardened/Paranoid protection is refused; Standard mutations require a freshly
  verified password or recovery factor bound to the exact action. A metadata-only `security` response and strict Electron
  client/host parser expose the effective profile and its source to main.
  Settings reads that projection from the active lock monitor.
- Native key buffers, explicit zeroing before release, optional/required locked
  memory, Linux dump exclusion and Unix process core-dump controls.
- Bounded JSON-line stdio transport, serialized handler calls, increasing IDs,
  cancellation, heartbeat expiry, EOF/lock shutdown and safe error codes.
- `--operation vault`: transport integration and per-path vault-instance lock.
  It handles `initialize`, `unlock`, native enrollment, `status`, `describe`, `heartbeat`, `cancel`
  and `lock`, plus native credential, tunnel and node list/read/save/delete and
  atomic single/multiple node-subtree deletion after unlock.
  Password/recovery unlock opens the SQLite owner and lock closes it
  and terminates the process. Status still reports `protectionAvailable: false`
  and `sharedWorkspaceAvailable: false` because app integration is incomplete.
  Unknown operations fail. It bypasses legacy migrations and log initialization.
- Authenticated initialization marker and UUID-bound staging database, durable
  no-replace publication and restart recovery after slot publication, torn staging
  or DB publication. Initialized missing databases are never recreated. Legacy
  CLI operations and direct legacy DB opens refuse any workspace with a slot file,
  even if that file is damaged.
- Dedicated Windows/Linux/macOS CI for the new packages and process smoke tests,
  with an 80% coverage gate for each package.
- Main-owned Electron vault client with bounded metadata and typed unlock requests, heartbeat,
  strict response projection and process-exit confirmation before replacement.
  Preload exposes status, public slot descriptors, the authenticated catalog and
  typed password/recovery unlock to the registered main document. Generic command
  forwarding remains unavailable; creation uses a separate main-owned dialog and preload. App lock,
  reload and shutdown stop an existing owner. Native Go interoperability and
  the client coverage gate are included in the platform matrix.
- A reusable DOM unlock screen supports password slots and formatted recovery
  codes, clears the input and caller byte buffer on submission, prevents duplicate
  requests and clears controls on disposal/pagehide. Recovery decoding/checksum
  verification stays in Go; the renderer never decodes the raw recovery key. Failed
  workspace loading after successful unlock retries loading without repeating
  authentication. The screen is tested in real sandboxed Electron with the startup
  styles and measured V8 coverage, and is mounted by bootstrap when public slot metadata exists.
- Native `workspace` reads the authenticated catalog and resolved display values
  under one owner lock. The Go projection builds the ordered tree, credential
  lists, tunnel labels and inherited RDP/serial settings; RDP identities honor
  retained migration choices. Incomplete targets remain visible, while failed
  authentication, storage or migration checks abort the entire snapshot. Both
  inherited display expansion and the final response are bounded. The typed
  Electron/preload read validates the tree, references and exact display schema,
  preserving native Unicode text without applying editor normalization. No
  passwords, private keys, notes, tunnel configurations or native key records
  cross this boundary. Provider-synchronized virtual credentials and certificate
  detail metadata still need their native consumers. Startup and workspace refresh use this read path for native vaults. Other domain actions
  still require migration to native commands; unsupported legacy calls are rejected.
- Native `startup` and the zero-argument `startup:load` IPC return public slot hints and
  the theme preference. They do not open SQLite, inspect the legacy auth store,
  migrate settings/data or return security policy. Missing or unusable cosmetic
  settings fall back to the system theme; corrupt slot files fail the request.
  A null slot descriptor grants no workspace access. File reads are bounded,
  buffers cleared and settings links/non-regular files ignored. After unlock, the
  preload supplies a settings request to `startup:load`. For native vaults, the
  handler authorizes the operation against the current lock epoch and reads allowlisted preferences through
  the authenticated `preferences` RPC, and loads the native workspace. Preferences
  never supply authentication or lock policy. Existing legacy workspaces retain
  their original startup behavior. Failed metadata reads never fall back to legacy.
- Main-process workspace selection survives lock and process retirement. Once
  selected, a missing or different slot identity fails closed for the app lifetime.
  A process opened only for metadata is not a selected vault. Selection invalidates
  application authorization; only a trusted, still-current unlock restores it.
  Native vaults suppress legacy background maintenance and legacy app-lock controls.
  The renderer unmounts the workspace on `vault:locked` and ignores late loads.
  Folder/connection saves, subtree deletion and resolver choices use the native
  fresh-auth flow at Standard. Other sensitive-action UI integrations remain
  unfinished. Preferences are read-only through this path.

The new SQLite store retains its exclusive lock until close. The vault process
uses it after authentication. The application unlock screen invokes that path for an existing native vault. Legacy
backend operations still open legacy workspaces independently; they refuse new
vault workspaces. Do not route legacy domain operations into the vault,
enable protected slots, claim that locking destroys all app secrets, or declare
the format frozen before completing the remaining F0 work.

The opt-in Adiantum VFS in `tools/wormhole-backend/internal/encvfs` encrypts the
database, rollback journal, WAL and SQLite temporary files in 4096-byte blocks.
SQLite opens each registered file with one main connection and an opaque URI
handle for a locked page key. The native VFS retains locking and sync.
SQLite can request preallocation in chunks rounded up to 4096 bytes. The
wrapper rounds the size hint to a whole chunk and writes encrypted zero pages
at their final offsets. Empty files stay empty until the first write. Hints
that would add more than 4 MiB in one call defer allocation to normal writes.
Tests on Windows cover both journal modes, recovery after
forcibly ending the writer, torn file tails, forced file-backed temporary
spills, sparse temporary-file I/O and reading a two-page reference database.
The fault suite traces physical ciphertext writes, compares a complete trace
with actual file bytes, and reopens separate images with dropped, reordered or
torn unsynced writes. It covers consecutive commits in both journal modes and
a WAL checkpoint. The model treats successful file deletions as durable.
The native CI matrix runs the storage fault tests, interrupted conversion and
rekey, and encrypted backup tests on Windows, Linux and macOS on x64 and arm64.
The conversion and rekey tests kill the writer after pending slots are synced,
after the new database is staged, after the old database is renamed, and after
the new database is published. Each restart checks the committed record, its
on-disk encryption and retirement of the temporary database copies.
`VACUUM INTO` can produce an encrypted
copy from a plaintext source or from a source encrypted with a different key.
[Reference database](https://github.com/ncruces/go-sqlite3/blob/v0.32.0/vfs/adiantum/testdata/test.db)

Native local unlock verifies the slot file and root key-check before opening
SQLite. An authenticated whole-file marker selects Adiantum, requires a current
recovery slot, and derives the page key for a single open database. The owner
checks the database identity before returning it to the app. Initializing
documents already marked for whole-file encryption use an encrypted stage and
the existing atomic publication path. Default creation still uses field
encryption.

Native root rotation now preserves whole-file encryption. Native maintenance
can also convert a protected plaintext workspace using the same recovery
journal. Both paths write the stage under the new page key, audit its graph and
publish its database and the new slots through the existing recovery phases.
For a source with a different page size, `VACUUM INTO` writes 4096-byte pages
in the encrypted copy while preserving the source. Publication recovery opens
the final file with the authenticated new slots.

Before an encrypted copy starts, the controller syncs the recovery journal and
the current slot document with the wrapped pending root and its KCV. The new
factor authenticates that intent on restart. During the pre-copy phase the
controller can reopen the authenticated source solely to rebuild an incomplete
stage. It rechecks the pending target's recorded floors before discarding any
partial copy, then lets SQLite settle surviving journals before taking the
source fingerprint. Ordinary unlock stays blocked until the prepared transition
finishes.

In development builds, **Settings → Security → Encrypt the vault database**
starts this conversion for an unlocked, protected local vault using field
encryption. Electron selects the operation and binds it to the current owner.
The protected window confirms the current factor and the new recovery code
before restarting into the existing rotation-resume flow. Packaged
availability and Hardened still require the platform storage-fault matrix.

The native vault service can export an unlocked whole-file vault as a
`.whvault` archive. Standard requires fresh authentication. The archive starts
with `WHVLBK01`, the big-endian slot length (32 bits) and the database length
(64 bits). It then contains the exact authenticated `.slots` file and an encrypted
SQLite snapshot. A trailing HMAC-SHA-256 covers the header and both payloads using
a key derived for local backups. The snapshot consolidates committed SQLite
transactions in a single database file.

Restore uses the recovery code from the archived slots. The native service
authenticates the archive before opening its SQLite snapshot and verifies the
database identity, authenticated record graph and slot checkpoints before
publishing a new directory containing both files. Publication refuses existing
destinations.

For a whole-file local vault, **Settings → Security → Export encrypted vault
backup** opens the native save dialog. On a fresh install, **Restore an encrypted
vault backup** opens the archive picker and a protected recovery-key prompt.
The prompt is bound to the selected archive's slots and authentication tag.
The service publishes the restored pair in a reserved sibling directory and
Electron restarts into the vault unlock screen. Startup requires the restored
pair or a pending native rotation journal and refuses conflicts with an
existing workspace.

## Remaining delivery work

| Stage | Remaining work                                                                                                                                                                                                                                                                                                                                                                       |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| F0    | Metadata domain storage and app-wide single SQLite owner; move every secret-touching call; sealed protocol consumers and replay tracking; resolver snapshots/shadow comparisons; slot-file transactions; pre-unlock startup allowlist; Electron IPC/window/packaging hardening; update-manifest format; PostgreSQL integration jobs and merged platform coverage.                    |
| F1a   | End-to-end local unlock; unprotected platform slots; journaled migration of every legacy secret/token/cache; rotation and secure deletion; authenticated slot files and high-water persistence; fresh authentication; main-owned lock policy; recovery, protect, unlock and clipboard UI; signed updates.                                                                            |
| F1b   | Attested and deterministic Hello integration, signed Touch ID helper, packaged whole-file conversion availability, and cross-platform durability and interoperability release gates.                                                                                                                                                                                                 |
| F2a   | PostgreSQL 16+ deployment, pgx authentication/TLS tests, roles and hardened API functions, key custodians, audited two-step release and atomic password changes.                                                                                                                                                                                                                     |
| F2b   | Invites/re-key/reset, resolver-pinned in-memory migration, export/recovery/break-glass and incremental sync.                                                                                                                                                                                                                                                                         |
| F3    | Server-enforced permissions, boundary/group keys, credential slots, admin screens and rotation on removal.                                                                                                                                                                                                                                                                           |
| L1–L4 | Network enforcement/CA rotation, Write/Reveal rules, session/profile enforcement, audit anchors, device certificates, metadata confidentiality, capabilities, Kerberos and AD sync.                                                                                                                                                                                                  |

The OS/DB integration matrix remains a release requirement. Unit tests do not
validate Hello hardware, Touch ID signing, PostgreSQL servers, VFS durability or
cross-platform migration of real credentials.

## Provisional v1 contracts

These contracts are implemented but remain provisional until the F0 interoperability
and migration gates are complete. Newer format versions are rejected explicitly;
unknown versions, suites, policies and slot kinds do not fall back to legacy reads.

### Field encryption

Suite 1 is AES-256-GCM with a random 12-byte nonce and 16-byte authentication tag.
Plaintext is bounded to 4 MiB. JSON encodes byte slices as base64. The envelope has
`formatVersion`, `suiteId`, `keyId`, `keyVersion`, `nonce`, and `ciphertext`.

AAD starts with the literal UTF-8 domain `wormhole/v1/envelope`, followed by
length-prefixed fields in this order:

1. format version (big-endian uint16);
2. suite ID (big-endian uint16);
3. WorkspaceId/VaultId;
4. table;
5. owner ID;
6. field;
7. key ID;
8. key version (big-endian uint32).

Every prefix is a big-endian uint32 byte length. String fields are UTF-8 and limited
to 1024 bytes. The binding passed to `Open` must come from the trusted resolver,
not from the stored envelope. The local owner generates a fresh DEK for every
write, retaining the logical DEK ID and increasing its version. Application-wide
rotation policy remains to be implemented; the primitive alone does not provide
nonce accounting or replay
protection.

### Local secret owner and persistence

`vaultstore.Store` exposes ciphertext records and atomic compare-and-swap writes,
without passing SQL connections to domain callers. SQLite schema version 6 stores
`WorkspaceMeta`, `Keys`, `KeyCopies`, `SecretValues`, `CredentialProfiles`,
`TunnelConfigs`, `Nodes` and `LocalState`. Every secret field has its
own stable DEK ID; each write creates a random 256-bit key at the next version,
retires the old key version and advances the value revision and workspace change
sequence in one transaction. Revision exhaustion fails without partial writes.
Retired key copies remain available for the future rotation/deletion workflow;
retirement alone does not erase historical key material.

The SQLite connection is pinned for the owner's lifetime, with foreign keys,
exclusive locking, full synchronization and in-memory temporary storage. Reads
bound blobs before returning them to Go. After slot-file authentication and
identity verification, version 1 adds credentials in one transaction, then
version 2 adds tunnels, version 3 adds nodes, version 4 adds credential
creation provenance, and version 5 adds local-state aggregates and extends the
SecretValues owner-kind constraint in separate versioned transactions. Each step preserves
existing ciphertext and ChangeSeq; failed DDL or version promotion rolls back
that step. A current-schema file never receives missing-table repairs; an
identity mismatch, unknown newer version or failed upgrade is refused. This is
an upgrade of the provisional vault schema, not a migration of legacy app data.

`localvault.Open` consumes the supplied root-key buffer and authenticates the
slot file/key check before SQLite opens. The root lives in `securemem`; each DEK
and borrowed plaintext is wiped after synchronous use, including callback errors
and panics. Callbacks must not retain secrets or reenter the owner. The owning
process must exit on lock; closing this object alone is not the app lock boundary.

Local field AAD uses table `SecretValues/<OwnerKind>`, the requested owner ID and
field `<FileId>:<RowVersion>:<Field>`. DEK-wrap AAD uses table `KeyCopies`, owner
DEK ID and field `<FileId>:<DekVersion>`, bound to the root ID/version. A record MAC
uses the local-seal HKDF purpose with the workspace ID as salt. Its input is
`wormhole/v1/local-secret-record` plus NUL, followed by compact Go JSON of
`{identity,value}` in declaration order with `value.copy.signature` set to null.
It authenticates the complete ciphertext, references and revision. The root-key
identity comes from trusted bootstrap state; it is not chosen from the DB row.

An authenticated minimum revision must come from the resolver/checkpoint. Passing
zero checks integrity but cannot detect restoration of a previously valid row.
The native unlock UI and four Standard mutation flows now use dedicated
authentication. Full persisted high-water enforcement, remaining resolver
authorization paths and the app-wide storage cutover remain outstanding. This API
does not expose a renderer-accessible operation for reading secrets.

### Credential aggregates

`vaultstore.CredentialStore` provides bounded ID-ordered pages, reads and one
aggregate compare-and-swap write. `localvault.Owner` signs and verifies metadata,
prepares fresh field keys, and lends plaintext only through its synchronous
callback. Metadata contains no password, passphrase, private-key or certificate
value. Key/certificate names are display labels; encrypted field values replace
the old private-key file references. The types retain the app's `password` and
`sshKey` credential kinds, protocol identifiers and local/Bitwarden providers.

The HMAC uses the local-seal purpose with WorkspaceId as salt and the domain
`wormhole/v1/local-credential` plus NUL. It covers compact Go JSON of
`{identity,credential}` in declaration order with `credential.seal` set to null,
including the file/root identity, owner, provider, metadata, row version,
deletion flag and complete field manifest. Field entries are sorted by name;
each carries its revision and presence flag. A release checks the requested
credential/field identities and requires the exact field revision from this
authenticated manifest, not merely a field newer than a supplied minimum.

One transaction installs the metadata and every changed DEK, key copy and value,
then advances ChangeSeq once. Stale aggregate/field revisions, duplicate names
within an owner, undeclared fields, missing values and ignored SQLite writes
roll back the whole transaction. Standalone field writes cannot bypass an
existing credential aggregate. Switching to Bitwarden requires clearing all
present local fields in that same transaction.

Removing a field writes a fresh encrypted empty value and retains its next
revision with `present: false`; re-adding it continues the revision sequence.
Deleting a credential removes all present fields this way and preserves a signed
metadata tombstone. The deleted ID cannot be reused. These operations remove
live secret access, not historical ciphertext/key copies or filesystem remnants;
rotation, secure deletion and VACUUM remain delivery work. The reserved
EncryptedMetadata, MetadataKeyId and NameBlindIndex columns must remain NULL
until the profile-aware metadata codec is implemented. Listing does not claim
rollback protection against a server or disk image that withholds whole rows.

The persistent native service exposes these operations after unlock:

- `credential-list`: `{after, limit}`, with a canonical UUID cursor (or empty
  for the first page) and 1–16 results in ID order. A full page can be followed
  using its last ID; an empty page terminates traversal.
- `credential-read`: `{id, rowVersion}`. The revision is a minimum, with `"0"`
  meaning no caller checkpoint. It does not replace persisted high-water marks.
- `credential-save`: `{metadata, changes, rowVersion}`. The revision is the
  expected current version; `"0"` inserts. Local owner identity is implicit,
  not selected by input. Each change has `field` and `remove`; a replacement
  also requires a base64 `value`, including an explicit empty string. Removal
  forbids `value`. Only the four known secret fields are accepted, at most once.
- `credential-delete`: `{id, rowVersion}`, with a nonzero expected revision.

Revisions are canonical decimal strings through signed-64-bit maximum. Reads
return metadata, a revision and four presence booleans; no field manifest, seal,
DEK, ciphertext or secret value is returned. Saves return the same projection;
deletes return ID, next revision and `deleted: true`. Lists are capped at 16 so
even maximum-size escaped metadata fits the transport response bound.

Request objects reject unknown, duplicate, case-altered and null fields at every
level. Decoded secret buffers and raw intermediates are wiped on success and
failure. Conflicts/missing records leave the session usable and are redacted by
the existing fixed-error transport. Authentication/rollback failures and invalid
aggregate formats retire the owner and terminate the service. This includes
inconsistent edits such as removing an already absent field: callers must refresh
their metadata before submitting edits. Cancellation can suppress a reply after
a committed write; the expected revision prevents a retry from applying twice.

The low-level `credential-save` operation remains native-only. The app credential
editor uses the stricter `credential-edit` input described above, and deletion is
connected through the revision-bound bridge. A generic plaintext read/reveal
operation is deliberately absent. The connection resolver and sealed
protocol consumers must authorize any secret release separately.

### Tunnel aggregates

`vaultstore.TunnelStore` exposes metadata reads, ID-ordered pages and atomic writes.
The provider configuration is one `SecretValues` record with OwnerKind `tunnel`
and Field `settings`. A metadata-only rename advances RowVersion without rotating
the configuration; replacement advances both revisions with a fresh DEK. A
provider-kind change requires replacement configuration. Deletion writes an
encrypted empty tombstone, keeps both revision histories and prevents reuse of
the ID. Primitive field writes cannot bypass a registered tunnel aggregate.

The local HMAC uses the same local-seal HKDF purpose and WorkspaceId salt as
credentials, with domain `wormhole/v1/local-tunnel` plus NUL and compact Go JSON
`{identity,tunnel}`. The seal field is null in signing bytes. It binds ID, name,
kind, immutable creation timestamp, update timestamp, both revisions and deletion.
Configuration release verifies the metadata and the exact field revision before
calling a synchronous native consumer. Timestamps are canonical UTC RFC3339Nano;
revision ordering, not wall-clock ordering, controls concurrency and rollback.

Native operations are `tunnel-list` (`{after,limit}`, 1–128), `tunnel-read` and
`tunnel-delete` (`{id,rowVersion}`), and `tunnel-save`
(`{metadata:{id,name,kind},rowVersion,configuration?}`). Revisions follow the same
decimal-string rules as credentials. An omitted configuration preserves the
current value and is forbidden on insert; a replacement is a base64 JSON object.
Null, empty, invalid UTF-8, duplicate top-level keys and more than 128 settings
are rejected before the existing provider validators run. Provider field names
and compatible extension fields retain existing semantics. At most 4 MiB of
decoded configuration is accepted. Errors and integrity retirement use the same
fixed transport policy as credentials.

Responses expose ID, name, kind, timestamps and row revision only. They never
contain provider configuration, endpoint, pin, key material or cache values.
The metadata protocol is native-only; Electron's allowlist is unchanged.
Provider runtime/lease routing, references from SSH jumps, native
editing, authentication caches and legacy protected-file migration remain to be
connected before activating this store for application tunnels. Historical key
copies still require the separately planned rotation and secure-deletion flow.

### Node aggregates

`NodeStore` retains explicit columns for the existing node, RDP and serial
metadata. Pointer fields preserve SQL NULL versus false, zero and empty strings.
The metadata also reserves owner/credential-slot identifiers and encrypted
metadata columns. Active slot mode and shared ownership are not exposed by the
native local API until their authenticated catalogs and permissions exist.
Serial stop bits include 1.5 (value 3), and flow control includes DSR/DTR (value 3),
matching the current native adapter. Protocol value 2 is the retired SFTP encoding;
legacy migration must normalize it before import.

Notes and inline passwords are independently encrypted `SecretValues` fields
with OwnerKind `node`. Notes keep the existing 16,384 UTF-16-unit limit, valid
UTF-8 and no NUL. `Nodes.Notes` stays NULL. The signed field manifest requires
inline-password presence to match the metadata flag, and tombstones retain field
versions. A rename preserves fields; clearing the inline flag requires removing
the value in the same transaction. Primitive field writes cannot bypass a node.

Node HMAC bytes use `wormhole/v1/local-node` plus NUL, local-seal HKDF and compact
Go JSON `{identity,node}`, with the seal field set to null. They cover all nullable
metadata, timestamps, revisions, field manifest, deletion state, suite and signer
identity/version. Suite 1 is local HMAC-SHA256 with the workspace root as signer;
capability IDs are reserved and must be NULL in this local implementation.

Before signing a write, the owner authenticates every proposed parent and direct
credential/tunnel reference. The SQLite transaction repeats structural checks:
parents must be live folders; cycles and depth above 128 are refused, including a
move that would push existing descendants over the cap. A changed leaf's direct
credential is checked against its effective protocol, including SFTP/SSH parity;
gateway credentials must be RDP. Inline/serial routing restrictions also use the
effective protocol. Referenced credentials cannot be deleted or change protocol;
referenced tunnels cannot be deleted. These checks do not replace the forthcoming
resolver's complete connection-chain authorization, inherited credential choices,
shadow comparison, persisted high-water marks or profile policies.

Native requests are `node-list` (`{after,limit}`, 1–16), `node-read` and
`node-delete` (`{id,rowVersion}`), and `node-save`
(`{metadata,changes,rowVersion}`). Metadata uses the explicit camel-case field
names from `NodeMetadata`; ID, name, kind and sortOrder are required. Only declared
nullable fields accept null. Revisions and signed-64-bit sortOrder are canonical
decimal strings, so JavaScript cannot round them. Secret changes use the same
base64/explicit-removal contract as credentials, restricted to `notes` and
`inlinePassword`. Responses contain metadata, timestamps, string revisions/order
and presence booleans only. They omit notes, passwords, manifests and seals.

`node-delete` is a leaf/empty-folder operation and rejects live children.
`node-delete-tree` accepts the same `{id,rowVersion}` contract and atomically
removes the root and all currently live descendants. It returns only the root ID,
new root revision and a decimal-string `deletedCount`. It authenticates each
node and every replaced secret, writes signed tombstones and fresh empty encrypted
fields, and advances ChangeSeq once for the entire tree. Existing tombstones keep
their field versions. A stale root, invalid descendant, failed/ignored write or
cancellation before commit rolls back the entire operation.

The SQLite owner traverses indexed child links in postorder with a stack bounded
by the existing depth limit, without loading the whole tree or imposing a new
node-count cap. Its synchronous crypto callback sees only the current node and
a transaction reader restricted to that node's encrypted fields; it cannot retain
the reader or reenter the store. Concurrent inserts/moves serialize with deletion.
This is logical deletion; historical key copies still require the separately
planned key rotation and secure-deletion flow. Future shared callers must
authorize the complete tree in the same permission snapshot before deleting it.
`node-delete-trees` accepts `{nodes:[{id,rowVersion},...]}` with 1–4096 distinct
canonical IDs and positive decimal revisions below the signed 64-bit maximum.
The entire request is bounded to 512 KiB. All selected revisions are checked in the
same transaction before any mutation. Overlapping ancestor/descendant selections
remove their union once, in either input order. A late authentication failure in
another selected tree rolls back earlier trees and their encrypted field changes.
The result contains only `deleted: true` and a positive decimal `deletedCount`.

The native workspace projection now exposes each node's public `rowVersion`.
The app's existing single/multi-selection delete confirmation retains these
observed revisions, rather than replacing them from a background refresh. The
dedicated typed preload call is checked against a current trusted main document
and unlocked owner, and never starts a replacement process to perform a mutation.
The client snapshots the bounded selection before queuing and allows 30 seconds
for the transaction. Lock or timeout may suppress a response after a commit;
subsequent unlock reloads persisted state. The legacy and non-persisted tree paths
keep their existing behavior.

This action is available at Default and at Standard through the one-action native
authentication flow. Folder/connection editing uses that same flow. Import
and remaining protocol launch paths still need integration.

`node-move` accepts `{nodes:[{id,rowVersion}],target:{id,rowVersion},placement}`.
The placement is `inside`, `before` or `after`; sources are 1–1000 distinct roots,
with the same strict revision contract as deletion and a distinct target. Ancestor
and descendant selections together, stale sources or target, cycles, non-folder
parents and resulting depth above 128 are rejected. The operation authenticates
all live metadata inside one SQLite transaction (bounded to the app projection's
50,000-node limit), preserves visible selection order and updates only changed
source placements and destination sibling order. Every changed row receives a new
revision and seal; IDs and encrypted field envelopes remain unchanged. Already
observed process-local revision floors are enforced before signing; observed and
changed floors are published only after success. Ordinary node writes use the
same floor to prevent an edit from bypassing a previous move checkpoint. Resulting
descendant references are checked against the new inherited protocol. Any failure
rolls back all rows and the single ChangeSeq advance. A no-op returns
`{moved:true,updatedCount:"0"}` without advancing the sequence.

The existing drag-and-drop captures source and target revisions from the visible
tree. Its dedicated preload/host path binds the submitting document and unlocked
owner; Standard requires fresh authentication for this exact action. The renderer
never receives secret fields. Concurrent stale moves fail instead of overwriting
one another; a refresh failure after commit retains the visible move and asks the
user to refresh. Legacy and temporary trees keep their existing path.

`node-duplicate` accepts only `{id,rowVersion}` for a live connection (folders are
not duplicable). It requires the source revision observed by the caller, and the
same trusted document/current owner and one-action Standard authentication used
by other native mutations. Under the owner lock it authenticates the source,
its field manifest and the paginated catalog used for sibling order, including
observed revision floors. At the 50,000-node app limit or signed integer sort-order
exhaustion, it refuses creation before publishing any new node or key.

The copy gets a fresh UUID, revision 1 and ` (copy)` name suffix (bounded to 256
Unicode code points), remains in the source folder and is appended after its live
siblings. Its leaf SSH host pin is cleared. Inline passwords and notes are
preserved inside Go and independently encrypted with new DEKs for the new owner
ID; existing ciphertext is never relabelled. Removed fields are not revived.
Profiles remain shared references. Unlike legacy duplication's OS-store workaround
that disables inline passwords, the vault can safely copy them without sending
plaintext through Electron. Every temporary plaintext byte slice is wiped on
success or error, and the complete new node/key/field graph is committed atomically.

Retained migration decisions remain encrypted. Their legacy and candidate node
IDs, and inline credential IDs, are rebound to the copy; keep/new choices and the
original full-source provenance fingerprint remain unchanged. That fingerprint
is not recomputed from the incomplete per-node subset. The native owner verifies
canonical source records and retained saved-profile references before writing.

The acknowledgement contains only the new ID, name and initial rowVersion. The
app refreshes the workspace after success. If refresh fails, its fallback uses
revision 1 and appends to the original folder/root only while the starting tree
snapshot remains current, so a late response cannot overwrite newer tree changes.

### Derivation and slots

Slot file version 5 authenticates an optional Windows Hello slot. Enrollment
requires a fresh software factor and keeps a current password or recovery
slot. Go asks the same KeyCredential to sign a challenge bound to the vault,
file, slot and root version twice. Both signatures must agree and verify as
RSA PKCS#1 v1.5 with SHA‑256 before Go can wrap the root. Proof bytes are wiped
in Go and the Windows adapter. The startup projection carries the slot type
and ID. The native Windows adapter uses the owner window on build 26100 and
later. It queries Windows Terminal Services for the current session protocol
before opening a Hello prompt. Only a confirmed console session is eligible.

On Windows, the startup screen offers Hello for an enrolled local vault. Main
supplies the native HWND and cancels authentication if its window closes,
navigates, or loses its renderer. Password and recovery remain available when
Hello is canceled or unavailable. Settings enrollment and removal both require
a fresh software factor in a protected window. Removal withdraws the slot even
when Windows cannot confirm deletion of the matching credential.

Slot file version 7 records a verified TPM attestation for the same public key
used during deterministic Windows Hello enrollment. Go verifies a TPM 2.0
certify statement, including the non-migratable signing attributes and the TPM
name of that public key. The AIK signature must use RSA with SHA-256. The AIK
certificate must carry the TPM attestation usage and chain to a preconfigured
machine trust anchor. The legacy evidence-present state remains eligible for
software-capable profiles.

The `HelloTPMAttestationRoots` REG_BINARY value under
`HKLM\SOFTWARE\Policies\Wormhole` accepts up to eight concatenated DER CA
certificates and at most 64 KiB. It is for AIK trust anchors selected by the
machine administrator. Verification is offline and only the machine policy
supplies trust anchors. The renderer receives slot identifiers and kind. Go
records the attestation result and the public key fingerprint in the slot file.
The Windows capability probe, certificate container decoding, and synthetic
attestation and unlock tests pass on Windows x64. A console operator on Windows
x64 build 26300 completed deterministic enrollment, reopened the temporary slot
and confirmed credential removal. The device returned `evidence-present`.
The TPM verification and software-key configurations, and the other OS and
architecture combinations, still require physical runs.

To run the physical check, build the backend test executable on the device with
`go test -c -o hello-device.exe .` from `tools/wormhole-backend`. From the
repository root, run
`pwsh -NoProfile -STA -File scripts/test-windows-hello-device.ps1 -TestBinary tools/wormhole-backend/hello-device.exe`.
Click **Start** at the console and respond to the Windows prompts. The test
uses a new temporary credential and a random in-memory root. Record the Windows
build, native OS and binary architectures, attestation disposition and test
result. Only `tpm-verified` confirms the key under the configured trust anchors.

Slot file version 6 adds an optional Touch ID slot. The Go backend derives a
wrapping key from a device-only Keychain factor, bound to the vault, file, slot
and root version. The nested universal macOS helper authenticates the packaged
backend and its Electron parent. Go verifies the helper's Developer ID signature
before launch and verifies the running process before sending the bounded
request. Enrollment requires a current software factor. The helper reads back
the new Keychain item only after Touch ID on the current biometric enrollment.
The factor travels in a private pipe and is wiped by Go after derivation.

The macOS release workflow accepts the helper's Developer ID provisioning
profile through `WORMHOLE_TOUCH_ID_PROFILE_BASE64` and uses the standard macOS
signing and notarization credentials. The ordinary packaging flow can still
produce a build where the helper is unavailable. On macOS, Electron offers
Touch ID at startup for an enrolled vault and in the protected vault settings.
The same window-lifetime and fresh-factor checks apply to both biometric
providers. Native compilation is wired into macOS CI. A signed, notarized run
with real hardware remains pending.

Root rotation keeps the authenticated v5, v6 or v7 source barrier and publishes new
password and recovery slots. Before clearing the rotation journal, Go attempts
to delete retired biometric credentials from the local system store. A missing
device or an unavailable store still allows recovery. Biometric unlock requires
enrollment again after the restart.

The Argon2id parameters are fixed preset IDs, not caller-supplied numeric costs:
`kdf-low` = 64 MiB/t3/p4, `kdf-v1` = 256 MiB/t3/p4, `kdf-v2` = 512 MiB/t3/p4,
and `kdf-v3` = 1 GiB/t4/p4. Local password slots use random 32-byte salts.
The policy owner must authorize the preset before calling a derivation; in
particular, low memory is permitted only by an authenticated Default policy.
The native Electron test measures the vault process before its first password
attempt and again after a rejected and a successful `kdf-v1` unlock. Each
measurement must be within 32 MiB of the initial working set on Windows or
resident set on Linux and macOS. On macOS the vault uses a private anonymous
mapping for the Argon2id working blocks. It erases and unmaps the allocation
before replying, including after a rejected password. The same serialized
derivation gate and `debug.FreeOSMemory()` run on all three systems.

Shared salt is SHA-256 of `wormhole/v1/salt`, the 36-byte lower-case canonical
workspace UUID and immutable NFC/lower-case LoginName, concatenated in that order.
Optional ASK material is 32 bytes; presence is explicit, never inferred at unlock.
HKDF separates account-master, login, unlock, local-seal, key-check, SQLite and
Hello purposes. The SQLite label is `wormhole/sqlite/adiantum/v1` as specified by
the issue's VFS section.

Slot headers include ID, kind, KDF preset, salt, ASK requirement, factor IDs and
wrapped key. The authenticated slot binding includes the ID, kind and preset.
Password unlock rejects unsupported envelope versions/suites and malformed
wrapped-key sizes before entering Argon2, including when a request is cancelled.
AND, platform-presence and unprotected kinds are reserved but not implemented by
the password/recovery APIs. No PIN or implicit platform fallback exists here.
Local slot files authenticate the outer document and use atomic persistence.
The vault process uses them for password/recovery unlock. Application/native UI,
migration and rotation callers are not yet connected.

### Authenticated local policy

The local owner reads a canonical, at most 16 KiB `LocalPolicy` document from
`WorkspaceMeta.SignedProfile` after authenticating the slot file. The document
contains the workspace policy, personal profile floor, file ID and root-key
ID/version. HMAC-SHA256 uses the local-seal subkey and the distinct
`wormhole/v1/local-profile` domain. Every member is authenticated; duplicate,
unknown, missing or case-aliased fields and noncanonical encodings are rejected.
The effective workspace/personal choice must satisfy the KDF and ASK requirements.
No setting in `settings.json` participates in this decision.

Only a new or authenticated pending, pristine initialization may seed a Default
policy. Its initial sequence is at least one and at least the authenticated slot
checkpoint. Existing non-pending vaults with absent or invalid policy fail open
attempts without repair. Interrupted initialization reuses the authenticated
seed, then records its sequence in the finalized slot file. Policy-only updates
advance `ChangeSeq`, so the old pending marker no longer passes the pristine check.

Native policy edits authenticate the previous document, require its sequence,
increase that sequence exactly once, and compare its exact bytes in the SQLite
transaction. A bounded readback after all updates checks that triggers did not
substitute the stored policy. A failed write rolls back both policy and counter.
The owner retains the greatest authenticated sequence it has observed and rejects
replay below it or below the slot checkpoint supplied at open.

In an eligible Default vault, Settings offers a personal Standard minimum. The
protected prompt verifies a fresh factor. Go compares the policy and slot file
revisions and checkpoints the update before acknowledging it. Electron then
locks the vault. Restoring both the database and its checkpoint from an older
backup remains a rollback risk.

In a shared workspace, the same choice applies to the enrolled device. The
native service checks the signed workspace policy and authenticates the device
password and any required ASK. It records Standard in version 7 of the encrypted
device trust state and updates the OS-protected startup checkpoint. Earlier
record versions contribute a Default personal minimum. Standard requires verified
TLS and checks that the connected PostgreSQL role has `log_statement=none`. The workspace policy
keeps its existing scope and sequence when a user changes the device minimum.

### Machine-policy floor and native security projection

The optional machine floor has one profile name: `default`, `standard`, `hardened`
or `paranoid`. The native reader never uses environment overrides, user settings
or subprocess output. Its machine sources are:

- Windows: the `Profile` REG_SZ value in the 64-bit view of
  `HKLM\SOFTWARE\Policies\Wormhole`. Reads use a fixed 64-byte buffer and do not
  expand variables. Missing key/value means no additional floor; all other
  access/type/length/value errors fail closed.
- Linux: `/etc/wormhole/policy.json`, containing exactly
  `{"profile":"standard"}` (with the chosen profile).
- macOS: `/Library/Managed Preferences/com.xbounceit.wormhole.plist`, an XML or
  binary plist dictionary with exactly one string entry named `Profile`.

Unix sources and every parent must be root-owned and not group/world writable.
The reader opens components relative to verified directory descriptors, refuses
symlinks, non-regular files and writable ACL access by the current non-root user,
and caps files at 4 KiB. Missing policy under a verified directory means no added
floor. A present but invalid file never means Default. XML shape/version and the
binary object graph are bounded before the pinned plist decoder sees the data;
duplicate entries, extra members and nested values are refused.

After authenticating local policy, the owner checks its API range and the strictest
OS/workspace/personal profile. Every password slot must meet the authenticated KDF
and ASK minima. Standard additionally requires a password and recovery slot.
Hardened admission still depends on the F1b storage release conditions.
Paranoid also requires an attested password-and-hardware slot. Domain RPCs recheck the machine
floor and local authentication on each request; a policy failure retires the
owner. Cancellation remains an ordinary canceled read. Standard writes require
the bundled fresh-action request; direct write RPCs continue to return a policy
error even after a previous successful confirmation.

The `security` RPC reports the decimal profile sequence, the three profile
sources and the effective profile. It also reports a retained session minimum
and eligibility to choose Standard when applicable. Electron validates this
projection before activating its policy monitor at unlock. Settings can request
the protected confirmation dialog for the current workspace. Native Linux and
macOS runtime tests are part of the CI matrix.

### Signed release manifest

`Wormhole-UpdateManifest-v1.json` contains a canonical JSON manifest and its
base64 Ed25519 signature. The signature covers `wormhole/update-manifest/v1`,
a zero byte and the canonical `manifest` object. The object binds the Wormhole
repository, release tag and five platform installers, with exact names, byte
lengths and SHA-256 digests. The pinned updater checks this manifest before it
offers a download, verifies the download and rechecks the cached file in Go
before Electron hands it to the platform. Releases that lack a valid manifest
remain visible as release metadata in pinned builds.

Linux managed updates use `Wormhole-UpdateManifest-v2.json`. It adds the
architecture-specific DEB and RPM under a distinct signing domain. The
administrator stages one format per architecture and approves the digest of
that manifest. The client verifies both the cached download and the root-owned
staged package before revealing the latter for deployment.

Official builds use the Actions variable `WORMHOLE_UPDATE_MANIFEST_PUBLIC_KEY`
for the public pin and the Actions secret `WORMHOLE_UPDATE_MANIFEST_SEED` for
the matching Ed25519 seed. Each value is 32 bytes encoded as lowercase hex.
The workflow pins the same public key into all build targets, signs the final
installers in a job with read-only repository access, then publishes the draft.
Published releases are left intact on retry. Development builds can omit the
pin and continue using SHA-256 sidecars from releases.

The release worker can check and download while the local or shared vault owns
the workspace. The authenticated owner records the last successful check in the
device's preferences. Electron starts an automatic check after unlock when
enabled and binds each result to that unlock. Locking or tightening the profile
retires pending work. Before opening an installer, Electron checks the update
owner and policy again after Go verifies the cached package.

Default allows in-app installation from a pinned manifest. A Windows build with
`WORMHOLE_WINDOWS_PUBLISHER_SPKI` also requires Authenticode for every install,
including Standard. The value is the lowercase hex SHA-256 digest of the signing
certificate's DER SubjectPublicKeyInfo. Windows verifies the primary signature
with the SHA-2 strong-signing policy and chain revocation checks, then Wormhole
compares the verified code-signing certificate's public key against the pin.
The release workflow signs each Windows installer in a separate Windows job
when the publisher pin is configured. The job uses the code-signing certificate
in Azure Key Vault and requests an RFC 3161 timestamp. It runs the updater's
native publisher check before generating the checksum. The release manifest
uses the resulting installers. See [release signing configuration](vault-managed-updates.md#windows-release-signing).

For macOS, `WORMHOLE_MACOS_PUBLISHER_TEAM_ID` pins the Apple Developer ID
Application team. The updater verifies the signed DMG with the system
`codesign` tool, then requires a notarized Gatekeeper verdict for the disk
image's primary signature. It refuses assessment overrides and rechecks that
the native tools assessed the file opened for the manifest hash. Standard can
offer installation on macOS once the team and manifest keys are configured.
The release job signs the DMG, submits it to Apple's notary service, staples and
validates its ticket, then runs the updater's verifier before producing checksums.
The job uses a Keychain profile provided by `WORMHOLE_MACOS_NOTARY_PROFILE`
and optional `WORMHOLE_MACOS_NOTARY_KEYCHAIN`, or creates a per-run profile in
the runner's Keychain from the existing Apple release credentials. In the
configured publisher flow, the app-specific password goes to the Keychain
tool's interactive prompt and subsequent notarization uses the profile.

Standard shows release notifications on builds without a supported publisher
configuration. Hardened uses public notifications or a machine-approved local
source. Paranoid accepts only the managed source. Release key rotation still
needs integration. Production signing keys must be provisioned before the
corresponding release runs. The macOS CI job verifies a digest-pinned notarized
disk image with the expected Apple Team ID and checks rejection with a different
Team ID. It also compiles the Touch ID helper's signing requirement with
`csreq`.

### Local slot-file persistence

`<database>.slots` holds format version, VaultId, FileId, root key ID/version,
an initialization marker, sequence, the whole-file
encryption flag, password/recovery slots, key-check value, profile sequence,
file epoch and sorted per-node high-water marks. UUIDs are canonical lower-case;
the document is capped at 2 MiB, 16 slots and 10,000 node marks. Platform,
unprotected and AND slots remain reserved. The limits and format are provisional.

An HMAC-SHA256 under the local-seal subkey (salt = VaultId) authenticates the
entire explicit Go JSON document with `authentication: null`, prefixed by the
`wormhole/v1/slot-file` domain and a length. Duplicate, unknown or case-aliased
fields, invalid UTF-8 and unsupported versions fail closed. The candidate key
must pass the key-check and document MAC before opening SQLite. Database identity
is checked again after open by the storage owner, including the authenticated
root-key reference. These additions remain part of the provisional v1 format;
the earlier foundation format without root identity is not accepted.

Writes acquire a slot-file lock, authenticate the previous document and require
its expected sequence. Updates increment that sequence and cannot reduce or
remove recorded high-water marks. They reuse the private-file writer's fsync,
atomic replacement and directory durability controls. A durability error after
replacement reports `vault_slot_commit_uncertain`: callers must read back and
authenticate state before retrying. Corrupt files are never automatically reset.
A rollback of the entire database and slot file together remains a documented
limitation without an independent high-water anchor.

The foundation service's `describe` operation returns only format version,
VaultId, the encryption flag and slot ID/kind/preset; a missing file returns null.
This descriptor is **untrusted before unlock** and must never choose policy or
claim protection. Reading and writing it do not open or create the database.
Fresh-auth authorization, optional unprotected enrollment, pending-key rotation and
legacy migration publication remain separate delivery work.

Recovery keys contain 32 random bytes plus the first four SHA-256 bytes of
`wormhole/v1/recovery || key`, base32 without padding, grouped by five with the
`WHREC1-` prefix. Recovery presentation must use a display-once protected flow;
these helpers do not save, copy or print it. Password change rewraps a key;
protection activation/removal/exposure still require the full rotation workflow.

### Initialization and native unlock transport

The native enrollment controller now provides `enrollment-begin`,
`enrollment-confirm` and `enrollment-cancel` for a **new, empty local workspace**.
The application uses these through its dedicated first-launch dialog; this is not
a legacy migration entrypoint. Begin accepts only base64 password bytes and a
32-byte X25519 recipient key belonging to the dedicated, content-protected recovery dialog. A generic renderer bridge
must not choose this recipient. Go generates the root/recovery keys and UUIDs,
wraps both password and recovery slots, then erases the password. The pending root
and 76-byte formatted code stay in required locked native memory. No database or
slot file is written before confirmation. An exclusive workspace-directory lease
prevents cooperating legacy startup from creating a DB during this flow.

The response contains only enrollment/workspace IDs, two distinct one-based group
numbers, and a `SealedBundle` containing the recovery code. Its HPKE suite is
X25519/HKDF-SHA256/AES-256-GCM; info is `wormhole/v1/recovery-display` followed by
workspace ID and enrollment ID, each prefixed with its uint32 big-endian byte
length. This domain cannot be substituted for a protocol credential bundle. The
recipient consumes its private key once and clears the displayed code before
confirmation or on disposal. Managed Save/Print and the cloud-folder warning remain
pending; the current dialog asks the user to write down the code. Main has no plaintext recovery
code response. The short final group is not selected for the two five-character
confirmation groups.

Confirm takes the enrollment ID and exactly ten base64-decoded bytes, consisting
of the two requested groups in their displayed order. Comparison is constant-time.
Three wrong attempts retire the pending keys. A five-minute native timer, explicit
cancel, EOF or service lock also wipes pending material and releases its lease;
expiry does not depend on renderer activity. Cancel is idempotent before an owner
exists. Confirmation transfers the lease to the new SQLite owner and uses the
existing durable initialization marker/publication flow below. An existing or
late-created database/slot file is never replaced. Failed publication retires the
process; authenticated restart can resume a marker only after the recovery
confirmation has happened. Begin/confirm use the authentication-cancellation
retirement policy; ordinary `enrollment-cancel` does not install keys. Default and
Standard machine floors are accepted, while unsupported stronger requirements
fail before enrollment starts.

The creation window has its own sandboxed preload and ephemeral Chromium session;
the ordinary renderer can only request that main open it. Navigation, popups,
downloads, permissions and unmanaged print/save shortcuts are blocked. Main
requires content protection on Windows/macOS and retires the owner on dialog/parent closure,
renderer failure, reload, OS lock or cancellation. A cancellation racing a durable
commit refreshes startup metadata, so the existing vault is reopened through unlock.
Electron does not implement capture exclusion on Linux. Linux uses the same
sandboxed, ephemeral recovery window and explicitly displays that limitation;
password/recovery protection remains available. This is a platform limitation of
the current Default/Standard secret dialog, not a claim of capture prevention.
macOS capture exclusion also does not block ScreenCaptureKit clients; see
[Electron's content-protection contract](https://www.electronjs.org/docs/latest/api/browser-window#winsetcontentprotectionenable-macos-windows).
After a successful commit, application authorization is activated only after the
native security policy; a failed workspace load can be retried without recreating it.

The dedicated DOM flow uses a non-exportable WebCrypto X25519 key pair and the
pinned `@hpke/core` 1.9.0 recipient implementation. The pair is passed together so
HPKE never needs to export the private key to reconstruct the public key. Password
and confirmation bytes are wiped after IPC forwarding; the recovery code never
crosses preload or enters React state. Temporary browser strings and crypto-library
allocations cannot be guaranteed erased before garbage collection. Production
bundling warns about the library's Node crypto fallback; the real packaged-page
Electron test exercises its browser WebCrypto path successfully.

`initialize` accepts native-flow factors over stdin, as base64 byte fields
`password` and `recoveryKey` (32 bytes). The native flow must generate and confirm
the recovery key before submitting; no key is returned over the response channel.
The vault generates its own root key and UUIDs, creates kdf-v1 password and
recovery slots, then persists `initializing: true` at sequence 1 before touching
SQLite. It refuses any existing database or slot file. This initializes an empty
workspace only; it does not migrate existing data.

The temporary DB is `<database>.creating-<authenticated FileId>`. After SQLite
close/fsync, Windows uses write-through MoveFileEx without replacement; Unix uses
an atomic same-directory hard link followed by unlink. Publication cannot replace
an existing target. After checking the published DB's identity, the slot marker
is finalized at sequence 2. Restart after a crash requires another successful
unlock. Only authenticated pending initialization permits rebuilding its staging
file; an initialized missing DB stays missing. A pending marker is rejected if
the key graph/change sequence shows any user writes. This guards replay of an old
initialization marker, not rollback of an entire matching workspace snapshot.

`unlock` accepts `vaultId`, `slotId` and either `password` plus optional `ask`, or
`recoveryKey`. Input is capped at 8 KiB, has exact unique field names and never
appears in error messages. The service checks the slot, KCV and whole document
before SQLite opens; it requires locked native root-key memory. Until authenticated
profile exceptions are connected, kdf-low password slots are refused. Success
returns only `unlocked` and `lockedMemory`. Cancelling initialize/unlock causes
service exit and key retirement, even when its result was queued. It does not
leave an unlocked owner behind a cancelled prompt.

After a factor successfully unwraps the root, a subsequent integrity/storage
failure retires the session and forces process exit without publishing a handler
result. A failed authentication attempt may be retried only when no root was
successfully unwrapped. Temporary DB initialization uses the ciphertext-only
store directly after authentication; it does not open and close extra key owners.

These operations are not generic renderer IPC APIs. Main registers enrollment
channels only for the current dedicated recovery window and its exact main-frame
URL. App-wide domain integration remains unfinished. The empty-workspace `initializing` marker is distinct from
the optional authenticated `migration` journal. Its source/choice commitment is
HMAC-SHA256 under the local seal subkey with the
`wormhole/v1/local-migration-source-and-choices` domain. It is not a full-content
digest or proof that the source has not changed since a copy. Every retry takes a
fresh source reservation and rebuilds; neither current phase permits publication.
Only the private native importer sets `AllowImport`; ordinary slot updates cannot
remove the journal or change its binding. A nil journal preserves the byte layout
of pre-migration slot MACs, verified against an independent old-format fixture.

A copied journal may additionally contain `snapshot: {bytes, authentication}`.
Its HMAC-SHA256 uses the same local-seal subkey with the distinct byte prefix
`wormhole/v1/local-migration-database\0`, followed by the fixed-width canonical
WorkspaceId, FileId and RootKeyId (36 bytes each), the lowercase source binding
(64 bytes), the root version (uint32 big endian), the file length (uint64 big
endian), then exactly that many database bytes. The outer slot MAC authenticates
the snapshot fields. A copying journal cannot contain a snapshot. This checkpoint
authenticates the destination only; it does not certify that source files have
been retired or remained unchanged after the source reservation was released.

### Profiles and seals

Profile and resolution-record signing bytes use explicit Go JSON structs (fixed
field order, no maps or floats), prefixed with a length and domain separator.
Null versus explicit false/empty retains inheritance semantics. Interoperating
implementations must match Go's JSON escaping, including HTML and U+2028/U+2029.
The signature covers signer identity/version, optional capability ID and revision.
Verification requires an independently trusted key and authenticated high-water
mark; these packages do not certify keys, authorize writers or persist revisions.

### Protocol bundles and transport

Suite 2 is DHKEM-X25519/HKDF-SHA256/AES-256-GCM (RFC 9180 base mode). Its HPKE info
is `wormhole/v1/protocol-bundle` followed by the same length-prefix encoding of
workspace, session, request, node, protocol, host, port (uint16), tunnel ID,
external-client flag (byte), and epoch (uint64). Empty AEAD AAD is used because
the full destination is bound in HPKE info. The `enc` value is 32 bytes.
Protocol processes must pin the child public key and consume each request once;
the primitive does not detect replay within the same session by itself.

Protected local serial connections use a fresh Go process for each tab. Saved
connections inherit their line settings from the authenticated node chain.
Quick connections pass a device selection through the unlocked local owner
for the same one-use handoff. The serial bundle binds the device name, the
opening request and the active unlock epoch. The worker consumes one sealed
configuration and then accepts only terminal controls for that session.
Electron sends terminal events to the opening renderer and waits for the
worker to exit on lock or close. Shared serial tabs use the same terminal
surface and open saved nodes through PostgreSQL's Use-checked connection
plan. Main rechecks Use on catalog notifications and every 30 seconds
while a shared serial tab is live. Permission checks cover open nodes outside
the current catalog page. A missing permission or unavailable verification
closes the associated native session.

The native SSH child consumes only one recipient key and one opening packet.
Its terminal plaintext is byte `1` (payload version), one boolean byte for Auto
Sudo. Explicit file-only opens use version `2` and flag byte `2`; other version/flag
combinations are refused and file-only mode cannot enable Auto Sudo. Both versions
are followed by six fields, each prefixed with a big-endian uint32 byte length:
UTF-8 username, canonical SHA256 host-key fingerprint, password, private key,
passphrase and user certificate. The complete plaintext is at most 4 MiB, with
no trailing bytes. Secret fields borrow the decrypted buffer and are wiped after
native dialing. Empty password and key together are refused. The unencrypted
opening packet contains `binding`, `bundle`, `columns` and `rows`. Explicit
file-only opens also carry `sftpOnly: true`; Go verifies it against the encrypted
version before dialing, so stripping or injecting the field cannot start a shell.
`ssh-bundle` and `ssh-route-bundle` accept the same main-only selection and echo it
in their public envelope; the relay validates the exact requested mode. Protocol
still identifies the stored connection's authenticated account path, not whether
a terminal or file subsystem is opened. Duplicate or
unknown properties at all three object levels are refused. The native vault's
`ssh-bundle` request uses a decimal-string epoch; its numeric HPKE binding is
limited to the positive JavaScript safe-integer range. Electron's main broker
owns recipient-key selection, snapshots the request, strictly parses Go's canonical
JSON and validates all binding fields before forwarding. It admits at most 32
children and bounds both input buffering and queued writes to 8 MiB. A presentation
callback that throws or synchronously locks the app cannot acknowledge a stale
connection. The native client retains its existing 16-request queue limit.

A tunnel configuration handoff uses the same suite/envelope and the separate
`wormhole/v1/tunnel-bundle` domain. Its info is that domain followed by
length-prefixed fields: the complete protocol-bundle info defined above, file ID,
provider kind (big-endian uint16), tunnel row revision (big-endian uint64), and
configuration revision (big-endian uint64). Protocol identifies the destination
(`ssh`, `sftp`, `rdp`, `vnc`, `http` or `https`); a nonempty tunnel UUID is mandatory
and external-client mode is not admitted. All context UUIDs are canonical and
nonzero. Revisions are positive signed-64-bit values, with configuration revision
no greater than row revision; both are decimal strings in JSON. The configuration
is nonempty opaque plaintext of at most 4 MiB, consumed only by the native route
recipient. `tunnel-bundle` takes `nodeId`, `credentialOverride` (empty or a canonical
UUID), `sessionId`, `requestId`, decimal-string `epoch` and a base64 X25519 public
key. Electron bounds the sealed response to 8 MiB and validates every expected
session field. No preload endpoint exposes it. Native child key consumption, lease
ownership and pairing with the destination protocol's bundle remain the controller's
responsibility; they are not supplied by this primitive.

A routed SSH credential handoff uses `wormhole/v1/routed-protocol-bundle`,
followed by length-prefixed complete tunnel-bundle info and the loopback endpoint.
The endpoint must be exactly `127.0.0.1:<port>` with a canonical decimal port in
1..65535. The encrypted payload is the same bounded SSH binary payload used for
direct connections. The full tunnel context and endpoint are authenticated and
cannot be substituted or opened under the direct/tunnel purposes. The native
`ssh-route-bundle` request adds `route` and `endpoint` to the direct SSH request;
main obtains both from its own lease, with no renderer selection. Native
`connection-route` takes the plan context without a recipient and returns either
the full route binding or explicit JSON `null`. Its errors remain errors.

Transport frames have `version: 1`, an increasing positive safe-integer `id`,
`operation`, and optional `payload` or `targetId`. Frames are limited to 8 MiB;
there is one active handler call and a bounded response queue. The output bound
includes JSON escaping and envelope overhead. Each input frame must end in LF or
CRLF; an unterminated final frame and invalid UTF-8 are rejected. Duplicate or
unknown fields and noncanonical top-level field names are rejected. Heartbeat
defaults to 30 seconds. `cancel` normally cancels the target request context and
reports whether the target was still active. Authentication handlers opt into
process exit on cancel to retire keys installed before completion. An
accepted cancellation discards a completion already waiting in the event queue;
it cannot roll back domain work already committed. EOF, `lock`, timeout, protocol
error and output failure cancel work, close the pipes and join workers before
closing the handler. Shutdown has a one-second deadline. A noncooperative worker
or cleanup failure returns a fixed error; the executable must exit when serving
ends, and must never restart the service in the same process.

Electron's metadata client accepts at most 16 queued domain reads, one heartbeat,
and 64 KiB per status/descriptor/heartbeat response (at most 4,096 fragments).
The read-only catalog has an 8 MiB frame limit; it does not increase the limit of
concurrent heartbeat responses. It accepts only exact status, descriptor, catalog
and heartbeat schemas, canonical metadata JSON (including Go HTML escaping), and fixed error codes;
stderr is discarded. Metadata requests time out after five seconds; password and
recovery unlock allow up to 120 seconds for the native KDF. Stop first invalidates
the client, writes `lock` and closes stdin, then requests forced termination after
1.5 seconds. Another 1.5 seconds without an observed exit reports an unconfirmed
shutdown; neither a sent signal nor `child.killed` authorizes a replacement.
The same client never restarts. Host replacement requires confirmed exit, and is
blocked during the complete app shutdown operation. Metadata alone does not grant
application authorization or establish that legacy secrets have been retired.

The native catalog holds the owner's mutex across all pages of nodes,
credentials and tunnels, authenticates every returned aggregate, checks node
migration version floors and validates parent/credential/tunnel references. A
failure returns no partial catalog. The total native metadata is bounded before
projection, and no secret field is decrypted. The transport emits an explicit
allowlist of stored display fields; nullable inheritance stays nullable and
64-bit versions/sort positions use decimal strings. Electron additionally checks
record order, identifiers, Unicode, field bounds and parent depth. This read-only bridge is used by the application after native unlock; legacy
workspaces retain their existing loader. It does not claim cryptographic inventory completeness or
cross-restart rollback protection; authenticated high-water enforcement remains
part of the later security work.

The typed unlock bridge accepts only a vault ID, slot ID, password/recovery kind
and bounded `Uint8Array` factor. A formatted recovery code uses the separate
`recovery-code` input kind and the native `recoveryCode` field; its 76-byte format,
checksum and slot opening are validated in Go before SQLite is opened. The caller
must clear its renderer input after
invoking the bridge; context isolation creates a separate preload copy. The
preload clears that copy immediately after IPC forwarding. Main consumes its copy,
and the client encodes base64 directly into a mutable stdin frame without creating
a base64 string. Owned factors and frames are cleared after forwarding or on
rejection, startup failure, pipe error and lock. No factor is passed in arguments,
logs, files or response data. A window that navigates or closes during unlock
causes owner retirement before the request settles. The native unlock UI uses this transport. Legacy workspaces retain their existing
authentication screen until migration is complete.

Handlers must honor cancellation before mutations and return only approved
metadata/ciphertext. Input is borrowed until Handle returns; the returned slice
transfers ownership to the transport and may alias that input. It must not be
retained or mutated by the handler afterward. They must not return
plaintext secrets through the general response channel. Transport redacts errors
but cannot replace domain authorization or response allowlists.

### One-action fresh authentication

Standard folder/connection/credential saves, credential/subtree deletion and resolver decisions open
an isolated main-owned confirmation dialog. Its IPC surface accepts a factor for
the action already captured by main; it cannot choose an operation or return a
reusable grant. Password/recovery inputs stay out of React state. Each retry owns
separate mutable edit buffers, so a wrong factor cannot erase the pending edit.
The trusted originating document and unlocked workspace must remain current.

Go receives one bounded request containing authentication and the exact action.
It verifies the current authenticated slot file, sequence floor, policy and OS
minimum before opening the selected password/recovery slot and comparing its root
to the resident key. Factors are cleared before the mutation. Existing action
validation, revision checks and transactions still apply. Ordinary Standard writes
remain denied after success; three wrong factors retire the process. Lock,
timeout or loss of the dialog/parent while submitting retires the owner before the
original request settles. Cancellation cannot undo a mutation already committed.

The app mutation flows, including the protected tunnel editor, enforce the
bundled authentication boundary. Slot management, recovery regeneration, profile changes, clipboard,
export and the broader migration/shared-workspace workflows still need their own
integration. Hardened/Paranoid are not enabled by this change.

### Main-owned idle and session lock

After a typed native unlock, the host reads authenticated security metadata and
activates a main-process monitor before acknowledging success. Its one-second
timer uses OS-wide idle time with a fresh unlock grace period: Default/Standard
15 minutes, Hardened 5 minutes, Paranoid 2 minutes. A pending security read never
pauses idle sampling. Invalid samples, policy failures or sequence regressions
lock the owner; policy relaxation takes effect only after another unlock.
Hardened/Paranoid remain unavailable in the native security gate until their other
requirements are implemented. Shared workspace/admin-configurable limits remain
part of the PostgreSQL work.

Power notifications retire the vault on suspend/resume, screen lock, session
deactivation and shutdown. Minimization locks Hardened/Paranoid. Every process
retirement disables the timer, including a submitting window that loses trust.

### Direct connection policy

The Go protocol connection plans treat a missing VPN in the authenticated
route as Direct. Default and Standard can open that route. Hardened and
Paranoid require a configured VPN. Local planning rechecks the authenticated
profile for Direct routes, including temporary targets and HTTP(S). Shared plans and
credential handoffs enforce the admitted profile before projecting connection
metadata or opening account keys. Shared denials follow the existing fail-closed
admission retirement path. The legacy Go VPN prompt uses a configured VPN
automatically under a Hardened or Paranoid machine floor and rechecks the floor
before accepting an outstanding Direct response.

### Electron window protection

Application BrowserWindows use one main-process factory. It enables the sandbox
and context isolation and disables Node integration and DevTools. Dedicated
vault dialogs continue to request capture protection when supported.

When the authenticated effective profile is Hardened or Paranoid, main requires
Electron content protection on existing BrowserWindows before acknowledging
unlock and on new windows before showing them. A failed activation retires the
vault. A new window that fails the check is destroyed while hidden. Protection
stays in place during lock and teardown. A later authenticated weaker profile
can release it for ordinary windows while independently protected dialogs keep it.

Electron has no capture exclusion on Linux. Its macOS protection does not
exclude ScreenCaptureKit clients. The protected RDP relay sends the Windows
ActiveX host a distinct startup command when the authenticated profile requires
capture exclusion. Older hosts reject that command. The adapter sets and reads
back the Win32 affinity on its separate top-level window before configuring the
session or revealing the overlay. The setting is reapplied if Windows recreates
the handle. A live upgrade into this requirement on Windows locks the workspace
and retires existing sessions before admitting a new owner.
Automatic and manual locks share session cleanup, invalidate authorization before
waiting for queued mutations, and wait for confirmed vault exit before success.
Overlapping cleanup holds cannot be cleared by another lock or a late legacy
settings response. Existing native vaults now use the unlock UI and native workspace read path.
These hooks do not migrate existing legacy storage.

[Electron powerMonitor](https://www.electronjs.org/docs/latest/api/power-monitor)
provides screen-lock events on Windows/macOS and session-deactivation events on
macOS; the `locked` idle state is platform-dependent.

On Linux the Go backend subscribes to logind's lock and session-deactivation
signals and to D-Bus ScreenSaver activation. The backend checks the bus service's
current owner and matches logind events to the Electron process's session as
resolved by logind. If that session cannot be identified, the ScreenSaver
subscription can still deliver lock events. The main process treats the loss of
a subscribed monitor as a lock and attempts to reconnect.

When logind grants a delay inhibitor, the backend holds its descriptor through
`PrepareForSleep(true)` until Electron confirms that the vault service, protected
sessions and dialogs have stopped. Each acknowledgement identifies one suspend
cycle. Electron keeps authorization held from preparation until logind reports
resume or cancellation. Logind defines the maximum delay if cleanup stalls.
Electron's power events remain active when inhibition is unavailable or sleep
bypasses logind. Hibernation snapshots remain a documented OS limit.

On Windows a hidden Go window subscribes to WTS notifications for its own
Windows session. A local console disconnect, Remote Desktop disconnect,
logoff or session lock takes the existing vault lock path. Other sessions,
reconnects and Windows unlocks cannot change vault authorization. Main retries
registration if WTS is unavailable at startup. The helper unregisters on
parent-pipe EOF.

### Native memory limitations

`securemem.Buffer.With` borrows native memory only for a callback; callers must
not retain the slice or convert keys to strings. A buffer is permanently retired
on its first Close attempt, even if native release fails; subsequent Close calls
can retry cleanup, but With and Locked never make those pages usable again.
Required page locking fails
closed; optional locking requires a warning when `Locked()` is false. Temporary
crypto-library allocations can remain in the Go heap until reclaimed. Process
termination, not best-effort clearing alone, remains the ultimate lock boundary.

Plain local SQLite vaults at Default and Standard can finish unlock when the OS
denies page locking. Native receipts and status report the actual locked-memory
result. The unlocked workspace displays a persistent warning when its root may
be paged. Already encrypted SQLite still requires locked root and page keys,
and migration and rotation staging keep their required-memory checks. Shared
admission continues to project its native warning, and Electron retires an
owner that would report a stronger profile without locked memory.

### Crash capture

Electron delays local Crashpad startup until authenticated Default or Standard
admission, or until the native startup probe confirms that the legacy workspace
can run under the Default machine floor. Protected admission and refresh require
a fresh process if Crashpad has already attempted to start. Electron provides no
stop for its crash reporter and renderer processes created before startup do not
participate in its crash reporting.

The Go vault and its secret-bearing sidecars disable core dumps on Linux and
macOS. On Windows they use a verified per-process error mode to suppress ordinary
Windows Error Reporting. Before reading keys they inspect the native 64-bit
machine LocalDumps configuration and refuse to start if global values or a key
for their own executable are present, or if the policy cannot be read. This
check covers the Go vault processes in every profile because their keys always
require dump protection. Default and Standard retain the local Electron Crashpad
path. Other per-application LocalDumps keys do not block startup.

On Windows, the native vault checks the actual Electron parent image against
LocalDumps and requires its ordinary WER exclusion before returning a Hardened
or Paranoid policy to main, including authenticated policy refresh on local
and shared workspaces. The native RDP
launcher checks the actual child image before sending the protected startup
command or authorizing credential handoff. The protected ActiveX adapter also
sets and verifies ordinary Windows Error Reporting suppression before it
creates its control. Default and Standard keep their existing desktop diagnostics.

The Windows installer registers the WER exclusion only for `Wormhole.exe` in
the machine's native 64-bit registry view. It preserves an existing entry and
uninstalls only its own unchanged entry. It also removes the exact previous
Wormhole LocalDumps defaults during upgrade and preserves customized values.
An executable outside that installer needs its own machine WER exclusion
before it can satisfy a strict profile. These checks cannot prevent privileged
collection or a later administrator policy change. Hibernation restrictions
remain open. Hardened and Paranoid admission remains unavailable.

### Child process policy

On Windows the native vault service and its migration launch install the
kernel child process restriction before opening the workspace. They verify
the effective policy without the secure-process exception and stop startup
if Windows cannot confirm it. The policy applies to the vault process.
External protocol hosts and legacy backend operations have separate lifecycles.

For offline SFTP edits, the vault authorizes a reveal only for a valid record
and an inactive transport scope. Electron main opens the folder from the
selected workspace, node and edit IDs. The renderer receives the public
operation result.

On Linux, migration reads the original `linux-secret-service-v1` credential
references directly from Secret Service. It uses the same attribute mapping as
retirement. A missing or ambiguous item stops staging. Both native migration
reads and retirement require an existing D-Bus session.

Linux amd64 and arm64 vault and migration processes install a seccomp filter
across all their threads before opening the workspace. It denies creating a
new process or replacing the vault executable. Go threads remain supported.
If the kernel cannot install the filter, vault startup stops. External protocol
hosts and legacy backend operations continue to run as separate processes.

On macOS, authentication document and protected-file keys use the native
Keychain API in the original file-based Keychain namespace. The backend
reads the older raw, hexadecimal and base64 Go keyring representations and
keeps the historical base64 representation for new entries. The system can
request permission when the backend first reads an item written by the old
CLI.

Packaged Electron starts the Touch ID broker as a sibling of the macOS vault.
It passes the other end of the broker's anonymous UNIX socket to the vault as
an inherited descriptor and closes its own copy before issuing requests. The
broker verifies and launches the signed Touch ID helper. Probe, enrollment,
unlock and removal use the same native request coordinates and return data
only over the inherited channel. If the vault exits or cancels an in-flight
request, channel loss cancels the helper. Software unlock remains available.

The macOS vault and migration service install and verify a hard process limit
of zero before opening a workspace. XNU applies the limit to fork and
posix_spawn. Startup refuses root because the kernel exempts it from this
limit. Signed Touch ID and native process enforcement still require a macOS
runtime check.

[Microsoft child process mitigation policy](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_process_mitigation_child_process_policy)
[Linux kernel seccomp filter](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
[Apple macOS Keychain implementations](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)
[Apple XNU process creation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_fork.c)

For local SSH and SFTP, a saved Bitwarden login can use the encrypted CLI
session imported during vault migration. Main requests a plan from the
vault after host verification. The vault checks the plan revision again
before sealing a one-use ticket to a dedicated `serve` process. That process
checks the saved CLI path and region, looks up the exact login item and
seals the password to the protocol child. Routed connections keep the
authenticated route and local endpoint in both releases. Closing the relay
cancels the CLI.

Saved VNC connections in the local vault can also use a Bitwarden login on
direct and VPN-routed connections. The VNC ticket has its own cryptographic
domain. Before issuing it, the owner checks the current connection revision
and route. The resolver reads the selected cached login and seals its password
to the VNC process. A cache miss ends this attempt without requesting a
Bitwarden sync. Closing the connection or locking Wormhole cancels the lookup
and waits for the resolver to exit.

Saved embedded RDP connections in the local vault resolve Bitwarden account
references for the destination and an independent gateway. The vault encrypts
the RDP settings and any local passwords directly to the RDP process. The
resolver gets the selected item IDs and seals only their account values. The
RDP process authenticates both envelopes against the per-opening link before
starting the native client. Changes to the gateway credential invalidate the
pending release. A gateway configured to reuse the destination account needs
one lookup. VPN routes follow the existing RDP gateway and certificate policy.
Closing the connection or locking Wormhole cancels any pending lookup.

For a direct local RDP connection with temporary destination credentials, the
protected document and the Bitwarden gateway have separate encrypted envelopes.
The vault binds the gateway release to the submitted document and the current
gateway revision. The RDP process opens both envelopes for the same connection.
A gateway configured to reuse the destination account uses the temporary
account supplied by the document.

In an unlocked local vault, **Settings → Extensions → Unlock Bitwarden CLI**
renews the session of a configured CLI that has already signed in. An isolated
password window seals the master password to a dedicated native process.
The native process gives the CLI a password stream through stdin on Unix or a
local Windows pipe bound to the launched CLI process ID. It encrypts the
returned session to the vault's one-use recipient. The vault checks the
current CLI configuration and encrypted row revision before saving the
session. Electron relays the encrypted envelopes. Lock, navigation, and window
closure cancel the operation.
After cancellation, the native worker waits for the CLI to exit. First-time
sign-in requires protected storage for the CLI account state. The upstream
CLI can persist readable access and refresh tokens in its default profile.
Additional protocol consumers remain open.

[Bitwarden CLI profile storage](https://github.com/bitwarden/clients/blob/main/apps/cli/src/service-container/service-container.ts)
[Bitwarden token storage](https://github.com/bitwarden/clients/blob/main/libs/common/src/auth/services/token.service.ts)

[Electron crashReporter](https://www.electronjs.org/docs/latest/api/crash-reporter) ·
[Microsoft SetErrorMode](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-seterrormode) ·
[Microsoft WerAddExcludedApplication](https://learn.microsoft.com/en-us/windows/win32/api/werapi/nf-werapi-weraddexcludedapplication) ·
[Microsoft LocalDumps](https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps)

### Resumable native protected-file retirement

The native migration coordinator now retires inventoried protected files and,
on macOS/Linux, their per-path protection keys. This is not wired to an app
migration command yet. SQL retirement is a separate native continuation described
below. Native Chromium inventory/retirement is also implemented below. The app
coordinator, runtime SSO adapters and final publication remain subsequent work.

Before the first removal, the coordinator verifies the closed staging snapshot,
its complete native integrity inventory and the current source checkpoint under
exclusive workspace ownership and one reserved source transaction. It transitions
the stage to `retiring` and persists an encrypted `migration-retirement` journal.
A matching authenticated slot marker at the source disables legacy access. Pending
stage-slot presence also blocks legacy entrypoints, even if the source marker is
lost, malformed or removed; unauthenticated stage phases cannot re-enable access.
Only the authenticated migration coordinator can resume/rebuild copy phases. Neither
source nor stage permits ordinary vault use. The copying path cannot rebuild or
regress a retiring stage.

Each file receives a durable intent containing its original protected bytes before
its external key or file is removed. The binary journal keeps the payload outside
JSON/base64, within the existing 64 MiB encrypted local-state limit. It binds the
source/choice commitment and authenticated aggregate counts. Retry verifies the
source database, rejects new or changed files, authenticates the pending payload,
and can finish an operation whose external deletion succeeded before its progress
write. A matching completed file that reappears may be retired again. Missing
unstarted files, lost guards, missing archives and malformed journals fail closed.
The original SQLite database remains intact throughout this phase.

Keychain deletion is checked: an existing key must decrypt the inventoried
ciphertext, deletion must succeed, and a subsequent lookup must confirm absence.
An absent key is accepted only within the persisted retirement intent. The
Bitwarden recovery file uses the primary file's key. Windows DPAPI master keys
belong to the OS and are never deleted by Wormhole. Source removal does not claim
secure erasure of historical disk blocks, OS backups or an untracked copy.

### Native credential-keychain retirement

The native-only continuation also retires inventoried credential references from
macOS Keychain and both Linux Secret Service encodings. Its version-2 encrypted
journal adds a separate key cursor and one pending key intent; old file-only
journals remain readable and are explicitly upgraded. A pending key intent is
resumed before any other file or key, and the file-only entrypoint refuses to
ignore it. No ordinary workspace access or final publication is enabled here.

Every deletion requires the exact source row, encoding, reference and keyed
commitment to the original decrypted bytes. The complete source SQLite checkpoint
and native archive integrity are verified first. The value is checked again after
persisting the intent, and its owned plaintext is cleared before native deletion.
A subsequent lookup must confirm absence before progress advances. Missing values
are accepted only for a pending or already completed operation. Empty credentials
remain distinct from missing ones. Changed, locked, unavailable or ambiguous stores
fail closed and retain recovery state. SQL rows remain intact until the separate
SQL retirement continuation begins.

Linux uses a private, bounded-lifetime D-Bus connection and distinguishes locked
and unlocked search results. Older `secret-tool` records use `account`; later
records use `username`. It reads exact bytes, removes one selected item and never
executes an unlock/delete prompt. macOS resolves exactly one item, bounds its
native copy before allocation, deletes the selected native reference and releases
it on close. A failed read never authorizes deletion. Windows DPAPI master keys
are untouched, and foreign OS references are refused. Native stores do not offer
compare-and-delete transactions: the coordinator requires exclusive Wormhole
ownership and source quiescence; hostile same-user mutation while unlocked remains
outside the issue's threat model.

Portable wire-model and native-stage tests cover interrupted deletion, absent and
empty values, replacement during the durable-intent write, replay, file/key intent
exclusion, malformed journals, cancellation, byte clearing and preserved archives.
Linux CI additionally runs a private `dbus-daemon` and an in-process test Secret
Service to exercise real wire marshalling without accessing a user's desktop
store. macOS CI creates and removes only fresh UUID test items in its unlocked
runner keychain. These platform integration tests must pass on their native
runners; cross-compilation alone does not verify desktop keychain interoperability.
The small C bridge is outside Go's coverage instrumentation; its actual successful
read, bounds, reference lifecycle and deletion are asserted by the native macOS
test. Allocation-failure and real locked-keychain UI cases require the manual
platform matrix, rather than synthetic coverage credit.

### Native Chromium inventory and retirement

Staging with an absolute native user-data path now inventories the Azure SSO,
origin-scoped WatchGuard and Bitwarden extension partitions. Historical persistent
Fortinet and global WatchGuard partitions are included too. Their complete regular
files and empty directories are retained, including IndexedDB and extension
storage. Ordinary unrelated profiles are excluded. A copy of the shared Chromium
`Local State` file preserves the original OS-crypt context; that shared file is
never deleted. Unknown owned namespaces and registered default/custom Bitwarden
roots without an implemented selective adapter stop migration instead of producing
a false empty-browser proof.

Files are encrypted as native `legacy-browser-file` local-state records. Keyed
commitments bind the native user-data path, workspace, profile, file path, size
and exact bytes. Each write must match the initial source inventory, and the
complete copied manifest must match too. Source replacement, unsafe path aliases,
symlinks and non-regular files fail closed. Borrowed contents are cleared after
use. The current bounded format accepts 256 profiles, 4,096 file/directory entries,
32 path components, 64 MiB per file and 128 MiB total; larger inventories are
refused before source retirement. Batched handling of larger profiles remains
part of the complete migration work.

After file/key retirement, the version-4 encrypted journal adds a browser cursor
and one pending profile intent. Archive integrity is verified before deletion.
Native `os.Root` confines recursive removal to the authenticated partition root;
its pathname identity is checked before and after removal, absence is verified,
and the parent directory is synced before progress advances. A pending retry may
contain only a matching subset of the original files. New or changed data,
missing unstarted profiles, false deletion acknowledgements and replacement
parents retain the recovery intent. The shared root may change cosmetics after
a restart; its original archived bytes are retained without deleting or replacing
the live shared file.

SQL retirement requires completed browser intent and a fresh absence check when
a browser inventory is present. Old native-only inventories lacking that proof
are not evidence of a completed app migration. Windows tests additionally create
real temporary Chromium profiles, close the owning Electron process, and run the
Go stage, archive verification, browser retirement and SQL compaction. These
tests do not establish a runtime restore adapter or the app migration UI.

### Resumable native SQL retirement

After file, credential-key and inventoried browser retirement, a native-only continuation retires all
`CredentialSecrets` rows, including the MCP token, inline/profile secrets and
tunnel rows. The complete staging inventory, source quarantine marker, file
absence and native credential-store absence are verified again. Unfinished file
or key operations, changed source metadata and unexpected sidecars fail closed.

The version-3 journal (version 4 when browser retirement is present) records the exact keyed database
checkpoint predicted with only those secret rows omitted. Its pending intent is
durable before the source is changed. SQLite uses exclusive locking, DELETE
journaling, FULL synchronization and `secure_delete=ON`. The actual post-delete
checkpoint must match the prediction before commit; trigger or cascade changes
to other rows cause rollback. An interrupted commit can resume from either the
original or the authenticated empty-secret state.

The committed deletion is followed by `VACUUM` and another checkpoint and file
identity check before the journal records `compacted`. A completed retry verifies
the source without rewriting the journal or repeating compaction. Existing
file/key entrypoints reject a started SQL phase. Unrelated metadata and the
encrypted native archives are preserved; neither source nor stage is published.
As with file retirement, this does not erase historical disk blocks, OS backups
or copies outside the migration inventory.

The app migration command, protected fresh-authentication/relaunch flow, remaining
legacy-root adapters, runtime SSO consumption and final atomic publication remain pending. The SQL
continuation is exercised only against synthetic test workspaces until that
coordinator owns the complete cutover.

## Verification

Run from `tools/wormhole-backend`:

```text
go vet -unsafeptr=false ./internal/encvfs
go test -coverprofile=vault.coverage ./internal/vault ./internal/securemem ./internal/encvfs ./internal/vaultwire ./internal/vaultstore ./internal/localvault
go test -count=1 -timeout=35m -coverprofile=vault-entry.coverage .
go test -race ./internal/vault ./internal/securemem ./internal/vaultwire ./internal/vaultstore ./internal/localvault
go test -count=1 -timeout=35m ./...
```

CI publishes `merged-vault-coverage` after the Windows, Linux and macOS vault
jobs succeed. It combines their Go statement profiles with the Linux and Windows
PostgreSQL tests and the Windows Electron enrollment tests. A portable block counts
once across all runs. Native files count on the platforms that compile them. The workflow reports the total
in the job summary and retains the existing per-platform coverage gates.

Native allocation failures, failures of fixed valid standard-library
constructors, and denied OS dump controls may not be reproducible on every host;
there are no exclusions from the measured package denominators. Windows native
allocation converts a VirtualAlloc address into a slice. The encrypted VFS
converts addresses supplied by modernc into native structs and I/O buffers.
`go vet -unsafeptr=false` is scoped to `internal/securemem` and `internal/encvfs`.

Run `npm run test:vault-client` for Electron contract, lifecycle, IPC and real Go
pipe tests. Node's native coverage measures the `electron/vault-*.ts`
modules with the project's 80% line/branch/function thresholds. Electron's large
main/preload entrypoints remain outside that unit-module denominator, consistent
with `scripts/test-coverage.ts`; their thin wiring is checked separately, while
behavior is tested through registered IPC handlers and actual child processes.
The modified app-lock handler is additionally executed from the real main source
with the existing authentication test harness and its 80% V8 block coverage gate.
Those cases verify cleanup while vault exit is pending, unconfirmed exit, native
service failure and a window that has already disappeared.

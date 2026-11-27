# Shared PostgreSQL deployment foundation

## Fresh database deployment

`deploy.SchemaScript` renders the same versioned migrations used for DBA
upgrades as one transaction. Run the exported SQL on a fresh connection to the
intended empty database, or use the native `sharedpg.DeploySchema` operation.
Both paths apply the current schema and verify its workspace identity, version,
TLS requirement and provisioning state before committing. The rendered script
contains no login secrets. The native operation accepts only the local script
generated for the supplied workspace identity and uses a dedicated connection.

After commit, **Run now** verifies the PostgreSQL catalog. **Check deployment**
performs the same read-only check after SQL export or reconnection. The app
repeats it before preparing the first administrator. It compares a SHA-256
fingerprint of the `wormhole_api_v1` and `wormhole_data` catalogs with the
schema shipped by Wormhole. The check covers function bodies, signatures,
execution settings, owners, table and column grants, and the definitions and
enabled state of application triggers. Monthly audit
partitions may come and go under the same permission policy. A changed grant
on a single partition fails verification.

If verification fails, confirm the database and workspace identity, then ask
the DBA to compare the installed routines and grants with the exported SQL.
After correcting the difference, select **Check deployment** again. When a
migration changes the expected catalog, maintainers verify the fingerprints
against clean installations by both a superuser and a delegated DBA in
`TestPostgresAtomicSchemaDeployment` and `TestPostgresSchemaDeploymentWithDelegatedDBA`.

### Upgrade an existing workspace

Use the backend bundled with the target Wormhole version to export the next
versioned SQL transaction. Read the current values on a DBA connection to the
workspace database.

```sql
SELECT role_tag, workspace_id, schema_version FROM wormhole_data.workspace_meta WHERE singleton;
```

For example, this PowerShell 7 command exports the 91→92 migration. Use your
workspace's values and the backend executable for your architecture.

```powershell
'{"roleTag":"acmeprod","workspaceId":"5581ede5-b096-44ea-869b-c165e4ca114f","installedVersion":91}' |
  .\wormhole-backend-x64.exe --operation export-shared-schema-upgrade > upgrade-92.sql
```

The offline exporter reads its request from stdin and writes SQL to stdout.
Check the exit code before using the file. Review the script and apply it on
a dedicated DBA connection during a maintenance window, for example with
`psql -v ON_ERROR_STOP=1 -f upgrade-92.sql` on the intended database. Each
transaction checks the workspace identity and installed version and takes the
schema migration lock. For older workspaces, repeat for the next version after
each commit. Run **Check deployment** once the workspace reaches the app's
schema version.

### Client access rules

For self-hosted PostgreSQL, open **PostgreSQL client access rules** in the
setup wizard. Enter the client IP addresses or CIDR networks that may connect
and select **Export pg_hba.conf rules**. The exported file applies to the
selected database and login names starting with the workspace’s exact role
prefix. It covers devices, invitations, reset logins and the workspace
deployer. The temporary DBA login uses the DBA’s own rules.

Place the file beside `pg_hba.conf`. Put `include wormhole-workspace-hba.conf`
before broader host rules, using the actual exported filename, and reload
PostgreSQL. The first matching rule applies. Each permitted range requires TLS
and SCRAM. A final rule rejects other TCP connections for the same database
and role prefix. For managed PostgreSQL, configure client networks and TLS
enforcement in the provider’s controls.
[PostgreSQL client authentication](https://www.postgresql.org/docs/16/auth-pg-hba-conf.html)

**Check deployment** sends one plaintext startup message for the workspace
deployer to the same server address from the same client IP as the verified
DBA connection. It closes the socket after the first response. The wizard
reports whether the server refused startup, offered authentication, or gave
an inconclusive result. The DBA must verify the rules for other roles, routes
and networks. The wizard also reports statement logging, parameter logging
and nested statement tracking observed on the DBA connection. A verified
endpoint offering SCRAM without SCRAM-SHA-256-PLUS produces a separate
channel-binding diagnostic.

### DBA permissions and preflight

On PostgreSQL 16, a delegated DBA needs database and public-schema ownership,
`CREATEROLE`, and authority to grant `pg_read_all_stats`. The fresh schema
transaction temporarily enables access to the roles created by the DBA and
revokes these added memberships before commit. PostgreSQL's creator ADMIN rights
remain in effect while that DBA role exists. A scoped column grant allows the
same login to reconcile an interrupted deployment. It covers the workspace UUID,
role tag, schema version, TLS requirement and state. The DBA also receives
permission to invoke the one-time bootstrap introduced in schema version 44. The application
account, signed policy and other private tables remain protected. Revoke the temporary
DBA login and its grants according to the provider's provisioning procedure.
See [PostgreSQL role creation](https://www.postgresql.org/docs/16/role-attributes.html#ROLE-CREATION)
and [the creator self-grant setting](https://www.postgresql.org/docs/16/runtime-config-client.html#GUC-CREATEROLE-SELF-GRANT).

`CheckDeploymentPrerequisites` reports connection failure stages using fixed
names and reads PostgreSQL version, deployment privileges, database emptiness
and logging settings. A successful TLS connection has completed SCRAM with
channel binding. Diagnostics come from a read-only query and expose neither
driver messages nor credentials. Connection failures report the furthest layer
observed across configured endpoints. A provider's additional restrictions may
still require a separate DBA to run the script. The transaction rechecks the
target before creating any objects and rolls back if a migration fails.

If the server disconnects before returning a confirmed commit, use
`CheckSchemaDeployment` on a new connection for the same workspace ID and role
tag. A successful inspection reports the server's deployment state. Workspace
admission still requires authentication of the signed organisation and device
state. The app wizard supports schema preflight, direct deployment, DBA script
export and reconciliation. Provider-specific setup is still pending.

Schema 45 adds audited workspace CA access for server certificate renewal.
For a schema-44 installation, the DBA can apply
`deploy.ServerCertificateRenewalMigration(roleTag, workspaceID)` on a dedicated
connection with the workspace owner role available. Fresh deployments include
the migration in the generated schema script.

Schema 46 adds staged CA rotation and retirement. Apply
`deploy.WorkspaceCARotationMigration(roleTag, workspaceID)` to an existing
schema-45 workspace with the same DBA setup.

Schema 47 adds audited recovery kit refresh after CA retirement. Apply
`deploy.WorkspaceRecoveryKitRefreshMigration(roleTag, workspaceID)` to a
schema-46 workspace with the same DBA setup. Fresh deployments include both
migrations. See [workspace CA and recovery kit operations](vault-workspace-ca.md).

Schema 48 adds the native break-glass recovery transaction. Apply
`deploy.WorkspaceAdminRecoveryMigration(roleTag, workspaceID)` to a schema-47
workspace. It uses the workspace's dedicated `wh_<tag>_deployer` login over
Verified TLS. Go opens the offline recovery kit with its code, verifies the
signed TLS bundle against the recovered organisation key, and checks the ready
workspace before certifying a new administrator. PostgreSQL publishes an
ordinary one-time invitation and its audit entry in one transaction. The native
path supports a single active escrowed workspace boundary at Default and
Standard. On a new app installation, choose **Recover shared workspace access**
and enter the workspace coordinates, deployer credentials and new administrator
credentials. Select the matching `.whrecovery` kit and signed `.whtls` bundle.
If interrupted, reopen the wizard with the same workspace and administrator
login to resume the encrypted checkpoint while the invitation is valid.

Schema 49 adds `export_workspace`. Apply
`deploy.WorkspaceRecoveryExportMigration(roleTag, workspaceID)` to a schema-48
workspace. On Verified TLS, the endpoint checks the current administrator
session, signed policy, account and TLS state, and both organisation key
copies. It reads the persistent catalog, permissions, encrypted values, key
graph and recovery custody records from one PostgreSQL snapshot and audits
the release. Runtime login, session and invitation credentials stay on
the source cluster. Default and Standard exports require escrowed boundaries.

The native vault checks the custody proof and, at Standard, requires fresh
account factors. It publishes a schema-3 Wormhole JSON backup using the
existing PBKDF2/AES-GCM envelope and a generated 256-bit recovery password.
In an admitted administrator session with an escrowed workspace and a signed
Verified TLS bundle, choose **Export workspace recovery backup**. Standard asks
for the current account password and its Account Secret Key when configured.
Wormhole prompts before saving to a recognized cloud-sync folder. Other providers
and folders may sync files under custom paths. The isolated window shows the
backup password once, so record it and store it separately before closing.

On a fresh app installation, choose **Restore a shared workspace**.
The protected window opens the encrypted backup with its recovery password.
Go checks the supported archive format and verifies the archived policy and TLS
signatures against the organisation signing key in the authenticated archive.
The window displays the original workspace ID, role tag, source schema and
record counts. Use **Save deployment SQL** to generate the schema for a
dedicated destination with that workspace ID and role tag. The generated SQL
contains deployment definitions and the workspace identity.

Schema 50 enables import into an untouched deployment with the matching
workspace ID and role tag. Apply
`deploy.WorkspaceRecoveryRestoreMigration(roleTag, workspaceID)` to upgrade a
schema-49 deployment. Fresh scripts include the migration. The wizard opens
archives from schemas 49 through 58.

Use a host approved by the archived signed TLS bundle and install a server
certificate that verifies against it. The DBA enables the dedicated
`wh_<tag>_deployer` login and configures `log_statement=none`,
`log_parameter_max_length=0` and `log_parameter_max_length_on_error=0` for
its connection. Turn off `pgaudit.log_parameter` if the server uses pgAudit.
The app checks these settings before sending the archive.

In the wizard, enter the destination coordinates and both passwords, confirm
the destination, then select **Restore to PostgreSQL**. The transaction preserves
the persistent graph, publishes a new catalog epoch, and records one restore
audit entry. Source device records, login verifiers, invitations and sessions
stay on the source cluster. If the commit reply is interrupted, retry the same
archive and destination. PostgreSQL uses the archive digest to identify a
completed restore.

Use **Recover shared workspace access** with the organisation kit to establish
an administrator on a supported single-boundary workspace.

## Account key custody

Schema 51 prepares accounts for password reset. Apply
`deploy.AccountRecoveryCustodyMigration(roleTag, workspaceID)` to an existing
schema-50 deployment. At native unlock over Verified TLS, the client checks the
signed escrow policy and the current certified account keys. The first eligible
custodian certifies the organisation encryption key with the trusted
organisation signing key. Clients then seal their own encryption and signing
private keys to that recipient in Go. PostgreSQL stores the two signed
ciphertexts and audits releases and writes. The backup includes those copies.

This deposit covers Default and Standard workspaces with organisation escrow.
Accounts enrolled before the upgrade must unlock with their current factors to
deposit their keys. An account can sign in while escrow is unavailable because
the recipient proof is invalid or a write is busy.

## Account reset offers

Schema 52 adds native reset issuance. Apply
`deploy.AccountResetIssuanceMigration(roleTag, workspaceID)` after schema 51.
The Go backend verifies the custodian and the target's enrolled identity before
opening the two escrow copies. It generates a fresh 128-bit code and 256-bit
ASK and requires both to open the account keys. The organisation signs the
offer, including the workspace identity, account login, wrapping revision,
policy and TLS trust.

Each offer has a 12-hour lifetime and its own scoped SCRAM login. Publishing
the same offer again reconciles a lost receipt. A replacement disables the
old login, removes its ciphertext and records its retirement. The protected
native presenter can borrow the factors once after publication.

From an admitted workspace with escrow enabled, a custodian chooses
**Issue account reset…** and confirms with their own password and ASK when the
device uses one. In the single-offer form they enter the recipient’s Wormhole
login. Wormhole saves the
signed `.whreset` offer to a new file before PostgreSQL enables the reset login.
After PostgreSQL confirms issuance, the protected dialog shows the reset code
and new ASK once. Send the file, code and ASK separately.

Before publishing, the backend checks that statement and parameter logging
are disabled on its issuer connection, including pgAudit logging and nested
utility tracking by pg_stat_statements. Reset roles and offers stay with the
original cluster.

Schema 53 adds native redemption. Apply
`deploy.AccountResetRedemptionMigration(roleTag, workspaceID)` after schema 52.
The recipient derives the new account master from the replacement password
and the new ASK. Go wraps the original key pair at the next revision and
requires the caller to save the pending device before dispatch. One PostgreSQL
transaction verifies both reset factors, updates the account, revokes previous
device logins and admissions, and consumes the offer.

The new device can prove the current reset receipt and exact saved wrapper
through ordinary authenticated admission. Its initial login expires after
one hour unless device confirmation succeeds. The native app publishes the
password/ASK-encrypted device and pending reset in the OS-protected startup
selection before sending PostgreSQL the write. Ordinary enrollment recovery
only proves a committed reset and can restore missing pieces of that
selection. Explicit continuation reopens the same request using the original
code and the new password/ASK. After confirmation, the app publishes the
ordinary startup anchor.

On a fresh local destination, the recipient opens **Join a shared workspace**
and selects **Use an account reset file**. The native picker selects the
`.whreset` offer, and the protected window accepts the separate code and new
ASK, a replacement password and a device name. After interruption the sign-in
screen identifies the pending reset. It can verify a completed reset with the
new password and ASK, or continue the same request with the original code.
Schema 54 adds the custodian queue and persistent handover tracking. Apply
`deploy.AccountResetHandoverMigration(roleTag, workspaceID)` after schema 53.
In **Issue account reset…**, select accounts to reset. **Select accounts that
need an offer** includes eligible accounts from the loaded pages with a missing,
expired or inactive offer. For each account, confirm your factors, save its
signed file and deliver that file, the reset code and the ASK separately. The
batch has no combined export.

Choose **Mark handed over and continue** after delivery or **Leave pending and
continue** to record it later from the account list. Each confirmation applies
to one offer. Replacing an offer retires the earlier one, and redemption is
visible in the list. Schema 53 keeps the single-offer form.

## Local workspace import

Schema 55 adds the native import transaction. Apply
`deploy.WorkspaceImportMigration(roleTag, workspaceID)` after schema 54.
The admitted writer supplies the signed document and the identities and
revisions of its existing destination boundaries. PostgreSQL checks current
account state, Verified TLS and boundary Write. The catalog, field envelopes,
key copies, receipt and audit entry commit together. Retrying the same request
with the same signed document returns the prior receipt.

The recovery archive includes the separately stored node data bound to the
imported node seal. The native metadata reader verifies that attachment against
the current node seal. PostgreSQL requires View and Use on the node, plus Use
on its boundary and the boundaries of any retained saved credentials. The
response contains the note revision and retained account metadata.

The native planner returns the signed attachment with the selected account and
authenticates the result again in Go. The app uses path-bound release for SSH,
standalone SFTP, RDP and VNC. File tabs that reconnect from an SSH connection keep
the SSH identity and open only the file subsystem. Go uses the inherited
protocol to check the default path, and the database records the actual path
in the committed audit and single-use ticket. The release checks Use and the
selected field versions again before returning ciphertext.

The app checks server support before requesting a ticket. Earlier servers keep
their existing release APIs. A refused or mismatched path ticket ends the
operation. Tunnel settings and IPsec-to-SSL fallback for a supported pinned
node use its authenticated route and retain separate fallback authorization.
RDP resolves the desktop and gateway from one locked catalog snapshot and
binds both to one audited ticket. The app uses the verified historical
identities when they differ from the credential profile. Manual RDP keeps the
primary credentials in the sealed prompt and borrows only an independently
selected gateway value.

Schema 56 adds protected notes. Apply
`deploy.ImportedNoteViewMigration(roleTag, workspaceID)` after schema 55.
New note imports wrap the note DEK to the boundary's signed view key. Earlier
imported notes retain their original secret-root copy. The **Notes** action in
the shared catalog sends the selected node and exact revision to Main. PostgreSQL
checks View on the node and its boundary and requires a committed audit event
before releasing the note graph. The ticket is single-use. The new node seal
authenticates the note revision independently of retained account pins.
Reading a legacy attachment with pins also requires the existing account
permissions. Go verifies the current policy, enrollment, node seal, note
reference and key copies before opening any key. Go seals the note to the
isolated notes window. The catalog receives only the display hint and revision.

Schema 57 adds authenticated destination selection and personal provisioning
for the deployment's first administrator. Apply
`deploy.PersonalImportBoundaryMigration(roleTag, workspaceID)` after schema 56.
The personal boundary is identified by the workspace and account together.
Go generates distinct view and secret keys and wraps each for the enrolled
account and the certified organisation recovery recipient. The organisation
signs the manifest. PostgreSQL commits the roots, four copies, owner grant and
audit event together. A retry reads the original signed manifest. Archive
export, restore and break-glass verify that both custody copies are present.
The backend keeps the default personal destination separate from the shared
workspace boundary.

Schema 58 adds signed setup import receipts. Apply
`deploy.SetupImportReceiptMigration(roleTag, workspaceID)` after schema 57.
From an unlocked local vault, open the protected setup wizard and choose
**Preview local import** after publishing the first administrator invitation.
Each item starts as Personal. Choose Shared explicitly and review dependencies
and differences in resolver choices before confirming. Re-enter the
administrator factors to import and select the shared workspace for restart.
The app also supports completing setup without an import.

Go binds the approval to the source snapshot, the destination workspace and
account, and the reviewed destinations and resolver choices. The encrypted
records and signed approval receipt commit in one PostgreSQL transaction.
An interrupted attempt can reconcile the same approval without a second
copy. If the source or choices differ, the existing receipt is left intact.
Source secret fields are borrowed only by Go and the source vault remains
available on disk.

Schema 59 adds administrative inventory. Apply
`deploy.AdminInventoryMigration(roleTag, workspaceID)` after schema 58.
Sign in as an administrator using verified TLS and open **Workspace
administration**. The isolated window has sections for accounts, devices,
recorded sessions and audit. The server checks current administrator authority
and device admission for every page. The audit view shows the recorded action,
outcome, time, actor and session. The session view represents sign-in records.

Schema 93 adds **Credential slots** to this window. An administrator can review
the name, protocol and assignment policy of each slot on a boundary where they
have View permission. Each page shows up to 25 slots. Large author certificates
can shorten a page. Use **Next page** to continue. The Go backend verifies
the signed slot and its author and saves the verified revisions before it
sends the page to the window. A workspace on schema 92 can use the offline
upgrade command described above.

Schema 60 adds the **Groups** section. Apply
`deploy.AdminGroupsMigration(roleTag, workspaceID)` after schema 59.
Administrators can create or rename groups, add an enabled account by its
exact sign-in name, and remove accounts from a group. Deletion requires an
empty group with no grants. The server checks the displayed group revision
and stores an audit event with the group and affected member when applicable.
Groups with a boundary grant, key, or signed membership require a key-aware
membership change.

Schema 61 adds the **Grants** section. Apply
`deploy.NodeGrantAdministrationMigration(roleTag, workspaceID)` after schema 60.
Choose a shared item for which you have View and Manage, then select accounts
or groups. Direct grants can be added, edited and revoked. Folder grants are
inherited by descendants. The server limits delegation to permission bits
the administrator holds on that item. Existing signed grants require a
separate signing workflow.

Schema 62 adds **Review group key recipients** under **Groups**. Apply
`deploy.GroupKeyProvisioningMigration(roleTag, workspaceID)` after schema 61.
A custodian using verified workspace TLS can review the certified enabled
members and issue the initial group key. The review supports up to 64 enabled
members. Issuance also creates an organisation recovery copy and records a
group key event. Membership changes on a keyed group require key rotation.

Schema 63 adds group-wrapped boundary key support to audited release. Apply
`deploy.GroupBoundaryReleaseMigration(roleTag, workspaceID)` after schema 62.
PostgreSQL can select a group already granted the relevant boundary permission
when a direct account copy is absent. New notes require the View root.
Connection credentials and VPN fallback configurations require the Secret
root and the Use permission.

Schema 64 adds administrative publication of group boundary grants. Apply
`deploy.GroupBoundaryGrantsMigration(roleTag, workspaceID)` after schema 63.
In **Grants**, select a shared item, open **Group grants**, then choose
**Boundary keys**. Review the group, its certified recipients and the selected
permissions before confirming. This grants keys for the entire boundary. Each
item still requires its own effective permissions. Publication requires a
custodian on verified workspace TLS with Manage on the shared item and
boundary, plus the boundary permissions to delegate. Changes to the reviewed
group or boundary invalidate the review. A group whose certified roster changed
must rotate before receiving more keys.

Schema 65 adds `deploy.BoundaryRotationMigration(roleTag, workspaceID)`. After
upgrading from schema 64, choose **Rotate boundary keys** under **Group grants**
and select the permissions the group should keep. Confirmation replaces the
roots for the removed permissions and rewraps their DEKs in the same transaction
as the revocation and audit entry. A retry after a committed rotation reports
that the grant is already current. A pending invitation that holds an affected
root, a previous-root transition window or a graph that exceeds the transaction
limits prevents rotation through this action.

Schema 66 adds `deploy.GroupMemberRotationMigration(roleTag, workspaceID)`.
After upgrading from schema 65, choose a keyed group under **Groups**, select a
member and choose **Remove**, then **Review member removal**. Confirm to issue a
new group key to the reviewed remaining members and record the affected shared
boundaries in PostgreSQL. New writes that depend on a queued root wait for its
rotation. For interrupted work, open the group and choose **Resume key rotation**
as a custodian with Manage and the relevant permissions on the affected boundaries.
Recovery archives preserve pending rotations and their write guards. A boundary
graph outside the rotation limits can prevent a queued step.

Schema 67 adds `deploy.WorkspaceBoundaryRecoveryMigration(roleTag, workspaceID)`
after schema 66. **Recover shared workspace access** verifies organisation
escrow for each active shared boundary. It requires the offline kit, its
recovery code, verified TLS and the workspace deployer login. When restoring an
archive with a pending group rotation, complete the recovered administrator's
Join, then open **Groups** and choose **Resume key rotation**. The recovered
account gets the boundary permissions and signed key copies needed to resume.
Node permissions are administered through their existing grants. Standard and
Default support up to 511 shared boundaries per recovery invitation within
the existing Join copy limit. Earlier single-boundary checkpoints remain usable.

Schema 68 adds `deploy.GroupMemberAdditionMigration(roleTag, workspaceID)` after
schema 67. In **Groups**, enter the enabled, enrolled account's sign-in name and
choose **Add member**. For a keyed group, review the certified account and the
scope of its boundary keys, then choose **Confirm member addition**. The
custodian needs Manage and the relevant View or Use permission on each affected
boundary over verified TLS. PostgreSQL transfers the group's current boundary
wraps to the new group generation in the same transaction as the membership
and audit entry. Finish any pending removal and resolve outstanding recipient
changes before adding another member.

Schema 69 adds `deploy.GroupRotationReconciliationMigration(roleTag, workspaceID)`
after schema 68. If **Resume key rotation** reports changed recipients, choose
**Review changed recipients**. Check the named group, certified recipients and
revised boundary count, then choose **Confirm recipients and resume**. A group
sharing an affected root may need review first. Review requires organisation
custody and Manage plus View or Use on the corresponding boundaries. A recipient
without valid enrollment material requires account remediation before the group
can be rekeyed. Earlier rotation archives use their original retired generation
when restored.

Schema 70 adds `deploy.WorkspaceAccessMigration(roleTag, workspaceID)` after
schema 69. From the protected workspace window over Verified TLS, use
**Accounts** to review and then disable or enable another account. Use
**Devices** to revoke an enrolled device. **My devices** shows only the signed-in
account's devices. Revoking the current device signs it out. Re-enabling a
suspended account allows an active device to authenticate again. Revoked devices
require a new enrollment.

Schema 71 adds `deploy.AccountSuspensionInventoryMigration(roleTag, workspaceID)`
after schema 70. Select **Review access at suspension** on a suspended account
to inspect the recorded boundary keys and password references. The report
shows the captured root versions and their current status. Detailed entries
require View and Manage on the corresponding boundary. The encrypted backup
includes this inventory.

Schema 72 adds `deploy.AccountBoundaryRotationMigration(roleTag, workspaceID)`
after schema 71. In **Boundary keys**, use **Rotate key…** to review and confirm
the replacement of a captured root on an escrowed shared boundary. The
operation requires organisation custody and View, Manage and the permission
for that root. Start the related group-key changes in **Groups** before
resuming a rotation on a root held by several of those groups.
Writes stay frozen while the captured root is active and the account remains
suspended. Restoring an archive preserves that pending state.

Schema 73 adds `deploy.PersonalBoundaryRotationMigration(roleTag, workspaceID)`
after schema 72. A verified organisation custodian can review and rotate the
suspended account's personal import boundary on Default or Standard when the
signed workspace policy and the signed boundary both allow organisation escrow.
The inventory shows the captured key coordinates and keeps private password
references restricted. The replacement is held by the organisation.

Schema 74 adds `deploy.AccountSuspensionGroupsMigration(roleTag, workspaceID)`
after schema 73. In **Review access at suspension**, choose **Groups at
suspension** to inspect the captured shared groups. A group is listed by name
when you have View and Manage on at least one of its captured, live shared
boundaries. Open the group to confirm the removal with the usual key review.
Return to the account's group inventory to queue other removals before
resuming a shared rotation. **Open queued rotation** selects the job for this
account and group.

Schema 75 adds `deploy.ScopedGroupRemovalMigration(roleTag, workspaceID)`
after schema 74. A removal opened from the suspension inventory binds its
review to that suspension revision. If the account is enabled or suspended
again before confirmation, reopen the inventory and review the current state.
Previously committed jobs keep their original scope and can be resumed.

Schema 76 adds `deploy.EnrollmentHistoryMigration(roleTag, workspaceID)` after
schema 75. It retains public historical certificates for the signing keys used
in earlier account enrollments and includes them in encrypted workspace backups.
Rotation workers use the certificates to verify existing key copies. Live
authentication still requires the current signed account state.

Schema 77 adds `deploy.SuspensionEnrollmentMigration(roleTag, workspaceID)`
after schema 76. Once either personal root has rotated, **Enable account**
requires a fresh enrolled encryption and signing key, newer signed account
state and organisation-issued copies of both current roots for the new
owner. The migration captures the current enrollment for existing suspension
records, and restores from older archives do the same.

Schema 78 adds `deploy.PersonalRootRecoveryMigration(roleTag, workspaceID)`
after schema 77. In the protected suspension inventory, choose **Restore
personal keys** to review the replacement enrollment, then confirm with your
password and ASK if your account uses one. PostgreSQL publishes both encrypted
copies and the audit entry in one transaction. Re-enabling the account is a
separate access change.

Schema 79 adds `deploy.AccountReenrollmentMigration(roleTag, workspaceID)`
after schema 78. Native custodians can publish a signed replacement offer for
the exact suspension after both personal roots have rotated. A temporary SCRAM
role releases a capsule over Verified TLS. The recipient opens it with the
code and ASK and generates their final account keys locally. The standard
password-reset APIs continue to serve ordinary resets.

Schema 80 adds `deploy.AccountReenrollmentRedemptionMigration(roleTag, workspaceID)`
after schema 79. The custodian opens **Review access at suspension** and
**Restore personal keys**. When the review calls for a replacement enrollment,
choose **Issue re-enrollment offer**, confirm your factors and save the
`.whreset` file. Deliver the file, code and new ASK separately.

The recipient opens the file from the protected shared-workspace join screen.
The client saves an encrypted checkpoint before PostgreSQL replaces the account
keys and registers the device. The custodian can then restore both personal
roots, and an administrator can re-enable the account. The recipient resumes
with the new password and ASK from the same device.

## Self-hosted server certificates

The default self-hosted setup uses a Wormhole workspace CA. Enter the PostgreSQL
host and any additional DNS names or IP addresses. Run the wizard's Linux or
PowerShell 7 command with OpenSSL 3 on the database server in a directory
restricted to the PostgreSQL service account. Paste the contents of `server.csr`
into the wizard. Wormhole verifies the CSR signature and requires an exact match
between its SANs and the approved names. [OpenSSL request options](https://docs.openssl.org/3.6/man1/openssl-req/)

The wizard shows the signed server certificate and the public workspace CA.
Save the server certificate as `server.pem` next to `server.key` on PostgreSQL
and apply the displayed TLS settings. The connection test uses the workspace CA
to verify the server and host name. First administrator preparation also checks
the exact issued leaf before creating the signed TLS bundle.
The bundle includes the approved names. The server certificate is valid for 365
days and the workspace CA is valid for 1,825 days.

Use the same first administrator password and optional Account Secret Key when
resuming setup. They protect the temporary organisation keys used to issue the
certificate. The P-256 CA key is wrapped to the organisation encryption key
from creation. After the administrator checkpoint is durable, the setup plan
retains the public certificates and removes the temporary factor envelope.
Both PostgreSQL's bootstrap recovery capsule and the offline kit include the
wrapped CA. The workspace trust bundle and offline kit include its public
certificate. An existing CA remains available for self-hosted installations.

### Rotate the workspace CA

To rotate an existing self-hosted CA, open **PostgreSQL server certificates**,
enter a server CSR and choose **Stage a new workspace CA**. The app locks after
it saves the signed trust update. Sign in again to retrieve the issued server
certificate and export the signed bundle for offline devices. Install the
certificate on every configured PostgreSQL endpoint and reload PostgreSQL.
Choose **Check installation and retire the previous CA**. A successful check
locks the app again. Sign in to export the final trust bundle and update the
offline recovery kit.

### Generate the server key in Wormhole

Default and Standard can choose **Generate for me** and enter a separate
server-key passphrase of at least 16 characters. **Save server files** writes
`server.key` as encrypted PKCS#8, `server.pem`, `workspace-ca.pem` and
`postgresql-tls.conf` in a device-local cache folder for the workspace. The
key file has mode `0600` on Unix and a user-only ACL on Windows. Hardened and
Paranoid require a server-generated CSR.

Install the files on PostgreSQL and configure `ssl_passphrase_command` to
retrieve the passphrase from the server's secret store. The configuration
snippet enables reload support. [PostgreSQL passphrase configuration](https://www.postgresql.org/docs/16/runtime-config-connection.html#GUC-SSL-PASSPHRASE-COMMAND)

After schema deployment, **Check deployment** verifies the expected schema
through the exact issued server certificate. A successful check enables
**Delete local server key**. That action removes the digest-matched key from
the local package.

## First administrator

During first administrator setup, enter the expected number of concurrent devices
if clients connect directly to PostgreSQL. Leave the field blank for a transaction
pooler or an unknown topology. The organisation signs this choice in the workspace
profile. A certified device uses a second connection for `LISTEN wormhole_changes`
when the estimate is 1–300. Larger deployments and poolers use one query connection.
Every device fetches authenticated changes after unlock and polls every 30 seconds.
**Test connection** and **Check deployment** both report the server’s configured
`max_connections`. For direct connections, allow twice the expected concurrent
device count plus 20. For example, 300 devices require a budget of at least
620 connections. The first-administrator form calculates this value as you type.

Schema 92 gives each enrolled device role a connection limit of three. Temporary
invitation and reset roles have a limit of two. Follow [the upgrade procedure](#upgrade-an-existing-workspace)
with installed version 91. The migration updates active confirmed roles with the original limit of
two after matching their PostgreSQL OID and role name. An older pending device
receives its new limit when it confirms enrollment.

Schema 94 creates one PostgreSQL group for each account. Its name contains the
workspace tag and the first 20 lowercase base32 characters of the SHA-256 digest
of the tag followed by the account's immutable UTF-8 login name. A confirmed
device receives membership with the PostgreSQL `ADMIN`, `INHERIT` and `SET`
options disabled. Disabling the account removes that membership. Enabling the
account restores it for eligible devices. Revoking a device removes its membership.
The database records the cluster OIDs of the group and device. Recovery creates
fresh groups on the target cluster. A collision with an existing role aborts the
transaction, including any groups it has already created.

The native bootstrap prepares an organisation signer, an organisation encryption
key, the workspace boundary's view and secret keys, and a certificate chain for a
single-use administrator invitation. The first admin receives custodian and
boundary key copies through ordinary certified Join. The offline recovery capsule
encrypts both organisation private keys under a separate, randomly generated
recovery key. Opening it checks the workspace, both key identities and versions,
and both expected public keys.

The DBA connection uses Verified TLS with SCRAM channel binding. During
preparation, the client confirms the deployment identity and signs only the CA
roots that verified the server. The bootstrap transaction stores signed
records, encrypted copies and the invitation's SCRAM
verifier. It creates an audit entry and leaves the workspace in provisioning.
Retrying the same prepared records returns the current state. Different records
cannot replace the first administrator. The ordinary Join transaction moves the
workspace to ready when it installs the certified account. The device still
completes the standard confirmation step.

On a fresh Wormhole profile, the protected setup wizard saves an encrypted
checkpoint before publishing the invitation. The administrator password and
optional Account Secret Key unlock it during setup and after restart. The wizard
saves the encrypted offline kit to a user-selected file and displays its key in
the protected window. The code is hidden before the administrator confirms two
groups from their offline copy. Confirmation removes the recovery key from the
checkpoint. The temporary DBA password is entered again for publication and
remains transient. The resulting invitation and its code go directly to the
native Join coordinator.

From an unlocked local vault, open **Workspace storage** in Settings and select
**Create shared workspace**. The wizard uses the same deployment and recovery
steps. **Join and switch on restart** confirms the device in a separate native
directory and writes an OS-protected selection bound to the local profile path
and the admitted workspace, device and vault. The current local vault stays
open. Restart Wormhole to unlock the shared workspace with the new administrator
account. A damaged selection or missing shared destination blocks startup.
The original vault remains on disk. Importing local records and switching
between workspaces from Settings remain pending.

## Individual migrations

Issue #495 is incomplete. The first versioned deployment script now creates a
**provisioning-only** database. A second migration adds audited `session_start`.
It does not implement `get_changes_since`, nodes/grants, key distribution,
provisioning, or the remaining business APIs.
It must not be presented as a ready shared workspace.

`internal/sharedpg/deploy.InitialMigration` returns a reviewable SQL script for a
DBA to execute in an empty dedicated PostgreSQL 16+ database. It validates a
lowercase base32 workspace role tag (8–16 characters) and canonical nonzero UUID
before substituting identifiers. It performs no database connection or runtime DDL.

Migration `0001_identity.sql` creates workspace-tagged owner, user, admin, and
deployer roles; `wormhole_data` and `wormhole_api_v1`; and workspace, user, and
device identity tables. The owner cannot log in. The deployer does not inherit
owner privileges but may explicitly set the owner role. Its password remains unset
until a separate authorized enrollment step. Application users receive CONNECT
and API-schema USAGE, with no private-schema/table access or TEMP privilege.
Public database privileges and CREATE on the public schema are revoked. Owner
default function execution privileges are revoked globally, covering future API
functions as well as existing private functions.

Deployment is transactional and bounded by lock/statement timeouts. Existing
roles are never adopted. Existing user relations, functions, types, or custom
schemas cause rejection before role creation. A failed role collision rolls back
newly created roles. Login names are immutable, device role names must exactly
match their workspace tag and UUID, and an absent/empty profile cannot mark the
workspace ready. These database checks do not replace client-side signature
verification, which remains necessary in the future bootstrap flow.

`SessionMigration` is executed by a DBA and upgrades exactly schema version 1 for the supplied workspace
identity. It preserves provisioning state and defaults to requiring TLS. Its
`session_start` API checks `session_user` against active devices and enabled users,
requires read-committed isolation to prevent retained snapshots from bypassing
revocation, validates API/application/source metadata, and records the session
and successful-login audit in one transaction. Missing audit storage rolls back
admission. The private identity helper is not executable by clients. Future API
functions must repeat the identity check and enforce their own permissions.

PostgreSQL restricts SSL statistics across roles, including when a definer
function runs under the workspace owner. A separate workspace-tagged `observer`
role has no login and inherits only `pg_read_all_stats`. Its argument-free private
function returns SSL metadata for `pg_backend_pid()` only. Clients cannot execute
that helper or assume the observer role; the workspace owner has EXECUTE on the
helper but does not inherit monitoring privileges. The observer has no schema
CREATE privilege after deployment. Schema 86 also gives the observer column-level
access to device identifiers, role names and confirmed role OIDs for the live
connection inventory. See PostgreSQL's
[statistics visibility rules](https://www.postgresql.org/docs/16/monitoring-stats.html).

The migration creates current and next UTC-month audit partitions. Admission
fails closed if the required partition is absent. Later migrations add protected
enrollment. Native admission verifies
the profile under an independently pinned key and persists the authenticated
trust state. The migration test uses synthetic profile bytes to exercise the
database admission gate.

### Audit partition maintenance

Schema 85 adds a DBA maintenance function. Existing schema-84 workspaces can
apply `deploy.AuditMaintenanceMigration(roleTag, workspaceID)`. Fresh deployments
include it. Schedule the following transaction daily with the database host's
scheduler. Supply the workspace UUID and its owner role as psql variables, and
run psql with `-X --set ON_ERROR_STOP=1` so the scheduler reports failures.

```sql
BEGIN;
SET LOCAL ROLE :"owner_role";
SELECT * FROM wormhole_data.maintain_audit_partitions(:'workspace_id'::uuid);
COMMIT;
```

The owner role is `wh_<role tag>_owner`. The job's database login must be
authorized to assume it. The function creates partitions for the current UTC
month and the next two. It drops complete months older than the cutoff and
deletes expired rows in the month containing the cutoff. The default is 400
days. When the workspace retention policy specifies a different period, pass
that number of days as the second argument. The result reports partitions
created, partitions dropped and individual rows deleted from retained partitions.

Concurrent schema maintenance returns SQLSTATE `55P03`; retry the transaction.
An unexpected partition name or range aborts the transaction, preserving its
data. Investigate the layout before repeating the job. Application and enrollment
roles have no permission to run maintenance.

The same upgrade preserves administrator recovery when the previous
administrator's suspension has queued a shared root for rotation. A recovery
invitation can deliver the current escrowed roots named in its manifest to the
replacement administrator. The earlier single-boundary recovery checkpoint
keeps its original scope. Personal roots and the pending rotation remain
protected by the existing rotation checks.

### Optional row-level security

Schema 91 adds a second check on direct reads and writes to workspace tables.
It is off by default. To upgrade a schema-90 database, apply
`deploy.RowSecurityMigration(roleTag, workspaceID)`. On a dedicated DBA
connection, supply the workspace UUID and the tagged owner role as psql
variables and run this transaction during a maintenance window.

```sql
BEGIN;
SET LOCAL ROLE :"owner_role";
SELECT wormhole_data.set_row_security(:'workspace_id'::uuid, true);
COMMIT;
```

PostgreSQL enables and forces row-level security on every workspace table and
audit partition. The application's owner-executed API functions can still
access rows. The observer can read its existing device identification columns,
and the original delegated installer can read its existing workspace inspection
columns. A device with an accidental table grant sees no rows directly.
Scheduled audit maintenance applies the same protection to each new partition.

The change takes exclusive table locks and commits atomically. Retry a busy
workspace after its active transactions finish. An unexpected policy stops
the operation for DBA review. **Check deployment** verifies the policies and
their roles across the entire workspace. To disable the option, use the same
transaction with `false`. Configure the option again on the destination after
restoring a workspace to a fresh database. Keep the table ACLs in place.
PostgreSQL governs `TRUNCATE` and `REFERENCES` through those grants. Superusers
and roles with `BYPASSRLS` retain their platform privileges.
See [PostgreSQL row security policies](https://www.postgresql.org/docs/16/ddl-rowsecurity.html).

### Unencrypted clients

Schema 86 adds **Unencrypted clients** to the administration window. Fresh
deployments include it. To upgrade a schema-85 workspace, apply
`deploy.UnencryptedClientsMigration(roleTag, workspaceID)` as a DBA authorized
to assume the workspace owner and observer roles. An administrator connected
over TLS can refresh the list or page through 25 devices at a time.

Each row identifies a registered device with at least one live TCP connection
to this database using neither TLS nor GSS encryption. **Connected since**
shows the start of its oldest such connection. Refresh after the last socket
closes to remove the device. When a proxy terminates transport encryption,
the database can observe only the connection between the proxy and PostgreSQL.

### SSH host-key confirmation

To upgrade a schema-86 workspace, apply
`deploy.SSHHostPinMigration(roleTag, workspaceID)` as a DBA authorized to
assume the workspace owner role. Fresh deployments include the migration.
Schema 87 lets a member with Write confirm a fingerprint from the SSH or SFTP
connection prompt. The audit log records each committed change under
`ssh_host_pin_change`. [Shared tunnels](shared-tunnels.md)

## Real-server regression tests

Tests never download binaries or register a service. An operator supplies a
PostgreSQL installation and an absolute scratch directory using
`WORMHOLE_TEST_POSTGRES_BIN` and `WORMHOLE_TEST_POSTGRES_SCRATCH`. With both set,
run from `tools/wormhole-backend`:

```powershell
go test -race -timeout=3m ./internal/sharedpg/...
```

The vault CI matrix runs native transport, schema deployment, audit retention,
SCRAM, TLS, role logging and session admission tests against PostgreSQL 16, 17
and 18 on Ubuntu and the runner's PostgreSQL 16+ installation on Windows. Each server
version has a separate scratch directory and contributes its own Go coverage.
The Windows job also starts Electron and the native backend to verify a new
login with an ASK, a personal Standard minimum after locking and reopening, and
recovery of an encrypted workspace backup onto a second PostgreSQL cluster.
Local runs without the binary setting skip the real-server tests.
[Ubuntu runner inventory](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md)
and [Windows runner inventory](https://github.com/actions/runner-images/blob/main/images/windows/Windows2025-Readme.md).

Each real-server test initializes an isolated loopback-only cluster using a random
superuser password passed on stdin. No password file, password argument, or system
service is created. Windows processes are hidden; the test uses PostgreSQL's
Windows stdin-prompt mode to avoid `CONIN$` blocking. Process output is discarded
and statement logging disabled. Cleanup is registered before server startup;
cluster deletion requires confirmed shutdown and a generated child path under the
specified scratch root. Failed/unconfirmed startup or cleanup retains artifacts
for diagnosis and may require operator cleanup.

Real PostgreSQL tests cover SCRAM success/failure, Unicode/NULL parameter binding,
LISTEN/NOTIFY, the three-connection device-role limit, deployment atomicity,
nonempty-database rejection, role separation, explicit deployer SET ROLE, direct
table/CREATE denial, default function EXECUTE denial, and identity constraints.
Session tests additionally cover migration identity/version guards, provisioning,
required-TLS denial, unsupported API versions, malformed metadata, disabled and
revoked identities, effective-role changes, stale-snapshot isolation rejection,
successful audit persistence, and rollback when auditing fails. The same admission
suite also runs with verified TLS and required SCRAM channel binding, checks
persisted TLS version and observer privilege separation, and rejects plaintext
admission even when the server supports TLS. Wrong CA and server name are rejected
without plaintext fallback. Each TLS cluster uses a disposable synthetic
self-signed server identity; its private key is written only inside that temporary
test cluster and removed after confirmed shutdown, never used for user data.
The Go deployment generator has measured Go coverage. SQL/PLpgSQL is excluded
from that numerical Go coverage because the project has no SQL coverage
instrumentation; its security branches are tested against the real server.
The PostgreSQL-before-16 version rejection is inspected but not executed by the
PostgreSQL 16 test environment.

The current Windows validation used PostgreSQL 16.15 binaries from the
[official EDB archive page](https://www.enterprisedb.com/download-postgresql-binaries),
after explicit operator approval for their unsigned executables. The archive and
extracted tools remain in ignored test artifacts and are not application assets.

## Fortinet IPsec provider extension

After schema 40, apply the identity-bound `FortinetIPsecMigration` to reach schema 41. This extends `tunnel_profiles.kind` to 0–9 without rewriting signed metadata,
configuration ciphertext, permissions or existing migration 40. Reapplying it or
using a different workspace identity is rejected. Runtime roles retain no table
or private-helper grants. Live localhost integration covers the upgrade and the
unchanged release/permission checks. [IPsec runtime limits](vault-ipsec-flow.md)
remain separate from accepting its authenticated storage records.

## Separate secondary tunnel release

After the enrolled author migration reaches schema 42, apply the identity-bound
`TunnelFallbackMigration` to reach schema 43. It invalidates outstanding old use
intents and adds separate fallback intent/audit fields. Runtime roles retain no
table or private-helper grants. Admin continues to inherit the user role; every
public source operation still requires an enrolled device and its capability.

`begin_fallback_use` binds the connection node, original IPsec tunnel and secondary
SSL tunnel to the admitted user/device/session, snapshot and committed audit.
`fetch_fallback_secret` rechecks the permissions and returns a bounded ciphertext
graph before spending the irreversible single-use generation. The graph preserves
the signed primary route and includes the target separately. Final enrolled
recipient keys and author certificates participate without bootstrap substitution.

SQL cannot authenticate the encrypted primary-to-secondary reference. The native
shared controller now verifies the source and target signatures, publishes trust
observations to protected custody and validates that reference before opening the
target. The transport decoder alone grants no such authority. Native stdio can
plan and seal this separately authorized target; [fallback activation](vault-tunnel-fallback.md)
still requires the actor, secondary recipient/lease and SSO integration.

# Existing local workspace migration

This is the opt-in activation path for the currently supported local vault,
within the still incomplete [#495 roadmap](vault-roadmap.md).

## Application flow

Settings > Security shows when workspace password protection is off and explains
that stored secrets currently depend on the operating system account. **Protect
workspace and restart** first checks the current unlocked application and the
native startup metadata. Existing vaults, shared workspaces and empty-workspace
creation cannot enter this route. Protected local vaults use the separate
[root-factor replacement](vault-root-rotation.md) route through the same
no-argument settings bridge; their original native owner is retained through
session quiescence and fresh current-factor verification.

A main-owned authorization hold blocks ordinary workspace operations while the
application checks pending file edits and confirms closing active sessions, then
flushes browser storage, tears down renderers and stops native services.
Only confirmed shutdown permits the dedicated sandboxed setup window to open.
The existing app-lock verifier is read from its native protected store; mutable
settings cannot turn a present PIN/password into an unauthenticated migration.
The user proves an available existing method and chooses a new Wormhole password.

The setup window shows the HPKE-delivered recovery code once. The user confirms
two randomly selected groups before Go saves an encrypted preparation capsule.
Preparation leaves the original database intact and never activates an ordinary
vault owner. The ordinary application renderer receives no factor, recovery code, private
key, source path or resolver plan. The protected document clears inputs and code
on completion, cancellation, navigation and disposal. Unsupported capture
protection is stated in that document.

After setup closes, the application confirms native exit and restarts. Cancelling
before confirmation also restarts, because the original native services have
already stopped; it leaves the legacy workspace intact. Interrupted confirmation
may have durably saved preparation, so the next launch checks native metadata
rather than assuming cancellation removed a confirmed capsule. If shutdown is
uncertain, the application exits with a generic error and does not automatically
relaunch or release its authorization hold.

## Isolated continuation

Before Chromium is ready, main freezes the original native paths and obtains the
single-instance lock for the original profile. A read-only Go startup probe opens
no SQLite database or legacy migration. Pending preparation selects a distinct
temporary Chromium user-data/session-data directory; Go retains the original
fixed paths. A failed probe cannot authorize legacy access or migration.

The startup screen offers continuation through a separate protected prompt. A
fresh new password or recovery factor is required. Only the main-owned migration
launch mode can assert that Chromium is isolated; renderer wire fields cannot.
Go owns source/stage exclusion, pinned resolver decisions, encrypted domain
copying, authenticated cleanup journals, source retirement, final checkpoint
verification and no-replace publication. Publication adopts the canonical source,
unlocked owner and native workspace lease together. Staged content remains
inaccessible through ordinary unlock. Interrupted retirement or publication is
resumed from authenticated durable state; an uncertain cleanup retains exclusion.

## Current limits

The flow refuses unsupported source state instead of silently dropping it. In
particular, [Fortinet IPsec](vault-ipsec-flow.md) settings, protected PEM imports
and noninteractive native handoff are supported, but prompted authentication,
SAML and SSL fallback still need their sealed authorization flows. Those runtime
paths remain closed. Some registered Bitwarden storage roots also still require
migration support. Browser archives do not by
themselves establish usable native VPN SSO restoration, account/origin/route
binding or certificate policy. These remain roadmap work.

This path does not implement unprotected enrollment, slot-management/rotation
screens, shared administration, encrypted SQLite VFS, hardware unlock or later
security profiles. Hardened and Paranoid stay unavailable until their native
prerequisites exist.

## Verification boundary

Regression tests cover native method hints and corrupt verifiers, byte ownership,
malformed metadata, concurrent/late requests, foreign frames, loss of parent,
confirmation retries, cancellation, OS lock and unconfirmed shutdown. Actual
sandboxed Electron windows exercise recovery display and preparation with Go on
synthetic workspaces; source bytes remain identical at preparation and no capsule
is published by cancellation before confirmation. Existing isolated-boot tests
exercise fresh native continuation and original-profile single-instance fencing.

Native runtime checks here are on Windows x64. Windows ARM64 compilation is
checked, but real ARM64 hardware, macOS/Linux native sessions and provider login
interoperability are not established by these tests. No user's existing workspace
was migrated during development.

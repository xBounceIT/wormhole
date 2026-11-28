# Local OS-only custody

Under the Default machine policy, a user creating a local workspace can choose
**Skip for now (Unprotected)**. On the next launch, **Open workspace** asks the
Go backend to reopen the existing vault with its OS-protected factor. The native
owner authenticates the v3 slot document and the stored policy before the app
opens the workspace. This flow requires exactly one OS-only slot and excludes
ASK, whole-file encryption and shared workspaces.

The native cryptographic primitive wraps the root under a random 32-byte platform
factor. It uses the existing unlock derivation and authenticated envelope; the
slot kind, vault identity, slot identity and key version are bound to the packet.
Recovery/password slots cannot be retagged as OS-only custody. The primitive
borrows its inputs and wipes its temporary derived key.

The native storage primitive protects the factor with the existing Windows
CurrentUser DPAPI or Keychain/Secret Service adapter. Only a bounded ciphertext
file is written. The caller must hold workspace ownership, use a clean absolute
database path and canonical vault/slot IDs, and publish a slot only after storage
has completed. An exclusive file reservation precedes any OS key-store write;
another creator cannot overwrite its custody. Missing, malformed or unavailable
storage never causes automatic key generation on the read path.

File access uses a native directory root, regular-file checks, a 4096-byte bound
and original-file identity checks across OS operations. Failed creation removes
only its own reservation. Cancellation suppresses returned material. Native
plaintext/ciphertext buffers are wiped, and errors contain no platform diagnostics
or key material. The macOS backend accesses the Keychain through Security.framework.

The machine policy must remain Default throughout the operation. Local policy
also rejects OS-only slots when Standard or higher applies, when an ASK is
required, or when a protected slot coexists with OS-only custody. A mixed set must
never be presented as protected merely because it contains a password slot.

Anyone using the unlocked OS account can open an **Unprotected** workspace.
The app displays a persistent warning with a **Protect now** action. Users can
also start protection from the startup screen before opening the workspace.

The [native root-rotation engine](vault-root-rotation.md) now prepares and audits
a separately reencrypted vault, including deleted records and retained SSO. It
holds source ownership throughout preparation and supports a source-recovery
envelope protected by the new factors. A native journal controller publishes
protected-to-protected rotations and resumes interrupted file replacement. Its
v2 journal also inventories an OS-only source's exact ciphertext and records
durable intent, platform-key retirement and factor-file retirement before new
slot publication. Protected v1 journals remain supported. The OS master DPAPI key
is never deleted; Windows retires the exact factor file. Keychain/Secret Service
deletion must acknowledge not-found, distinct from a locked or unavailable store.

The native isolated upgrade now confirms new password/recovery factors before
opening the old OS source. Its purpose-limited scope checks the stored policy
against the protected target and returns only a rotation stage, never an ordinary
source owner. Ordinary Open retains its original source-policy checks. Partial
allocations remain attached to the scope until cleanup is acknowledged.

**Protect now** quiesces active sessions and restarts Wormhole in isolated
maintenance mode. A protected window asks for a new password and confirmation
of two groups from the generated recovery code. Go prepares the rotated
database, re-encrypts secrets, reseals metadata and compacts the target. On
restart, the new factor authorizes publication and retirement of the old OS
slot. If publication is interrupted, the next launch resumes from the journal.
Users of an already password-protected vault can rotate their factors from
**Settings > Security**.

Tests cover independent slot/context substitutions, reserved shapes, bounds,
missing/corrupt files, borrowed-buffer wiping, cancellation, file replacements,
exclusive concurrent creation and mixed-slot/policy refusal. The desktop-client
test creates a vault, stops its backend and reopens the same workspace in a new
process, upgrades it with a password and reopens it with its recovery code.
CI runs it against Windows DPAPI, a private Linux Secret Service collection
and a temporary macOS Keychain. The Windows Electron rotation test
also exercises **Protect now** through confirmation, restart and retirement.

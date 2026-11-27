# Local OS-only custody

The Unprotected application flow is not enabled yet. The v3 native slot reader
can authenticate an exact single OS-only source for forward root rotation;
older containers, mixed sets, ASK and encrypted OS-only containers are refused.
The ordinary factor-unlock API still rejects this slot, and no OS-only
create/unlock/startup operation invokes the native custody primitives. Existing
password/recovery vaults keep their flow; an interrupted root transition resumes
through a protected startup prompt.

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
or key material. Sensitive Keychain writes use stdin rather than process arguments.

The machine policy must remain Default throughout the operation. Local policy
also rejects OS-only slots when Standard or higher applies, when an ASK is
required, or when a protected slot coexists with OS-only custody. A mixed set must
never be presented as protected merely because it contains a password slot.

OS-only custody is **Unprotected**. It offers no Wormhole password or user-presence
boundary against someone using the OS account. It must eventually display the
persistent warning and Protect now action specified in issue #495. It is not a
Windows Hello or Touch ID slot and cannot satisfy their requirements.

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

Remaining activation work includes the typed application bridge/window for that
upgrade, OS-only native creation/startup/unlock, authenticated state for the
persistent indicator, and Protect now. Protected
existing vaults can already enroll replacement factors through
Settings > Security; that path still refuses OS-only source slots.
Protect now must generate a new root, re-encrypt every secret, reseal metadata,
confirm a new recovery key and retire the old OS slot through a resumable journal.
It must finish secure deletion/compaction before claiming the transition complete.
The current primitives and staging engine do not complete or bypass that transition.

Tests cover independent slot/context substitutions, reserved shapes, bounds,
missing/corrupt files, borrowed-buffer wiping, cancellation, file replacements,
exclusive concurrent creation, mixed-slot/policy refusal and real Windows DPAPI.
Portable provider fixtures exercise file custody with AES-GCM, and cross builds
check compilation. They do not establish macOS/Linux runtime key-store behavior
or a complete application workflow.

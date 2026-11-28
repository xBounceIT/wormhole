# Native shared admission controller

The Default and Standard shared-workspace startup paths use
`sharedAdmissionController` to connect the authenticated device trust store,
the unlocked account keys and a PostgreSQL session. The controller checks the
signed policy and account state before the application uses the catalog or
requests a secret. Administration and key rotation also require the corresponding
authority on the active session.

The caller constructs an owner, calls `Open` once and retains it until `Close`
confirms cleanup. It supplies an authenticated device binding, an absolute
device-local trust path, a minimum revision, authenticated transport metadata,
expected admission identities, security floors, and borrowed 32-byte root and
derived login-material buffers.
The controller copies the root into `securemem.Buffer`; it does not retain the
login buffer. It retains a SHA-256 commitment for the subsequent
[native account unlock](vault-shared-account-unlock.md), and clears it on close.
The caller remains responsible for wiping its own borrowed buffers.

Admission performs these steps under a cancellation-aware operation gate:

1. Validate metadata and load/authenticate the encrypted trust state.
2. Verify the cached profile and prepare transport settings before sending a
   login proof. Unsupported runtime profiles fail before connecting.
3. Encode the derived login material for transport, open the owned connections,
   and call `AuthenticateSession` with that same material. Challenge, credential
   proof and audited admission run in one short pinned transaction. Its independent
   session capability remains in native protected memory; login material is borrowed
   only for this call and the encoded transport copy is wiped afterward.
4. Verify the returned profile using the existing pin and advance its sequence.
5. Persist a newer state with compare-and-swap, or durably confirm unchanged
   state. This detects a competing state update too. Uncertain durability gets
   one bounded recovery attempt through exact-state confirmation.
6. Recheck the new profile against the established transport and runtime support,
   then publish successful admission only if the context and session remain live.

A verified newer profile is persisted even if its stronger requirements cannot
currently be met. The next login therefore cannot silently accept an older
profile. The established transport floor is not relaxed during an admission.
Default and Standard admission are supported by this controller. Hardened and
Paranoid remain rejected until their full runtime requirements are implemented;
passing transport validation alone does not establish those profiles' compliance.

The overall admission context is bounded to 60 seconds and is linked to owner
invalidation. Closing first withdraws admission and cancels startup/queued work,
then serializes cleanup. If account keys were unlocked, their native buffer is
retired first; root retirement also occurs before waiting for PostgreSQL
cleanup. The native buffer and session remain owned if their release is uncertain,
and `Close` must be retried. A gate/cleanup deadline is not proof that resources
have stopped; the application must preserve the owner until cleanup is confirmed.
`Session.Done` immediately makes the controller report unadmitted and triggers
root retirement and connection cleanup. No implicit reconnect occurs.
`MemoryLockWarning` reports whether any native allocation for the trust root,
session capability or unlocked account keys could not lock its pages. The shared
sign-in screen displays a protected-memory warning when admission reports this
condition under Default or Standard.

Tests combine real encrypted files and secure-memory buffers with an injected
session boundary to exercise ordering, stronger policy persistence, invalid
inputs, pre-login rejection, partial failure, cancellation, invalidation, concurrent
state changes, uncertain writes and cleanup retries. Electron integration tests
also exercise admission against a local PostgreSQL server using TLS and SCRAM.
Managed-provider interoperability still requires native verification.

## Rotation after account suspension

Confirming a suspension records the account ID and suspension revision in the
administering device's encrypted trust store. While that device is signed in,
the backend reads the captured group memberships and boundary keys. Each change
requires the current permissions, verified TLS and a review bound to the exact
suspension. The worker starts after startup has persisted the trust anchor.

For a certified group, the first transaction replaces the group key and queues
the affected boundary keys. Each successful step rereads the inventory and
continues the same job. If it cannot advance the group, it gives other entries
a turn. The job ID derives from the workspace, suspended account, suspension
revision and group, so the device can recognize its own work after restart.

An Electron integration test holds the boundary manifest locked until the first
process exits. A second process finishes the job. PostgreSQL checks the retired
group key, both retired boundary keys and the copies for the surviving recipient.

### Handoff to another custodian

On schema 90, an administrator who holds the organisation signing key on a
TLS-required workspace can authorize another custodian to continue the rotation.
Confirming **Disable account** signs the workspace ID and epoch, the actor and
target accounts, the resulting suspension revision and the organisation key ID
and version. PostgreSQL verifies the signature and records it in the suspension
transaction. A failed verification rolls back the suspension and its audit entry.

After sign-in, other administrators on verified TLS read pending receipts one
page at a time. The device checks each signature against its pinned organisation
key and the epoch from its admission. Publication checks the live inventory and
the acting custodian's authority for the individual keys. Remote receipts stay
in memory for that admission. Re-enabling the account ends its rotation and
restoring an archive advances the workspace epoch.

Before signing a replacement group key, the worker checks the membership
committed by the previous signed manifest. Removal drops only the suspended
account. Reconciliation preserves the identities of the remaining recipients,
whose current keys must also pass enrollment verification. Schema 90 retains
the membership used to issue each group key. For an older group, the client
can use a reconstructed list if it matches the signed digest.

Older deployments and administrators who do not hold the organisation signing
key keep the local queue. When there is no verifiable prior roster, a custodian
can review the group explicitly in the protected inventory.

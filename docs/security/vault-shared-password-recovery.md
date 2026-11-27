# Native shared-password recovery

`sharedAdmissionController.RecoverPasswordChange` reconciles a pending password
change without submitting another mutation. It is a native backend operation on a
fresh controller, not a running-app password-entry or enrollment workflow. The
caller supplies authenticated enrollment settings/binding, a native-derived
master, the new journal root and, for old-password recovery, the old root. Inputs
are borrowed and must be wiped by their owning native flow after return.

`RecoverAccount` accepts the native
[AccountMaster owner](vault-shared-account-password.md), so its preset/ASK facts
come directly from derivation. Cached KDF/ASK policy is checked before opening the
connection, and the signed policy returned by fresh admission is checked again.

The caller explicitly selects the old or new credential. There is no automatic
fallback on login failure: authentication, network, busy-state and malformed-data
errors cannot establish noncommit. The pending journal remains available on those
failures. Its independently bound new-root encryption supplies the existing
organisation pin, signed policy and previously observed floors; it never supplies
an unauthenticated endpoint or replacement trust anchor.

Recovery first prepares transport from the authenticated cached policy and the
strictest workspace/OS/user floor. It opens a fresh session and completes the
audited credential proof on the **same enrolled device**. The existing PostgreSQL
locks prevent this proof from overtaking an operation already authorized with the
old capability; after the proof, the superseded capability cannot submit a delayed
password mutation. A real PostgreSQL regression verifies both sides of this
ordering. Successful SCRAM login alone is insufficient.

Before interpreting account material, recovery verifies and durably retains the
new signed profile, then reapplies transport/runtime and native KDF/ASK policy.
It retrieves signed account state separately and stores it before denying a
revoked account. The combined certificate/capsule response is checked again so a
revocation between reads also survives. Unsupported stronger profiles remain
recorded rather than allowing a later replay of the older policy.

The capsule must open against the independently pinned organisation, current
signed key selection, certificate floors and the selected master. New-password
recovery additionally requires a wrapping revision at least as high as the
prepared successor. Old-password recovery requires the exact original wrapping
revision and refuses to discard any higher verified floor. Temporary private
keys are immediately wiped; they are never published to an application owner.
Only cryptographically opened material can advance the observed wrapping floor.

The encrypted journal has an optional `observed` trust snapshot. Absence preserves
the original format-1 encoding. Observations can advance policy/account/floors
while immutable preparation fields, pins and identity remain fixed. Each persisted
update uses an exact journal comparison under the same exclusive file lock; an
uncertain replacement can be confirmed by rewriting the exact intended result.
Observations remain persistable even when the destination file is damaged or was
partially finalized, so a verified revocation is not forgotten.

After proving the outcome, promotion merges all observations under the new root.
Noncommit finalization authenticates the old root and persists observations under
that root before removing the journal. The simple pre-dispatch abort refuses an
observation-bearing journal. Both finalizers accept only the original ciphertext
or an authenticated intermediate destination bounded by the immutable original
state and current journal target. Thus a later observation can still be finalized
after an earlier destination replacement was interrupted. They refuse foreign
pins, states ahead of the journal and a committed state presented as an abort.

The result reports the proven remote outcome and target revision. It remains
available alongside local durability or cleanup errors; callers must not treat
that combination as a clean local completion. Recovery retires the controller on
every started attempt and never publishes `Admitted`/`Unlocked`. Callers reconnect
normally only after local completion, and retry `Close` if cleanup is uncertain.
No SQL mutation or credential fallback is retried by this operation.

Tests use real encrypted files, native crypto and an injected typed session for
committed/noncommitted recovery, missing/forged/revoked material, stronger policy,
wrong credential mode/root, observation durability, interrupted finalization and
concurrent Close. The underlying transport's same-device proof ordering is covered
separately on PostgreSQL. A complete app restart/password-entry/enrollment test,
continuous change monitoring and full Hardened/Paranoid runtime remain pending.

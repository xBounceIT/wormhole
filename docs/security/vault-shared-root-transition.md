# Shared password-root transition

The native trust-file layer can now stage and recover a local password-derived
root replacement. This is a persistence primitive, not an application password
change workflow. The native controller now coordinates it with the PostgreSQL
mutation through `ChangePassword`; native
[outcome reconciliation](vault-shared-password-recovery.md) is also available.
The application password-entry and enrollment workflow remain to be implemented.

`PrepareTrustRootTransition` authenticates the exact current format-3 trust file
under the old root and independently supplied enrollment binding. It requires an
active signed account, an exact local revision and an incrementable wrapping
revision. The prepared record includes the previous trusted state, SHA-256 of the
exact previous ciphertext, a random operation ID, and the predicted next state.
In that predicted snapshot, only the wrapping floor and local revision advance by
one. A separate optional `observed` snapshot retains newer authenticated policy,
account state and verified wrapping floors during reconciliation. Organisation pins,
policy, account state and key references cannot change through this operation.

The record is sealed under the new root with a separate AEAD table/field domain.
It contains no master, root, login material or private account keys. Recovery
needs only the new root and the independently enrolled binding. Canonical JSON,
strict identity binding and an 8 MiB envelope limit apply; ordinary trust files
and transition records cannot be interchanged. This changes root material under
the same enrollment key reference; general key-reference rotation is separate.

`stageSharedTrustRootTransition` writes the fixed `.password-change` sibling using
the existing private atomic writer and the same exclusive lock as ordinary trust
updates. A pending entry prevents replacement by another transition and freezes
ordinary writes/confirmations. An uncertain staging write must be confirmed by
authenticating the exact expected journal, checking the previous ciphertext hash,
and durably rewriting the journal **before** any remote mutation is submitted.

After independently proving a remote commit, the caller can promote the predicted
state under the new root. Promotion requires the exact prepared record and either
the original ciphertext or an authenticated intermediate promoted state bounded
by the original and current target. The target includes every retained observation.
It durably replaces the destination before deleting the journal and
syncing the directory. Retrying local promotion confirms durability and never
repeats a PostgreSQL mutation. A lost deletion-sync confirmation is recoverable
even if the journal has already disappeared, provided the destination is exactly
the expected successor.

Before SQL dispatch, or after independently proving noncommit, abort removes the
journal only while the old ciphertext is unchanged and no observations would be
lost. Observation-bearing rollback authenticates the old root and durably writes
the observed state under it before deleting the journal. A deletion-sync failure can
be confirmed with the same exact source check. Abort cannot erase recovery state
after local promotion. These privileged native helpers do not themselves establish
remote commit/noncommit: a prepared journal is never evidence of a SQL outcome.

Tests use real encrypted files and inject directory-sync failures during staging,
destination replacement and journal cleanup. They cover recovery with the new
root, wrong roots/bindings, cross-domain replay, malformed authenticated records,
legacy/revoked/exhausted states, stale revisions, lock contention, ordinary-writer
blocking, duplicate staging, changed/missing source files and promotion/abort
retries. Native remote reconciliation is documented separately; the full application
flow and enrollment lifecycle remain separate work. These files do not provide a hardware
monotonic counter or detect restoration of all old trusted state together.

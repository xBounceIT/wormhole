# Adversarial ledger — Backup export/import Fake glue (`wormhole-import`)

**Scope:**
- `rust/crates/wormhole-import/src/backup_glue.rs` (+ `backup_payload.rs`, `backup_crypto.rs`, crate re-exports)
- Composes `FakeBackupLab` + `wormhole-secrets-win::{FakePasswordStore, FakeKeyMaterialStore, FakeTunnelPayloadStore}` + optional `StorageBackupSource` / `StorageBackupSink`
- Docs: `12-import.md` (backup round-trip section), `feature-matrix.md` (Backup row), `README.md` index
- this ledger

**Out of scope:** C# backup dialogs / GPUI; Bitwarden cache repository (export empty / import no-op); `ScrubDanglingReferences` / virtual Bitwarden id merge; transactional import across metadata + secrets; live user AppData zip; WebView2 / extension packages.

**Compared against:** C# `BackupService` metadata + secret merge-skip semantics  
**Authority:** full adversarial-review-fix (edit in scope)  
**Gates:** 2 clean adversarial cycles + 3 clean iterative-review-simplify cycles

## Baseline

- Before review: backup envelope inspect only (`backup.rs`); feature-matrix Backup row **Spike**
- Attack focus: temp/Fake FS only; fail-closed truncated/corrupt JSON + AES-GCM; never log password/key bodies; Bitwarden passwords excluded from export; merge-skip by id/name; conditional secret restore (inserted row or missing secret only); atomic temp write

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| Bk-001 | P1 | `legacy_payload_to_rows` | Malformed array elements silently dropped via `unwrap_or_default` | Hostile hand-edited JSON | **Fixed** — per-element deserialize → `InvalidData` + regression |
| Bk-002 | P2 | `import_backup` | `FakeBackupLab` could not be sink + secrets simultaneously (`&mut` + `&`) | Test compile failure | **Fixed** — `BackupMetadataSink` uses `&self` (Mutex interiors) |
| Bk-003 | P2 | `StorageBackupSink::insert_node` | `ConnectionRepository::insert` expects `&ConnectionNode` | E0308 | **Fixed** — pass `&node` |
| Bk-004 | P2 | `backup_crypto` | PBKDF2 `Sha256` digest version mismatch with `pbkdf2` crate | Build failure | **Fixed** — pin `sha2 =0.10.9` for `pbkdf2_hmac::<Sha256>` |
| Bk-005 | P2 | `backup_crypto` | Lab PRNG for salt/nonce | Weak entropy | **Fixed** — `getrandom::fill` |
| Bk-006 | P2 | `export_backup` | Plaintext export legitimately contains `passwords[]` bodies | False-positive “no password in JSON” test | **Fixed** — test targets `inspect_backup_json` slim envelope instead |
| Bk-007 | P2 | `BackupMetadataSink` | Pre-existing credential `SecretProvider` not seeded for Bitwarden skip on merge | Partial-import edge | **Rejected** — lab targets empty sink / full round-trip; documented |
| Bk-008 | P2 | import | No `ScrubDanglingReferences` | C# parity gap | **Rejected** — explicit out of scope; nodes import with refs as-is |
| Bk-009 | P2 | docs | Ledger + README + feature-matrix + `12-import` section | Policy | **Fixed** — this ledger + doc updates |

## Fixes applied

- `backup_glue.rs` — `FakeBackupLab`, traits, export/import, merge-skip, topological parent ordering, regressions
- `backup_payload.rs` — typed camelCase rows + domain/storage conversions
- `backup_crypto.rs` — PBKDF2-SHA256 (600k) + AES-GCM 12-byte nonce seal/unseal
- `lib.rs` / `Cargo.toml` — `secrets` feature, re-exports
- `docs/migration/12-import.md` — backup round-trip behaviour + verification
- `docs/migration/feature-matrix.md` — Backup row → Lab
- `docs/migration/README.md` — index row
- `docs/migration/adversarial-ledger-backup.md` — this ledger

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 | Contract → boundary → security (secrets/logging) → corrupt/truncated archive | Bk-001…006 | Fixed; reset |
| Adv-1 | Reverse: tests-as-oracles → Bitwarden skip → wrong password → SQLite round-trip | None (Bk-007…008 rejected) | Clean (1/2) |
| Adv-2 | Forward: encrypted path, inline passwords, duplicate skip, iteration cap | None | Clean (2/2) |

### Iterative-review-simplify

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Reuse secrets Fakes + storage repos | Single glue module behind `secrets` feature | Fail-closed legacy decode; sink `&self` | **Fixed** → reset adv |
| Sim-2 | Shared payload types; crypto split | No duplicate inspect path | Unused imports trimmed | None | Clean (1/3) |
| Sim-3 | Trait boundaries for Fake vs SQLite | Atomic temp write | Malformed array test | None | Clean (2/3) |
| Sim-4 | No GPUI / no live AppData | Ledger + verification commands | None | None | Clean (3/3) |

Post-simplify adversarial re-run (Adv-1/Adv-2 after Sim-1): no new accepted findings.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-import
```

**Result (final):** `wormhole-import` **72** lib + **1** integration + **5** backup_glue-related integration = **78** total passed; 0 failed.

```powershell
git diff --check -- rust/crates/wormhole-import docs/migration/adversarial-ledger-backup.md docs/migration/12-import.md docs/migration/README.md docs/migration/feature-matrix.md
```

**Diff hygiene:** clean (no whitespace errors on scoped paths).

## Gate confirmation

- Adversarial clean passes: **2** (Adv-1 / Adv-2).
- Iterative-review-simplify clean passes: **3** (Sim-2…4 after Sim-1 fix + post-adv re-run).
- No accepted non-blocked findings remain.
- No live user AppData / GPUI / password bodies in logs.

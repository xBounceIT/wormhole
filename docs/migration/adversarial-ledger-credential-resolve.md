# Adversarial ledger — Credential password resolution (`wormhole-secrets-win`)

**Scope:**
- `rust/crates/wormhole-secrets-win/src/credential_password_resolver.rs`
- Crate-root re-exports in `lib.rs` / `Cargo.toml` description
- Docs: `04-secrets.md`, `feature-matrix.md`, `README.md` index
- this ledger

**Out of scope:** C# `SshCredentialResolver` full connect path (inline / transient / SSH-key /
prompt fallback); live `bw` CLI / `BitwardenCliVaultClient`; unlock prompt delegate;
`wormhole-ui` / session orchestrator DI; GPUI.

**Compared against:** C# `CredentialPasswordResolver` + `SshCredentialResolver` password branch  
**Authority:** full adversarial-review-fix (edit in scope)  
**Gates:** 2 clean adversarial cycles + 3 clean iterative-review-simplify cycles

## Baseline

- Before review: CredMgr Fake + Bitwarden catalog/session stubs only; no password resolve glue
- Attack focus: local vs Bitwarden routing; locked vault fail-closed; empty / whitespace
  password fail-closed; virtual id compose via catalog; no secrets in Debug/errors; no live `bw`;
  unsupported field path; SSH-key kind rejection

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| CR-001 | P1 | (missing module) | No lab resolver for local CredMgr vs Bitwarden item id | Task + C# `CredentialPasswordResolver` | **Fixed** — `CredentialPasswordResolverGlue` |
| CR-002 | P1 | Bitwarden path | Locked session must fail closed (no silent unlock) | Task + C# locked vault exception | **Fixed** — `VaultLocked` before vault read |
| CR-003 | P1 | all paths | Empty / whitespace password must fail closed | Task | **Fixed** — `ensure_non_empty_password` (trim-aware) |
| CR-004 | P2 | Bitwarden path | Vault disabled must not read Fake vault | C# `EnableBitwardenVault` guard | **Fixed** — `VaultDisabled` |
| CR-005 | P2 | Bitwarden path | Missing / blank `bitwarden_item_id` | C# null/whitespace guard | **Fixed** — `MissingBitwardenItemId` |
| CR-006 | P2 | Bitwarden path | Missing vault item / blank login.password | C# not-found / empty throws | **Fixed** — `BitwardenItemNotFound` / `EmptyPassword` |
| CR-007 | P2 | v1 field path | Only `login.password` supported | C# default path | **Fixed** — `UnsupportedFieldPath` |
| CR-008 | P2 | kind gate | SSH-key profiles must not return passphrase as login password | C# uses separate key path | **Fixed** — `NotPasswordCredential` |
| CR-009 | P2 | virtual ids | Compose catalog `get_by_id` + resolver | Task | **Fixed** — `read_password_by_id` + test |
| CR-010 | P2 | Debug / errors | Must not echo password material | Task + crate redaction policy | **Fixed** — length-only Debug + error scan tests |
| CR-011 | P2 | `Send + Sync` | Trait object safety on `CredentialPasswordResolver` | `cargo build` E0277 | **Fixed** — bounds on glue impls |
| CR-012 | P3 | docs | Ledger + README + feature-matrix + `04` section | Policy | **Fixed** — this ledger + doc updates |
| CR-R1 | — | Unlock prompt callback | C# `BitwardenUnlockPrompt` not in lab API | Task = Fake session only | **Rejected** — session must pre-unlock |
| CR-R2 | — | `bw sync` retry on missing item | C# `GetItemWithRetryAsync` + `SyncAsync` | No live `bw` in lab | **Rejected** — documented gap |
| CR-R3 | — | Whitespace-only transient passwords | C# `ThrowIfNullOrEmpty` accepts `" "` | Resolver fail-closed per task (stricter) | **Rejected** — intentional lab guard |
| CR-R4 | — | `wormhole-ui` home | Task allowed UI crate | Resolver belongs with secrets Fakes | **Rejected** — correct crate |
| CR-R5 | — | Merge into catalog module | Single file possible | Separation of metadata vs secret bodies | **Rejected** |

## Fixes applied

- `credential_password_resolver.rs` — glue + `FakeBitwardenVaultPasswords` + 10 unit tests
- `lib.rs` / `Cargo.toml` — module, re-exports, description
- `docs/migration/04-secrets.md` — resolution section + API table row + test blurb
- `docs/migration/feature-matrix.md` — password resolution row → Lab
- `docs/migration/README.md` — index row
- `docs/migration/adversarial-ledger-credential-resolve.md` — this ledger

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 | Contract → C# parity → lock/empty gates → Debug redaction → catalog compose | CR-001…012 | Fixed; reset |
| Adv-1 | Reverse: tests-as-oracles → virtual id path → error taxonomy → trait bounds | None (CR-R1…R5 rejected) | Clean (1/2) |
| Adv-2 | Security: secret logging scan → locked+linked → disabled vault → field path | None | Clean (2/2) |

### Iterative-review-simplify

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Reuse `BitwardenCatalogProfile`, `FakePasswordStore`, session status | Single `ensure_non_empty_password`; no duplicate catalog merge | Unused `SecretsError` import | **Fixed** | Reset |
| Sim-2 | `enabled_resolver` / `unlocked_session` test helpers | No extra trait objects beyond injectable sources | Locked virtual id → catalog `NotFound` before vault (documented) | None | Clean (1/3) |
| Sim-3 | No further extraction | Ledger + verification | Test assert avoids `wormhole-secrets-win` false positive on `"secret"` substring | **Fixed** | Reset |
| Sim-4 | Stable surface | No GPUI / `bw` churn | None | None | Clean (2/3) |
| Sim-5 | Same | Diff hygiene | None | None | Clean (3/3) |

Post-simplify adversarial re-run (Adv-1/Adv-2): no new accepted findings.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-secrets-win --lib credential_password
cargo test -p wormhole-secrets-win
```

**Result (final):** `credential_password` filter **10** passed; full crate **205** passed; 0 failed.

```powershell
git diff --check -- rust/crates/wormhole-secrets-win/src/credential_password_resolver.rs rust/crates/wormhole-secrets-win/src/lib.rs docs/migration/adversarial-ledger-credential-resolve.md docs/migration/04-secrets.md docs/migration/README.md docs/migration/feature-matrix.md
```

**Diff hygiene:** clean (no whitespace errors on scoped paths).

## Gate confirmation

- Adversarial clean passes: **2** (Adv-1 / Adv-2).
- Iterative-review-simplify clean passes: **3** (Sim-3…Sim-5 after post-Sim-1 fixes).
- No accepted non-blocked findings remain.
- No live `bw` CLI / GPUI / SQLite password bodies.

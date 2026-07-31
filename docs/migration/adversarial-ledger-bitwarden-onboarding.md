# Adversarial ledger — Bitwarden onboarding notice versioning (`wormhole-ui`)

**Scope:**
- `rust/crates/wormhole-ui/src/bitwarden_onboarding_notice.rs` (+ crate-root re-exports in `lib.rs` / `Cargo.toml` description)
- Settings fields on `AppSettings` (`bitwarden_onboarding_notice_*`, schema v6 migration in `settings/model.rs`)
- Docs: `17-tree-settings-vm.md`, `04-secrets.md` (cross-ref), `feature-matrix.md`, `README.md` index
- this ledger

**Out of scope:** C# `IDialogService` / GPUI dialog chrome; live `bw` CLI (`wormhole-secrets-win::bitwarden_session`);
Bitwarden browser WebView2 / extension update services; credential password resolution.

**Compared against:** C# `BitwardenOnboardingNoticeService` + `BitwardenOnboardingNoticeServiceTests`
**Authority:** full adversarial-review-fix (edit in scope)
**Gates:** 2 clean adversarial cycles + 3 clean iterative-review-simplify cycles

## Baseline

- Before review: `cargo test -p wormhole-ui --lib bitwarden_onboarding` — **9** passed
- Attack focus: 0.7.x-only gate; seen/pending version math; schema `< 6` → pending=1; dialog fail → no save;
  save fail after dialog → no persist; cancellation; negative versions; Fake Debug length-only; Arc UI harness

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| BO-001 | P2 | tests | `glue.ui` private field — tests would not compile | Child module cannot access private `ui` | **Fixed** — `with_fake_ui` + `Arc<FakeBitwardenOnboardingNoticeUi>` |
| BO-002 | P2 | `FakeUiState` | `#[derive(Default)]` on struct with non-Default inner state | `cargo build` E0277 | **Fixed** — manual `Default` impl |
| BO-003 | P2 | version gate | `0.6.x` / `major != 0` unpinned | Boundary lane vs C# `Minor == 7` | **Fixed** — `does_not_show_on_version_06` / `does_not_show_when_major_nonzero` |
| BO-004 | P2 | persistence | Save failure after successful dialog unpinned | State atomicity lane | **Fixed** — `save_failure_after_dialog_does_not_persist_seen` |
| BO-005 | P2 | migration | Schema `< 6` pending=1 not tied to glue | C# `AppSettingsService` + Rust `migrate_from_schema` | **Fixed** — `migrate_from_schema_before_v6_sets_pending_notice` |
| BO-006 | P2 | pending `>=` | `pending = 2` still shows on 0.7 unpinned | C# uses `>= CurrentBitwardenOnboardingNoticeVersion` | **Fixed** — `pending_above_current_notice_version_still_shows_on_07` |
| BO-007 | P2 | docs | Ledger + README + feature-matrix + `17` section missing | Policy requires closed ledger | **Fixed** — this ledger + doc updates |
| BO-R1 | — | async / `CancellationToken` | C# async dialog; Rust sync `cancelled: bool` | Lab Fake glue; bool checked before load/UI/save | **Rejected** — intentional lab surface |
| BO-R2 | — | In-memory seen on save throw | C# catches `Save()` exception after setting `Current` fields | Rust propagates `SettingsError` (fail-closed on disk) | **Rejected** — stricter than C#; test documents disk unchanged |
| BO-R3 | — | `wormhole-secrets-win` home | Task preferred UI or secrets crate | Settings UX + `SettingsStore` — belongs in `wormhole-ui` | **Rejected** — correct crate |
| BO-R4 | — | Feature-gate module | Could use `update`-style optional dep | No extra crate dep; always settings-only | **Rejected** |
| BO-R5 | — | Log warning on dialog fail | C# `ILogger.LogWarning` | Lab has no logger; `DialogFailed` outcome suffices | **Rejected** — host can log outcome |

## Fixes applied

- `bitwarden_onboarding_notice.rs` — glue + Fake UI + `with_fake_ui`; parity tests (C# matrix + boundaries)
- `lib.rs` / `Cargo.toml` — module + re-exports
- `docs/migration/17-tree-settings-vm.md` — behaviour + API + verification
- `docs/migration/feature-matrix.md` — Creds onboarding row
- `docs/migration/04-secrets.md` — cross-ref in public API table
- `docs/migration/README.md` — index row
- `docs/migration/adversarial-ledger-bitwarden-onboarding.md` — this ledger

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 | Contract → boundary → state → concurrency → security → integration → perf → tests | BO-001…007 | Fixed; reset |
| Adv-1 | Reverse: tests-as-oracles → version gates → save atomicity → migration | None (BO-R1…R5 rejected) | Clean (1/2) |
| Adv-2 | Forward on post-fix surface (Arc harness, negative versions, Debug redaction) | None | Clean (2/2) |

### Iterative-review-simplify

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | `should_show_*` pure helper; `with_fake_ui` mirrors `UpdateNotifyGlue::with_fake` | No extra trait objects beyond `SettingsStore` | Dialog fail / cancel semantics documented | None | Clean (1/3) |
| Sim-2 | Constants for title/message; `Arc` deref impl only | Inline `FailSaveStore` in test only | No logger / GPUI churn | None | Clean (2/3) |
| Sim-3 | No further extraction | Ledger + verification | None | None | Clean (3/3) |

No simplify code edits after Sim-1 → no post-simplify adversarial re-run required.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui --lib bitwarden_onboarding
```

**Result (final):** `bitwarden_onboarding` **14** passed; 0 failed.

```powershell
git diff --check -- rust/crates/wormhole-ui/src/bitwarden_onboarding_notice.rs rust/crates/wormhole-ui/src/lib.rs docs/migration/adversarial-ledger-bitwarden-onboarding.md docs/migration/17-tree-settings-vm.md docs/migration/README.md docs/migration/feature-matrix.md docs/migration/04-secrets.md
```

**Diff hygiene:** clean (no whitespace errors on scoped paths).

## Gate confirmation

- Adversarial clean passes: **2** (Adv-1 / Adv-2).
- Iterative-review-simplify clean passes: **3**.
- No accepted non-blocked findings remain.
- No `bw` CLI / GPUI / CredMgr churn.

# Adversarial ledger — Credential picker search glue (`wormhole-ui`)

**Scope:**
- `rust/crates/wormhole-ui/src/credential_picker.rs` (+ crate-root re-exports in `lib.rs` / `Cargo.toml` description)
- Docs: `20-connection-editor.md` (credential picker section), `feature-matrix.md` (Creds picker row), `README.md` index
- this ledger

**Out of scope:** SQLite credential-catalog repository; Bitwarden virtual rows; C# `ResolveExact` / `ResolveForCommit`; GPUI combo chrome; CredMgr / DPAPI secret bodies; `tree/reparent.rs` (do not churn); storage `credential_glue` CRUD.

**Compared against:** C# `ViewModels/CredentialPickerSearch.Filter` (+ `CredentialsViewModel` load-catch last-good)
**Authority:** full adversarial-review-fix (edit in scope)
**Gates:** 2 clean adversarial cycles + 3 clean iterative-review-simplify cycles

## Baseline

- Before review edits: `cargo test -p wormhole-ui --lib credential_picker` — **13** passed
- Attack focus: empty/whitespace = all (stable order); name **or** username **or** domain; `from` source `Err`; VM replace vs last-good; Debug / no secrets; `contains("")` footgun; Fake recover; test resistance
- Preserve unrelated migration / `reparent.rs` work

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| CP-001 | P2 | `CredentialPickerSearchVm::load_from` | Last-good vs wipe undocumented; “fail-closed” wording ambiguous vs serial picker | C# `LoadAsync` catch keeps prior list; `?` leaves cache; docs said “load fail-closed” | **Fixed** — module/docs last-good + replace-not-append; regressions |
| CP-002 | P2 | Fake / tests | `set_profiles` clearing fail flag unpinned | Hosts recover Fake after `failing()` | **Fixed** — `fake_set_profiles_clears_fail_flag` |
| CP-003 | P2 | filter OR | Multi-field hit could theoretically double-emit if collector drifted | Name+username+domain all match `"alice"` | **Fixed** — `multi_field_match_returns_row_once` |
| CP-004 | P2 | docs / index | Ledger + README row + `20` adversarial link missing | Policy requires closed ledger | **Fixed** — this ledger + README + `20` + feature-matrix link |
| CP-005 | P2 | `profile_matches_query_lower` | Rust `haystack.contains("")` is **true** for every string — empty `query_lower` would match all rows | Private helper; public callers branch first, but footgun if a future caller forgets (same class as tree TF-002) | **Fixed** — empty guard + `empty_query_lower_does_not_match_via_contains_empty` |
| CP-006 | P3 | optional fields | `Some("")` username/domain vs non-empty query unpinned | Boundary lane | **Fixed** — `empty_string_optional_fields_do_not_match_nonempty_query` |
| CP-R1 | — | Port `ResolveExact` / `ResolveForCommit` | C# commit helpers | Explicit non-goal in `20-connection-editor.md` | **Rejected** — search Filter glue only |
| CP-R2 | — | Rust `to_lowercase` ≠ C# `OrdinalIgnoreCase` | Turkish İ / locale | Same as tree filter TF-009 | **Rejected** — intentional; ASCII picker names |
| CP-R3 | — | Wipe VM cache on `load_from` Err | Serial picker clears list on enumerator Err | C# credentials page keeps last-good | **Rejected** — parity with `CredentialsViewModel.LoadAsync` |
| CP-R4 | — | Debounce inside SearchVm | C# 120ms on `CredentialsViewModel` | Module docs: host owns debounce | **Rejected** |
| CP-R5 | — | Share matcher with tree `fields_match_query_lower` | Different fields (host vs username/domain) | One-off abstraction | **Rejected** |
| CP-R6 | — | Return indices / `Cow` from filter | Avoid clone | Picker-sized lists | **Rejected** — micro |
| CP-R7 | — | Redact username/domain from `CredentialProfileRow` Debug | Metadata is searchable UI data | Not CredMgr secrets | **Rejected** — Fake/VM Debug already length-only |

## Fixes applied

- `credential_picker.rs` — last-good / replace docs; empty `query_lower` guard; regressions for load Err, replace-not-append, Fake recover, multi-field once, empty optional fields, `contains("")`
- `docs/migration/20-connection-editor.md` — load semantics table + adversarial link + test wording
- `docs/migration/feature-matrix.md` — ledger link on Creds picker row
- `docs/migration/README.md` — index row
- `docs/migration/adversarial-ledger-credential-picker.md` — this ledger

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 | Contract → boundary → state → concurrency → security → integration → perf → tests | CP-001…004, CP-006 | Fixed; reset |
| Adv-1 | Reverse: tests-as-oracles → `contains("")` → Fake recover → Debug | CP-005 | Fixed; reset |
| Adv-2 | Forward on post-fix surface (guards, load last-good, exports) | None (CP-R1…R7 rejected) | Clean (1/2) |
| Adv-3 | Reverse: C# Filter parity, empty optional fields, query preserve, no secret fields | None | Clean (2/2) |

### Iterative-review-simplify

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Shared `profile_matches_query_lower`; optional helper kept; no tree-filter merge (CP-R5) | Short-circuit OR; no extra I/O | Empty guard local; last-good docs aligned | None | Clean (1/3) |
| Sim-2 | Exports match `lib.rs`; Fake `&` impl kept for ergonomics | Clone-on-filter rejected (CP-R6) | Debug contracts intact | None | Clean (2/3) |
| Sim-3 | No further helpers worth extracting | Mutex Fake only in tests | Ledger + verification commands | None | Clean (3/3) |

No simplify code edits → no post-simplify adversarial re-run required. Latest adversarial clean pair (Adv-2/Adv-3) remains valid.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui --lib credential_picker
```

**Result (final):** `credential_picker` **19** passed; 0 failed.

```powershell
git diff --check -- rust/crates/wormhole-ui/src/credential_picker.rs docs/migration/adversarial-ledger-credential-picker.md docs/migration/20-connection-editor.md docs/migration/README.md docs/migration/feature-matrix.md
```

**Diff hygiene:** clean (no whitespace errors on scoped paths).

## Gate confirmation

- Adversarial clean passes: **2** (independent orderings; post CP-005).
- Iterative-review-simplify clean passes: **3**.
- No accepted non-blocked findings remain.
- No CredMgr / DPAPI / GPUI / `reparent.rs` churn.

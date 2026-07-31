# Adversarial ledger — Update check UI notify glue

**Scope:**
- `rust/crates/wormhole-update/src/notify.rs` — `check_now`, `notify_status_from_result`,
  `UpdateNotifyStatus` / `UpdateNotifyKind`, fail-closed map over Fake / NetworkStub / channel `Err`
- `rust/crates/wormhole-ui/src/update_notify.rs` — `UpdateNotifyGlue` (stamp / skip / startup /
  dismiss / development), PAT-safe `Debug`, Fake / NetworkStub wiring
- Docs: `docs/migration/13-update-logging.md` (notify section), this ledger + `README.md`

**Out of scope:** live GitHub HTTP / installer UX / MOTW / changelog WebView / GPUI Settings chrome;
`UpdateChecker` channel already closed in [`adversarial-ledger-update-channel.md`](adversarial-ledger-update-channel.md);
version/download/SHA in [`adversarial-ledger-update-logging.md`](adversarial-ledger-update-logging.md).

**Authority:** full adversarial-review-fix (edit in scope)  
**Attack focus:** fail-closed exhausted Fake; PAT never in Debug; stamp only on success;
skip/dismiss/startup parity with C# `UpdateViewModel`; Error preserves prior availability.  
**Baseline:** `cargo test -p wormhole-update` — 52 green; `wormhole-ui` `update_notify` — 7 green  
**Final:** wormhole-update **53**; wormhole-ui `update_notify` **13**

Compared against C#: `UpdateViewModel.ApplyResult` / `CheckNowAsync` / `RunStartupCheckAsync` /
`Dismiss`; `UpdateService` stamps `LastUpdateCheck` only after a parseable GitHub answer (not on
transport failure); `LatestKnown` not clobbered on `CheckFailed`.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix + post-simplify re-run) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-update` | **pass** (53) |
| `cargo test -p wormhole-ui --features update --lib update_notify::` | **pass** (13) |
| `git diff --check` (scoped) | **pass** |

---

## Accepted findings

### UN-01 — Dismiss after Error drops skip (`P1`) — **fixed**

- **Where:** `UpdateNotifyGlue::dismiss` + `apply_status(Error)`
- **Invariant:** C# `Dismiss` uses `LatestKnown.LatestVersion` (not clobbered on `CheckFailed`).
  Error only replaces the status line; dismiss must still persist `SkippedUpdateVersion`.
- **Evidence:** Error overwrote `status_text` with `UPDATE_NOTIFY_ERROR_TEXT`; old
  `extract_version_for_skip` parsed the `"Update available: "` prefix → `None`, then cleared the
  info bar without recording a skip.
- **Fix:** Remember `last_available_version` on Available; preserve across Error; clear on None;
  dismiss clones that field into settings.
- **Regression:** `dismiss_after_error_still_records_skip`

### UN-02 — Empty Fake glue under-pinned (`P2`) — **fixed**

- **Where:** `UpdateNotifyGlue::with_fake` (empty script)
- **Invariant:** Exhausted/empty Fake → Error notify; never advertise
- **Evidence:** Channel/notify covered exhausted Fake; UI glue only covered NetworkStub + scripted paths
- **Regression:** `empty_fake_glue_fail_closed_no_advertise`

### UN-03 — Development CheckNow must not call checker / stamp (`P2`) — **fixed**

- **Where:** `UpdateNotifyGlue::check_now` early return when `is_development_build`
- **Invariant:** C# DEBUG CheckNow sets status only; no service call; no `LastUpdateCheck` stamp
- **Evidence:** Startup covered; manual CheckNow path under-tested
- **Regression:** `development_check_now_skips_checker`

### UN-04 — Hostile `check_failed` + available flag (`P2`) — **fixed**

- **Where:** `notify_status_from_result`
- **Invariant:** `check_failed` wins → Error (never advertise)
- **Regression:** `check_failed_takes_precedence_over_available_flag`

### UN-05 — `format_last_check` / sync / `set_api_token` Debug under-pinned (`P3`) — **fixed**

- **Where:** `format_last_check`, `sync_last_check_from_settings`, `set_api_token`
- **Regression:** `format_last_check_never_and_stamp`, `sync_last_check_from_settings_without_running_check`,
  `set_api_token_stays_redacted_in_debug`

### UN-06 — Available kind rustdoc overclaimed installer URL (`P3`) — **fixed**

- **Where:** `UpdateNotifyKind::Available` rustdoc
- **Evidence:** Notify Available requires a version, not an installer URL (hostile Fakes allowed)
- **Fix:** Rustdoc clarified

### UN-07 — Ledger / notify doc drift (`P3`) — **fixed**

- **Where:** missing `adversarial-ledger-update-notify.md`; `13-update-logging.md` dismiss/Error note
- **Fix:** This ledger + README row; dismiss-after-Error + stamp contracts documented

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Live GitHub HTTP / installer UX / changelog WebView — explicit non-goals |
| REJ-02 | — | `IsBusy` reentrancy guard — no GPUI chrome; host wires busy later |
| REJ-03 | — | Dismiss when info bar already hidden (skipped) — C# uses LatestKnown; Rust early-returns when bar not shown (no user action) |
| REJ-04 | — | Zeroize PAT on Drop — beyond stub surface / channel ledger REJ |
| REJ-05 | — | Share `available_result` fixture across crates — test-only duplication |
| REJ-06 | — | Remove `check_now` token-len observe — intentional non-use documentation (channel parity) |
| REJ-07 | — | Whitespace-only `release_name` fallback — display-only; empty already filtered |
| REJ-08 | — | Stamp `Some("")` now_utc — harness clock; `format_last_check` still shows Never |

---

## Adversarial cycles

| Pass | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-1 | Contract → C# ApplyResult/Dismiss → security → test resistance | UN-01…03 | Fixed; reset |
| Adv-2 | Security-first → boundaries → docs/rustdoc → test resistance | UN-04…07 | Fixed; reset |
| Adv-3 | PAT / fail-closed / Error preserve / stamp | None | Clean (1/2) |
| Adv-4 | Tests-as-oracles → startup/skip/dev → integration drift | None | Clean (2/2) |
| Adv-5 | Post-simplify delta: `last_available_version` + Debug derive | None | Clean (1/2 re-run) |
| Adv-6 | Attack checklist: exhaust Fake / PAT Debug / dismiss-after-Error / no stamp on Error | None | Clean (2/2 re-run) |

---

## Iterative-review-simplify cycles

| Cycle | Reuse | Efficiency | Quality | Disposition |
|---|---|---|---|---|
| 1 | Drop hand-rolled `UpdateNotifyUiState` Debug (derive) | `dismiss` uses `as_ref` + single clone | Removed fragile status-text skip parse | **Fixed** |
| 2 | No findings | No findings | No findings | **clean 1** |
| 3 | No findings | No findings | No findings | **clean 2** |
| 4 | No findings | No findings | No findings | **clean 3** |

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-update
cargo test -p wormhole-ui --features update --lib update_notify::
```

Expected: wormhole-update **53** passed; update_notify **13** passed. No live network.

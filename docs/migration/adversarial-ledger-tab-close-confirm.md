# Adversarial ledger — Session tab close-confirm Fake glue

**Scope:** `rust/crates/wormhole-ui/src/tab_close_confirm.rs` (new) + registration /
`pub use` in `rust/crates/wormhole-ui/src/lib.rs`.

**Out of scope:** GPUI / WinUI close-confirm chrome; tab-removal ordering; real
`ContentDialog`; session disconnect orchestration (lives in `wormhole-session`).

**Compared against:** C# `ViewModels/ShellViewModel.cs` (`CloseAllSessionsAsync`,
`CloseTabForShutdownAsync`, `ActiveSessionCount` / `WillDisconnectOnAppClose`),
`ViewModels/Sessions/SessionTabViewModel.cs`, `MainWindow.xaml.cs` close path.

**Authority:** full adversarial-review-fix (reviewer subagent; parent re-verified)  
**Baseline:** module **16** tests green  
**Final:** module **20** tests; wormhole-ui lib **443** / **17** doc / **5** integration

**Attack focus:** duplicate batch ids → phantom pending entries; zero-disconnect batch
short-circuit vs outstanding confirmations (fail-open torn-down tabs); global pending
gate on close-everything; stale member disconnect; disjoint concurrent batches;
prompt-failure / unknown-id fail-closed; Debug leakage.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-ui` | **pass** (443 lib) |
| `cargo check -p wormhole-ui` / `--no-default-features` | **pass** |
| `git diff --check` (scoped) | **pass** |

---

## Accepted findings and fixes

| ID | Sev | Finding | Fix |
|---|---|---|---|
| F1 | P2 | `request_close_all(&[a, a])` recorded two pending entries for one tab — `index_of`/`remove` saw only the first → phantom entry, wrong `confirm_all` counts | Batch ids deduped order-preserving before recording; `will_disconnect` clamped to unique count |
| F2 | P2 | Zero-disconnect shortcut checked before pending-overlap → batch containing a pending-confirmation tab returned `Closed` (fail-open) | Overlap check moved ahead of the shortcut |
| F3 | P2 | Zero-disconnect batch returns `Closed` = "close every tab"; tabs outside the batch with an outstanding confirmation got torn down under their live prompt | Global `has_pending()` gate on the `Closed` path |

## Regression tests added (4)

`batch_with_duplicate_ids_records_each_tab_once`, `batch_zero_disconnect_does_not_bypass_pending_confirmation`
(incl. unrelated-tab case), `batch_member_stale_disconnect_removes_member_only`,
`two_disjoint_batches_coexist_and_resolve_atomically`.

---

## Test command

```powershell
cd rust
cargo test -p wormhole-ui tab_close_confirm
cargo test -p wormhole-ui
```

**Counts:** tab_close_confirm **20/20**; full wormhole-ui lib **443**.
# Adversarial ledger — Update installer launch + changelog UX glue

**Scope:** `rust/crates/wormhole-update/src/installer.rs` (new), `src/changelog_vm.rs` (new), `src/lib.rs` registration/re-exports, `src/error.rs` (3 new `UpdateError` variants: `InstallerNotStaged`/`InstallerLaunchFailed`/`PrepareForInstallFailed`).

**Out of scope:** live GitHub HTTP download (stays `download.rs`/`github.rs` — closed ledger `update-channel`); real `Process::Start`; `UpdateChangelogFormatter` (HTML rendering stays C# side).

**Compared against:** C# `Services/UpdateService.cs` (download → SHA-256 verify → prepare-for-install → launch; skip-version), `ViewModels/UpdateViewModel.cs`, `Views/Controls/UpdateChangelogView.xaml(.cs)`, `App.xaml.cs` prepare-for-install Bitwarden flush ordering; Rust `shutdown_order.rs` recorder style.

**Authority:** full adversarial-review-fix (reviewer subagent; parent re-verified)  
**Baseline:** wormhole-update **76** tests  
**Final:** wormhole-update **84** tests

**Attack focus:** illegal state transitions out of failure terminals/Done, verify-before-launch bypass, prepare-sink-before-launch ordering (strict prefix validation), launcher/prepare failure fail-closed, order validation (wrong order/duplicates/extra), changelog edge cases, `file://` release-url invariant, skip-version parity, Debug token leakage.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-update` | **pass** (84) |
| `cargo check` / `cargo clippy --all-targets` | **pass** / clean in scope (2 pre-existing github.rs warnings) |
| `git diff --check` (scoped) | **pass** |

---

## Accepted findings and fixes

| ID | Sev | Finding | Fix | Regression tests |
|---|---|---|---|---|
| F-A | P2 | Illegal transitions out of failure terminals/`Done` + sink re-run/double-launch unguarded by tests | (code already fail-closed; pinned) | `verify_failed_terminal_rejects_all_further_steps`, `launch_failed_terminal_rejects_retry_without_relaunch`, `prepare_failed_terminal_rejects_retry_without_launch`, `done_terminal_rejects_further_steps_without_relaunch` |
| F-D | P2 | Skip-stamp parity: `no_update`-with-version never yields a stamp (C# `Dismiss`-reachable) | (already correct; pinned) | `skipped_version_none_for_no_update_even_with_version` |
| F-B | P3 | `apply_changelog` copied `release_url` verbatim — broke the "never `file://`" invariant | Re-filter through `is_allowed_http_url` | `non_http_release_url_dropped_fail_closed` |
| F-C | P3 | `select("")` could select an empty-tagged release | Empty-tag guard | `select_empty_tag_never_selects_even_an_empty_tagged_release` |
| F-E | P3 | 3 clippy warnings in new files | Derive `Default`, `unwrap_or`, `enumerate` | — |
| IRS-1/2 | P3 | `stage()` reset contract + duplicated path-join helper unpinned | — | `restaging_starts_a_fresh_flow_and_resets_recorder`; helper reuse |

### Rejected candidates

Whitespace-only tag selectors; C# `Dismiss` no-update stamping (deliberate notify-parity); `changelog_title` version fallback (no version on `ChangelogDocument`); transient `Launching`/`Launched` unobservability; `SelectedChangelog` derived Debug (titles public, bodies redacted); `File.Exists` pre-launch check (launcher fails closed — more conservative than C# silent skip).

---

## Test command

```powershell
cd rust
cargo test -p wormhole-update
```

**Counts:** `installer::tests` **20**, `changelog_vm::tests` **11**; full wormhole-update **84**.
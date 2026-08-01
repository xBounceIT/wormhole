# Adversarial ledger — HTTP/HTTPS profile wipe FS glue

**Scope:** `rust/crates/wormhole-http/src/profile_fs.rs` (new: `ProfileFs` trait + `RealProfileFs` + `FakeProfileFs` + `ProfileWipeGlue` + path confinement), `src/profile_wipe.rs` (doc pointer only — closed ledger `adversarial-ledger-http-profile-wipe.md` untouched), `src/error.rs` (`UnsafeProfilePath` / `ProfileFs` variants), `src/lib.rs` registration/re-exports.

**Out of scope:** WebView2 COM env-create (`ensure_web_browser_user_data_dir` does the args→`create_dir_all` only); Bitwarden extension storage internals.

**Compared against:** C# `App.xaml.cs::ClearWebBrowserUserData`, `Helpers/AppPaths.cs`, `Helpers/WebViewBrowserArguments.cs` (fingerprinted shared/isolated web roots, wipe must leave Bitwarden cookies/IDB, tolerate locked files like the C# catch).

**Authority:** full adversarial-review-fix (reviewer subagent; parent re-verified final battery)  
**Baseline:** wormhole-http **104** tests  
**Final:** wormhole-http **108** tests

**Attack focus:** path traversal (`..`/absolute), CurDir/nested root collisions, symlink/junction escape (rejected: std `remove_dir_all` is reparse-safe; web root is a fixed `AppPaths` constant), Bitwarden marker preservation, locked-file tolerance, `Debug`/`Display` leakage of home dirs, sweep enumeration failure tolerance.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (+ re-run on IRS delta) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-http` | **pass** (108) |
| `cargo check` / `cargo clippy --all-targets` | **pass** / clean |
| `git diff --check` (scoped) | **pass** |

---

## Accepted findings and fixes

| ID | Sev | Finding | Fix |
|---|---|---|---|
| F-1 | P1 | `roots_overlap` compared raw components — a `.` segment (`…\webview2-web\.` + `…\webview2-web\bitwarden`) bypassed the nested-root check → Bitwarden storage could be wiped | Both roots CurDir-folded before case-insensitive prefix compare |
| F-2 | P2 | `sweep_stale_keyed_folders` failed hard on `list_dir` errors (C# swallows) | Enumeration failure → `Ok(0)` |
| F-3 | P3 | `FakeProfileFs::remove_dir_all` ignored a lock on the target dir itself | Block on `locked.starts_with(&path)` incl. equality |
| F-4 | P3 | `error.rs` docs overclaimed `UnsafeProfilePath` / collision source | Corrected |
| F-5 | P3 | Sweep hostile-escape path untested | `sweep_hostile_path_escape_is_rejected_before_any_io` |
| F-6 | P3 | `ProfileWipeGlue` Debug redaction untested | Extended Debug test |
| F-7 | IRS | Duplicated confinement check (already diverged once) | Centralized `confined_under` core |

### Rejected candidates

Symlink/junction escape in `RealProfileFs` (reparse-safe std; web root is a fixed constant); Fake/Real `list_dir` missing-dir drift (permitted by the trait contract); `FakeWebBrowserProfileStore` equal-only root check (doc-only scope; folder names, not paths).

---

## Test command

```powershell
cd rust
cargo test -p wormhole-http
```

**Counts:** `profile_fs::tests` **20**, `profile_wipe::tests` **17**; full wormhole-http **108**.
# Adversarial ledger — update check + logging bootstrap

**Scope:** `rust/crates/wormhole-update/`, `rust/crates/wormhole-app/` logging init + binary bootstrap, `docs/migration/13-update-logging.md`  
**Authority:** full adversarial-review-fix (edit in scope; no C#; no installer UX)  
**Baseline:** `cargo test -p wormhole-update -p wormhole-app` — 18 + 3 unit / 3 smoke green before review  
**Final:** wormhole-update **33** tests; wormhole-app **5** unit + **3** smoke green  

Compared against C#: `Services/UpdateService.cs`, `Wormhole.Tests/Services/UpdateServiceTests.cs`, `Helpers/LogFiles.cs`, `App.xaml.cs` Serilog / GitHub `HttpClient` registration.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix + post-simplify re-run) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-update -p wormhole-app` | **pass** |
| `git diff --check` (scoped) | **pass** |

---

## Accepted findings

### UPD-01 — Version components ignored `System.Version` Int32 ceiling (`P1`) — **fixed**

- **Where:** `version.rs` `parse_dotnet_version`
- **Invariant:** C# `Version.TryParse` uses signed 32-bit components
- **Evidence:** `2147483648.0` would parse as `u32` but fail in .NET
- **Fix:** Reject component `> i32::MAX`
- **Regression:** `rejects_invalid` overflow cases; `accepts_i32_max_component`

### UPD-02 — No oversized body fail-closed cap (`P1`) — **fixed**

- **Where:** `download.rs` `download_bytes_to_temp`
- **Invariant:** Attack focus — oversized in-memory payloads must not write
- **Fix:** `MAX_INSTALLER_BYTES` (512 MiB) + `download_bytes_to_temp_limited` for tests
- **Regression:** `download_rejects_bytes_over_cap_before_write`, `download_accepts_bytes_at_cap`

### UPD-03 — Manifest / changelog URLs accepted `file://` and weird schemes (`P1`) — **fixed**

- **Where:** `github.rs` / `check.rs` / `changelog.rs`
- **Invariant:** C# has no host allow-list on the download client; still reject non-http(s) schemes (SSRF floor)
- **Evidence:** `evaluate_release` would advertise `file:///…` installer URLs; changelog copied `file://` html_url
- **Fix:** `is_allowed_http_url` / `try_validate_http_url`; evaluate treats bad installer URL as no-update; changelog drops bad `html_url`
- **Regression:** `http_url_rejects_weird_schemes`, `rejects_file_scheme_installer_url`, `from_manifest_drops_file_scheme_url`, `strips_disallowed_release_html_url`

### UPD-04 — Path traversal / multi-component names under-tested; evaluate advertised unsafe names (`P1`) — **fixed**

- **Where:** `download.rs` `validate_installer_file_name`; `check.rs` `evaluate_release`
- **Evidence:** `.` / separators could confuse joins; asset names with `/` still matched `find_installer_asset`
- **Fix:** Single `Component::Normal` gate + parent-dir defense; evaluate requires `is_safe_installer_file_name`
- **Regression:** expanded `download_rejects_path_traversal_name`; `rejects_traversal_installer_file_name`

### UPD-05 — Hash mismatch fail-closed before write under-tested (`P1`) — **fixed**

- **Where:** `download.rs` (verify-before-write already present)
- **Fix / regression:** `hash_mismatch_writes_nothing` asserts empty dest dir

### UPD-06 — Attacker-controlled error context unbounded (`P2`) — **fixed**

- **Where:** `error.rs` + constructors in version/github/download
- **Fix:** `UpdateError::clip_ctx` (256 Unicode scalars + ellipsis)
- **Regression:** `clip_ctx_caps_long_attacker_strings`

### UPD-07 — Pre-release / component-count compare gaps (`P2`) — **fixed**

- **Where:** `version.rs` / `check.rs` tests
- **Fix:** Regressions for `-rc`/`+meta`, `vv…`, empty segments, `1.0.0 > 1.0`, prerelease draft path
- **Regression:** `rejects_invalid` expansions, `three_component_beats_two_when_prefix_equal`, `prerelease_ignored`, `unparsable_prerelease_tag_is_no_update`

### LOG-01 — `password=` / `token=` not redacted (`P1`) — **fixed**

- **Where:** `wormhole-app` `logging.rs` `redact_log_text`
- **Invariant:** Attack focus — never miss `password=` / `token=` (case-insensitive, optional spaces around `=`)
- **Fix:** Always run `redact_assignment_keys` after Bitwarden/secrets pass
- **Regression:** `redact_password_and_token_assignments`

### LOG-02 — Non-UTF8 writer path skipped redaction (`P2`) — **fixed**

- **Where:** `RedactingWriter::write`
- **Fix:** `String::from_utf8_lossy` before `redact_log_text`

### LOG-03 — Log dir creation / path secret hygiene under-tested (`P2`) — **fixed**

- **Where:** `init_tracing_with_dirs` / path helpers
- **Regression:** `init_tracing_creates_logs_dir`; path assertion excludes `password=`/`token=` substrings

### DOC-01 — Migration doc drift (`P3`) — **fixed**

- **Where:** `docs/migration/13-update-logging.md`
- **Fix:** Document fail-closed contracts, scheme floor, password/token redaction, ledger link

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Host allow-list beyond http(s) — C# download `HttpClient` has none; scheme floor matches attack brief |
| REJ-02 | — | Windows `remove_file`+`rename` vs `MoveFileEx(REPLACE)` — no win32 dep in update crate; acceptable for cache write stub |
| REJ-03 | — | Live HTTP / MOTW / silent installer / cache rotation — explicit non-goals |
| REJ-04 | — | Share `local_app_data` across crates — not worth a new shared crate for one helper |
| REJ-05 | — | Push `password=`/`token=` into `wormhole-secrets-win` — out of edit scope; logging layer owns the extra patterns |
| REJ-06 | — | AppServices unrelated feature bag changes — out of scope |

---

## Simplify passes (iterative-review-simplify)

| Cycle | Reuse | Efficiency | Quality | Disposition |
|---|---|---|---|---|
| 1 | Unused `NoInstallerAsset`; redundant `.`/`..` checks; weak password test | — | Docs drift | **Fixed** |
| 2 | No findings | No findings | No findings | **clean 1** |
| 3 | No findings | No findings | No findings | **clean 2** |
| 4 | No findings | No findings | No findings | **clean 3** |

---

## Adversarial cycles (post-simplify re-run)

| Pass | Strategy | Accepted |
|---|---|---|
| 1 | Security / URL / download fail-closed first | none |
| 2 | Tests-outward + C# integration drift (Version Int32, repo regex, Serilog path, HttpClient) | none |

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-update -p wormhole-app
```

Expected: wormhole-update **33 passed**; wormhole-app lib **5** + smoke **3** passed.

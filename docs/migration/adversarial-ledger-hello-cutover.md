# Adversarial ledger — Hello / app-auth / Bitwarden / cutover

**Scope:**
- `rust/crates/wormhole-secrets-win/` — `hello`, `app_auth`, path segment guards for Bitwarden helpers
- `rust/crates/wormhole-http/` — `bitwarden` HTTPS profile helpers
- `docs/migration/15-cutover.md` (+ related links in `04-secrets.md`, `10-http.md`, `README.md`)

**Out of scope:** C# tree; full WinRT `UserConsentVerifier` UI (documented gap only);
Bitwarden CLI `bw unlock` / memory-only `BW_SESSION` (separate stub in
`bitwarden_session` — see [04-secrets.md](04-secrets.md)).

**Authority:** full adversarial-review-fix (edit in scope)  
**Baseline:** `cargo test -p wormhole-secrets-win -p wormhole-http` — 35 + 26 green before review  
**Final:** 43 + 29 green  

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix + post-simplify re-run) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-secrets-win -p wormhole-http` | **pass** (43 + 29) |

---

## Accepted findings

### HC-01 — Bitwarden path helpers allowed traversal (`P1`) — **fixed**

- **Where:** `paths.rs` `bitwarden_browser_webview2_user_data`, `bitwarden_extension_install_dir`
- **Invariant:** Profile / extension paths must stay under `%LOCALAPPDATA%\Wormhole\…`
- **Evidence:** `join("..\\..\\keys")` / version with separators escaped the WebView2 / extensions root
- **Impact:** Hostile folder/version strings could target sibling secret stores
- **Fix:** `require_single_path_segment` + `SecretsError::InvalidPathSegment`; helpers return `Result`
- **Regression:** `paths::tests::single_segment_*`, `user_data_and_extension_dir_reject_traversal`

### HC-02 — `AppAuthUnlock` Debug leaked verifier plaintext (`P1`) — **fixed**

- **Where:** `app_auth.rs` `AppAuthUnlock`
- **Invariant:** Secrets surfaces must not echo secret payloads in `Display`/`Debug`
- **Evidence:** `#[derive(Debug)]` dumped `plaintext: […]` bytes
- **Impact:** Logging unlock results would leak app-auth JSON
- **Fix:** Custom `Debug` with `plaintext_len` only
- **Regression:** `unlock_debug_redacts_plaintext`

### HC-03 — Bitwarden profile APIs lacked HTTPS fail-closed gate (`P1`) — **fixed**

- **Where:** `wormhole-http` `bitwarden.rs`
- **Invariant:** Bitwarden extension profiles are HTTPS-only (logical target / `original_uri`)
- **Evidence:** `user_data_folder_for_target` / route keys accepted `http://` and non-http schemes
- **Impact:** Cookie/profile isolation for http / `javascript:` targets
- **Fix:** `ensure_https_bitwarden_target`, `HttpError::BitwardenRequiresHttps`; `user_data_folder_for_target` → `Result`; route key returns `None` for non-HTTPS
- **Regression:** `ensure_https_*`, `user_data_folder_for_target_rejects_http`, route-key http `None`

### HC-04 — App-auth wrong-entropy / LocalAppData contracts under-tested (`P2`) — **fixed**

- **Where:** `app_auth` tests / path assertions
- **Evidence:** Wrong entropy covered mainly via raw `unprotect`; default path not pinned under `LOCALAPPDATA`
- **Fix:** Wrong Bitwarden-entropy blob fails unlock without leaking secret; default path under LocalAppData\Wormhole
- **Regression:** `wrong_entropy_blob_fails_unlock_without_leaking_secret`, `default_path_under_localappdata_wormhole`, `wormhole_paths_live_under_local_app_data`

### HC-05 — Hello stub message-echo / success claims under-pinned (`P2`) — **fixed**

- **Where:** `hello.rs` tests
- **Invariant:** Stub must never claim `verified`/`available`; must not echo caller prompt
- **Fix:** Regressions for production entry points + short/non-`RDP-` SESSIONNAME
- **Regression:** `verification_never_echoes_caller_message_or_claims_success`, `sessionname_short_or_non_rdp_prefix_is_local`

### HC-06 — Cutover overclaim / typo vs crate capabilities (`P2`/`P3`) — **fixed**

- **Where:** `docs/migration/15-cutover.md` (+ `04-secrets.md`, `10-http.md`, `README.md`)
- **Evidence:** Hello table could be read as “gate works ⇒ Hello usable”; “Evergreen Evergreen” typo; API docs lagged Result/HTTPS gates
- **Fix:** Explicit fail-closed Hello status; cargo-test ≠ hardware gate; HTTPS/path docs; ledger link
- **Regression:** doc review (no runtime)

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Full WinRT `UserConsentVerifier` — out of scope; thin stub already fail-closed |
| REJ-02 | — | `userinfo` in authority for route-key material — matches .NET `GetLeftPart(Authority)` parity; hash not logged |
| REJ-03 | — | `LOCALAPPDATA` env hijack — intentional OS/test override; paths still under that root |
| REJ-04 | — | Double HTTPS check in `build_persistent_route_key` after `ensure_*` — defense in depth for standalone callers |
| REJ-05 | — | Merge overlapping Hello tests — clarity preferred over fewer cases |
| REJ-06 | — | C# mutation — explicitly out of scope |

---

## Adversarial cycles

| Pass | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → security → integration → tests | HC-01…HC-05 | Fixed; reset |
| Adv-2 | Docs/cutover accuracy → reverse security → SESSIONNAME edges | HC-06 | Fixed; reset |
| Adv-3 | Post-simplify delta: `get(..4)` remote detect, Hello entry cleanup | None | Clean (1/2) |
| Adv-4 | Tests-as-oracles → HTTPS gate → path segment → Debug redaction | None | Clean (2/2) |

---

## Simplify passes (iterative-review-simplify)

| Cycle | Reuse | Efficiency | Quality | Disposition |
|---|---|---|---|---|
| 1 | Redundant `let _` before Hello `with` helper | — | SESSIONNAME `get(..4)` safer than index | **Fixed** → reset |
| 2 | Path segment helper centralized; HTTPS ensure reused | No hot-path I/O | Docs/API aligned | Clean (1/3) |
| 3 | No missed local helpers | Route-key HTTPS re-check kept | Fail-closed stubs intact | Clean (2/3) |
| 4 | Same | Same | Diff hygiene / ledger | Clean (3/3) |

Simplify cycle 1 changed code → Adv-3/Adv-4 re-run completed clean; Sim-2…4 clean with no further edits.

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-secrets-win -p wormhole-http
```

Expected: **43** (`wormhole-secrets-win`) + **29** (`wormhole-http`) passed.

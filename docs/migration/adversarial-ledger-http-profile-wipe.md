# Adversarial ledger — HTTP/HTTPS WebView2 profile isolation / wipe Fake glue

**Scope:**
- `rust/crates/wormhole-http/src/profile_wipe.rs`
  (keyed fingerprint / shared vs isolated / `FakeWebBrowserProfileStore` /
  `clear_web_browser_user_data` / `stale_keyed_folder_names`)
- `HttpError::{EmptyPath,EmptyIsolatedId,WebProfileRootCollision}` + `lib.rs` exports
- Docs: `docs/migration/10-http.md`, `feature-matrix.md`, `interop-inventory.md`,
  README ledger index

**Out of scope:** Live WebView2 / GPUI env create; real `%LOCALAPPDATA%` disk wipe;
Bitwarden extension install / cookie seeding; `wormhole-surface-win`
`unique_user_data_dir` lab temp folders; C# `App` / `WebBrowserView` edits;
mcp / ssh / sftp crates.

**Authority:** full adversarial-review-fix (edit in scope)  
**Impl:** parent agent (no child agents)  
**Baseline:** `cargo test -p wormhole-http` 70 green (15 `profile_wipe`, pre-review)  
**Final:** `wormhole-http` **72** green (**17** `profile_wipe`)

Context7 MCP unavailable in this environment.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (Adv-C1/C2) + **2** post-simplify re-adv |
| Iterative-review-simplify clean passes | **3** consecutive (after Sim-fix hash + `require_isolated_id`) |
| `cargo test -p wormhole-http` | **pass** (72) |

---

## Accepted findings

### HPW-01 — HTTP leaf ignore could force isolation via raw bool (`P2`) — **fixed** (pre-review)

- **Where:** `requires_isolated_web_profile` / target path
- **Invariant:** C# `IgnoreCertErrors` is scheme-gated; plain HTTP must share
- **Fix:** Prefer `_for_target` / rustdoc “resolved” wording;
  `plain_http_leaf_ignore_does_not_isolate_via_target`

### HPW-02 — NBSP / Unicode White_Space empty path under-pinned (`P2`) — **fixed** (pre-review)

- **Where:** `require_non_empty_path` / `require_isolated_id` / Fake store ctor
- **Fix:** NBSP assertions on path helpers + Fake `new`

### HPW-03 — Case-insensitive web≡Bitwarden root collision (`P2`) — **fixed** (pre-review)

- **Where:** `FakeWebBrowserProfileStore::new`
- **Fix:** `path_eq_ignore_case`; `C:\Same` vs `c:\same` regression

### HPW-04 — Empty `current_keyed` would mass-delete `shared-*` (`P2`) — **fixed** (pre-review)

- **Where:** `stale_keyed_folder_names`
- **Fix:** Empty / whitespace current → no-op `Vec`

### HPW-05 — Same folder name across web + Bitwarden roots (`P2`) — **fixed** (pre-review)

- **Where:** `clear_web_browser_user_data`
- **Fix:** `wipe_leaves_bitwarden_even_when_folder_names_collide`

### HPW-06 — `resolve_and_seed` re-parsed `file_name` (`P3`) — **fixed** (pre-review simplify)

- **Where:** `FakeWebBrowserProfileStore::resolve_and_seed_for_target`
- **Fix:** Derive path + name from `WebBrowserProfileKind`

### HPW-07 — Double `require_isolated_id` on select join (`P3`) — **fixed** (pre-review simplify)

- **Where:** `select_web_browser_user_data_folder` / resolve Isolated arm
- **Fix:** Join `env-{id}` after kind validation; keep public
  `web_browser_isolated_user_data` for direct callers

### HPW-08 — Unused `HttpCertPolicy` import warning (`P3`) — **fixed** (pre-review)

- **Where:** module imports
- **Fix:** Import only in tests

### HPW-09 — README ledger index missing (`P2`) — **fixed**

- **Where:** `docs/migration/README.md`
- **Invariant:** Gate requires ledger + README index
- **Evidence:** Ledger file untracked; HTTP ledger table stopped at nav-report
- **Fix:** Index row for `adversarial-ledger-http-profile-wipe.md`

### HPW-10 — `resolve_and_seed` only pinned shared (`P2`) — **fixed**

- **Where:** `resolve_and_seed_records_shared_or_isolated`
- **Invariant:** SOCKS / ignore-cert must seed `env-<id>`; empty id fails closed
- **Evidence:** Test name claimed both paths; body only exercised shared
- **Fix:** Extend test — empty-id error + SOCKS/ignore seed; no mutation on fail
- **Regression:** that test

### HPW-11 — Hostile seed names under-pinned (`P3`) — **fixed**

- **Where:** `seed_web_folder` / `seed_bitwarden_folder`
- **Fix:** `seed_rejects_hostile_folder_names` (empty / NBSP / `..` / separators / NUL)

### HPW-12 — Sweep Bitwarden isolation under-pinned (`P3`) — **fixed**

- **Where:** `sweep_stale_keyed_folders`
- **Fix:** `sweep_never_touches_bitwarden_folders` (same `shared-*` name in BW set)

### HPW-13 — Whitespace-padded `current_keyed` deletes live shared (`P2`) — **fixed**

- **Where:** `stale_keyed_folder_names`
- **Invariant:** Trim keep name before compare (empty already no-op’d)
- **Evidence:** `"  shared-815e5671  "` failed `eq_ignore_ascii_case` vs real folder
- **Fix:** `let current = current_keyed.trim()` then compare; padded regression
- **Regression:** extended `stale_keyed_helper_is_case_insensitive_on_current`

### HPW-14 — Non-`shared-*` keep mass-deletes every shared folder (`P2`) — **fixed**

- **Where:** `stale_keyed_folder_names`
- **Invariant:** Fail-closed like empty fingerprint — keep must itself be `shared-*`
- **Evidence:** `current_keyed = "env-1"` would mark all `shared-*` stale
- **Fix:** No-op when keep lacks `shared-` prefix; `10-http.md` row updated
- **Regression:** assertion on helper test

### HPW-15 — Double SHA-256 on shared `resolve_and_seed` (`P3`) — **fixed** (simplify)

- **Where:** Shared arm called `web_browser_shared_user_data` + `keyed_shared_folder_name`
- **Fix:** Single fingerprint + join (mirrors Isolated arm)

### HPW-16 — `require_isolated_id` duplicated `require_folder_name` (`P3`) — **fixed** (simplify)

- **Where:** `require_isolated_id`
- **Fix:** Thin alias to `require_folder_name` (call-site semantics preserved)

---

## Rejected candidates

| ID | Reason |
|---|---|
| REJ-01 | Live disk wipe under `%LOCALAPPDATA%` — **forbidden** non-goal; Fake only |
| REJ-02 | Wire WebView2 / GPUI / surface-win `unique_user_data_dir` — out of scope |
| REJ-03 | Share `hex_lower` with `bitwarden.rs` — micro-dupe; local helper fine |
| REJ-04 | Reject ZWSP-only isolated id — not Unicode White_Space; speculative vs C# Guid |
| REJ-05 | Treat C# best-effort locked-folder skip in Fake — Fake always removes tracked names |
| REJ-06 | Put glue in `wormhole-surface-win` — chosen `wormhole-http` (docs / feature-matrix) |
| REJ-07 | New `InvalidFolderName` error for seed hostility — `EmptyIsolatedId` fail-closed enough |
| REJ-08 | Nested web/Bitwarden path (subdir) collision — separate Fake sets; disk nesting N/A |
| REJ-09 | Collapse Shared/Isolated resolve arms into one helper — two arms stay readable |

---

## Gate record

### Adversarial loop

| Pass | Focus | Accepted | Result |
|---|---|---|---|
| Adv-1 | Contract / docs index / resolve_and_seed / seed+sweep tests | HPW-09..12 | Fixed; reset |
| Adv-2 | Reverse: stale keep compare / padded fingerprint | HPW-13 | Fixed; reset |
| Adv-3 | Security: non-`shared-*` keep mass-delete | HPW-14 | Fixed; reset |
| Adv-C1 | Lifecycle wipe/reseed; Debug; HTTP leaf; collision | None | Clean (1/2) |
| Adv-C2 | Reverse: golden hash / C# SOCKS∨ignore / README | None | Clean (2/2) |
| Adv-R1 | Post-simplify delta (single hash Shared arm; id alias) | None | Clean (1/2) |
| Adv-R2 | Reverse: public helpers still fail-closed; 17 tests | None | Clean (2/2) |

### Iterative-review-simplify

| Pass | Reuse | Efficiency | Quality | Result |
|---|---|---|---|---|
| Sim-fix | — | HPW-15 double hash | HPW-16 id alias | Fixed; reset |
| Sim-1 | Keep semantic `require_isolated_id` alias | Single fingerprint | Docs + tests aligned | Clean (1/3) |
| Sim-2 | Reject shared hex / new error variant | Fake in-memory only | Collision / NBSP / hostile seed pinned | Clean (2/3) |
| Sim-3 | Public `web_browser_isolated_*` kept | No hot-path I/O | No secret Debug; README indexed | Clean (3/3) |

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cargo test -p wormhole-http
cargo test -p wormhole-http --lib profile_wipe
git diff --check -- rust/crates/wormhole-http docs/migration/10-http.md docs/migration/README.md docs/migration/adversarial-ledger-http-profile-wipe.md
```

Result: **pass** — 72 unit tests (17 `profile_wipe`). Diff hygiene clean for touched paths (trailing whitespace on `10-http.md` status line removed).

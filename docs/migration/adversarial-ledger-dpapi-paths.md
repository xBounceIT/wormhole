# Adversarial ledger — DPAPI keys/tunnels path confinement

**Scope:**
- `rust/crates/wormhole-secrets-win/src/paths.rs` (`ensure_confined_under`, `confined_file_under`, `key_path` / `tunnel_path` / `_under`)
- `rust/crates/wormhole-secrets-win/src/key_tunnel.rs` (read/write payload helpers)
- `SecretsError::PathNotConfined` in `lib.rs`
- Docs: `docs/migration/04-secrets.md` Path confinement + coverage; `docs/migration/README.md` ledger index

**Out of scope:** Symlink follow / canonicalize (lexical-only, same class as settings guards); CredMgr size; Hello / Bitwarden session; Stormshield/WatchGuard/Azure cache path helpers (guid-only, not injectable roots); raw `write_protected_file` callers outside key/tunnel helpers.

**Authority:** full adversarial-review-fix (edit in scope)  
**Attack focus:** reject `..` and absolute escapes; `PathNotConfined` never embeds path/key material; confinement before I/O; temp-dir tests  
**Baseline:** `cargo test -p wormhole-secrets-win` — 72 tests green before review  
**Final:** 73 tests green  

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix + post-simplify re-run) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-secrets-win` | **pass** (73) |

---

## Accepted findings

### DPAPI-01 — Empty-root confinement short-circuit untested (`P1`) — **fixed**

- **Where:** `paths.rs` `ensure_confined_under` / `confined_file_under`
- **Invariant:** Empty `root` must be rejected; on Windows/Unix `path.starts_with("")` is vacuously true for every path
- **Evidence:** Empty-root check existed but had no regression; removing it would accept any absolute escape
- **Impact:** Accidental removal / refactor could disable all lexical confinement
- **Fix:** Document vacuous-`starts_with` rationale; tests `ensure_confined_under_rejects_empty_root`, empty root in `confined_file_under_rejects_hostile_root_and_name`, empty tunnel root in key_tunnel hostile test
- **Regression:** those tests; Display/Debug free of `Windows` / `evil` / `C:\`

### DPAPI-02 — Hostile-root before-I/O not proven on filesystem (`P2`) — **fixed**

- **Where:** `key_tunnel.rs` tests
- **Invariant:** Confinement runs before mkdir / DPAPI protect / read; hostile roots leave the temp tree untouched
- **Evidence:** Prior test only matched `PathNotConfined` on `C:\temp\..\Windows` — no proof `create_dir_all` / write never ran
- **Impact:** A regression that confined after I/O could still pass the old assertion
- **Fix:** Temp-dir roots containing lexical `..`; assert no children / no `outside` after failed write **and** read on keys and tunnels
- **Regression:** `write_and_read_helpers_reject_hostile_root_before_io`

### DPAPI-03 — Read helpers + Windows join-replacement vectors under-pinned (`P2`) — **fixed**

- **Where:** `paths.rs` / `key_tunnel.rs` tests; docs
- **Invariant:** Reads confine before I/O; single-segment rejects forms where `Path::join` replaces the root (`D:evil`, `\Windows\…`); prefix confusion (`keys` vs `keys_extra`) rejected; `PathNotConfined` never embeds path/key material
- **Evidence:** Only writes were hostile-tested; `\Windows\…` has `is_absolute() == false` on Windows; drive-relative `D:evil` replaces on join
- **Fix:** Extended segment / confined_file / ensure_confined matrices; shared `assert_path_not_confined`; docs Path confinement + coverage link
- **Regression:** `single_segment_rejects_traversal`, `confined_file_under_rejects_hostile_root_and_name`, `ensure_confined_under_rejects_parent_and_absolute_escape`, key_tunnel hostile test

### DPAPI-04 — Read/write confinement docs incomplete (`P3`) — **fixed**

- **Where:** `key_tunnel.rs` rustdoc; `04-secrets.md`; `README.md`
- **Fix:** Document confinement-before-I/O on read helpers + tunnel write; module doc covers reads/writes; ledger index row

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Symlink / junction escape past lexical confine — residual; same class as settings / import guards |
| REJ-02 | — | `SecretsError::Io` may embed OS path strings — out of `PathNotConfined` contract; confined helpers fail closed before I/O on escapes |
| REJ-03 | — | Confine Stormshield/WatchGuard/Azure cache helpers — out of keys/tunnels attack scope; filenames are `guid_n` only |
| REJ-04 | — | Case-insensitive Windows `starts_with` mismatch — fail-closed (false reject), not escape |
| REJ-05 | — | Drop defense-in-depth `ensure_confined_under` after single-segment join — keep fail-closed belt |
| REJ-06 | — | NTFS ADS / trailing-dot filename speculation — `guid_n` hex-only; segment rules reject separators |
| REJ-07 | — | Share `assert_path_not_confined` into `paths` tests — two call sites; not worth a test-only export |

---

## Adversarial cycles

| Pass | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-1 | Security / empty-root vacuity / before-I/O / error redaction | DPAPI-01..03 | Fixed; reset |
| Adv-2 | Tests-outward + Windows join replacement + prefix confusion | DPAPI-03 strengthen + DPAPI-04 docs | Fixed; reset |
| Adv-3 | Concurrency (pure path fns) → failure atomicity → I/O-outward | None | Clean (1/2) |
| Adv-4 | Integration drift vs `04-secrets.md` + reverse boundary matrix | None | Clean (2/2) |
| Post-simplify Adv-1 | Docstring delta + confinement-before-I/O still holds | None | Clean |
| Post-simplify Adv-2 | Test oracles + PathNotConfined payload-free | None | Clean (2/2) |

---

## Simplify passes (iterative-review-simplify)

| Cycle | Reuse | Efficiency | Quality | Disposition |
|---|---|---|---|---|
| 1 | — | — | Tunnel/read rustdoc omitted before-I/O; module doc said writes-only | **Fixed** → reset |
| 2 | Early empty/parent in `confined_file_under` kept (fail-fast) | No hot-path I/O | Contracts + docs aligned | Clean (1/3) |
| 3 | No new shared abstraction needed | Same | Prefix / empty-root / temp-dir pins intact | Clean (2/3) |
| 4 | REJ-07 share helper | Same | Diff hygiene / ledger / README | Clean (3/3) |

---

## Attack lane outcomes (summary)

| Lane | Outcome |
|---|---|
| `..` / absolute escape | `PathNotConfined` / `InvalidPathSegment`; join-replacement forms rejected |
| `PathNotConfined` embeds path/key | Display/Debug = `op` only; tests assert no path/secret fragments |
| Confinement before I/O | `key_path_under` / `tunnel_path_under` before protect/read; temp dir untouched on hostile root |
| Temp-dir tests | Round-trip under injectable roots; hostile `..` roots leave zero children |

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-secrets-win
```

Expected: `73 passed`.

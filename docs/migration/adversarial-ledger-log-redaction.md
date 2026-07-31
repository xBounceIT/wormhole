# Adversarial ledger — `redact_log_text` / logging redaction

**Scope:** `rust/crates/wormhole-app/src/logging.rs` (`redact_log_text` + writer hook), `docs/migration/13-update-logging.md`  
**Authority:** full adversarial-review-fix (edit in scope)  
**Attack focus:** case-insensitive `password=` / `token=` / `secret=` / `SVPNCOOKIE=` / `BW_SESSION=` always stripped; nested / query-string; bare `key=` left; never claim full free-form secret scrubbing  
**Baseline:** `cargo test -p wormhole-app` green before review  
**Final:** `cargo test -p wormhole-app` — logging redaction unit tests green (plus unrelated in-crate tests)

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (incl. post-simplify re-run) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-app` | **pass** |
| `git diff --check` (scoped) | **pass** |

---

## Accepted findings

### LOG-R-01 — Trailing CR/LF collapsed / bare `\r` dropped (`P2`) — **fixed**

- **Where:** `redact_log_text`
- **Invariant:** Trailing record separators must be preserved exactly
- **Evidence:** `"password=x\n\n"` → single `\n`; `"password=x\r"` lost `\r`
- **Fix:** Preserve `value[core.len()..]` after `trim_end_matches(['\r','\n'])`
- **Regression:** `redact_preserves_exact_trailing_line_endings`

### LOG-R-02 — Docs under-stated assignment keys + over-claim risk (`P2`) — **fixed**

- **Where:** `docs/migration/13-update-logging.md`, `redact_log_text` rustdoc
- **Invariant:** Document all five keys; never claim full free-form scrubbing
- **Fix:** Redaction table + non-goal bullet; rustdoc best-effort disclaimer
- **Regression:** doc text + `redact_does_not_claim_freeform_secret_scrubbing`

### LOG-R-03 — Freeform / substring contracts under-tested (`P2`) — **fixed**

- **Where:** tests
- **Evidence:** Prose / JSON `:"…"` / `secret_key=` / `api_token=` not pinned
- **Fix:** Negative freeform test + intentional substring pins + nested/query coverage
- **Regression:** `redact_does_not_claim_freeform_secret_scrubbing`, `redact_nested_and_query_string_assignments`

### LOG-R-04 — Secrets-off fallback redacted only first `--session` / `--code` (`P2`) — **fixed**

- **Where:** `fallback_redact_flag` (and former `fallback_redact_env`)
- **Invariant:** Multi-occurrence CLI flags must all scrub when `secrets` is off
- **Fix:** Loop all matches (env names reuse `redact_assignment_key`)
- **Regression:** covered by Bitwarden-style multi-pattern tests under default features; loop mirrors `wormhole-secrets-win`

### LOG-R-05 — Comment claimed identifier boundary that code does not enforce (`P3`) — **fixed**

- **Where:** `redact_assignment_key`
- **Fix:** Comment now states intentional substring match; `REDACTED` const centralized

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Stop `\S+` at `&` / `;` for dual query markers — values already stripped via swallow; Bitwarden `\S+` parity |
| REJ-02 | — | Chunk-split write bypass — `tracing-subscriber` 0.3.23 buffers full event then `write_all`; our `write` consumes the whole buffer |
| REJ-03 | — | JSON / prose / colon forms — explicit non-goal |
| REJ-04 | — | `File` `flush()` no-op on cached handle — every `write_daily_file` already flushes |
| REJ-05 | — | Push assignment keys into `wormhole-secrets-win` — logging layer owns the extra patterns |
| REJ-06 | — | Fullwidth `＝` / exotic Unicode keys — ASCII `=` contract only |
| REJ-07 | — | Single-pass multi-key redactor — ≤500 chars after Bitwarden truncate; not worth complexity |

---

## Simplify passes (iterative-review-simplify)

| Cycle | Reuse | Efficiency | Quality | Disposition |
|---|---|---|---|---|
| 1 | Thin `fallback_redact_env` wrapper | — | — | **Fixed** (inline → `redact_assignment_key`) |
| 2 | No findings | No findings | No findings | **clean 1** |
| 3 | No findings | No findings | No findings | **clean 2** |
| 4 | No findings | No findings | No findings | **clean 3** |

---

## Adversarial cycles (post-simplify re-run)

| Cycle | Notes | Disposition |
|---|---|---|
| 1 | Security + contract + writer lanes on inlined fallback | **clean 1** |
| 2 | Reverse order: tests → docs → assignment engine | **clean 2** |

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-app
```

Pre-existing warnings in sibling crates (`wormhole-ui` unused import, `wormhole-storage` dead_code) are unrelated to this scope.

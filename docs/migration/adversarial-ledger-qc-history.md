# Adversarial ledger — Quick Connect recent-history VM glue

Scope (ONLY):
- `rust/crates/wormhole-ui/src/quick_connect/history.rs`
- Related HTTP address format helper used by history
  (`connection_editor/http_address.rs` `format_http_address` / `parse_http_address` re-export)
- Docs `docs/migration/21-quick-connect.md`, README ledger link
- Focused lib tests under `quick_connect::history` (+ `http_address` format round-trip)

Out of scope: GPUI MRU chrome; durable SQLite/file history backend; auto-record on
`connect_quick_connect`; C# production app; unrelated session/tunnel streams.

Baseline: `cargo test -p wormhole-ui --no-default-features --features session --lib history`
(10 → 16 tests through review). Context7 MCP unavailable; pins from workspace
`Cargo.toml` / `deps-pins.md`.

Attack focus: MRU cap / dedupe; EmptyHost fail-closed; clear/remove; no passwords;
HTTP(S) host/port round-trip vs `ConnectionNode`; store commit atomicity; reload clamp.

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| QCH-001 | P1 | `apply_to_quick_connect` | HTTP(S) cleared port and set bare host only; `write_to` splits address → port lost on re-seed | QC `fw.local:8443` → node host/port split → apply → `fw.local` | **Fixed** — `format_http_address` rebuilds `host[:port]` / `[ipv6]:port`; `try_new` parses HTTP address into bare host + port |
| QCH-002 | P2 | `insert_front` / `remove*` / `clear` | Mutated in-memory list before `store.save`; save `Err` left memory ahead of store | Controllable failing store | **Fixed** — persist-first `commit` |
| QCH-003 | P2 | `reload` | Clamped capacity in memory only; orphans remained in store (unlike `with_capacity`) | Oversized store + `reload` | **Fixed** — sanitize + persist when dirty |
| QCH-004 | P2 | `normalize_port` | Explicit protocol default (`Some(22)` etc.) did not dedupe with implicit `None` | SSH `None` then `Some(22)` → 2 entries | **Fixed** — collapse defaults via `default_port` |
| QCH-005 | P2 | tests / docs | HTTP apply, password ignore, reload clamp, save-fail atomicity, default-port dedupe under-tested; docs under-specified | Attack lanes | **Fixed** — focused regressions + `21-quick-connect.md` + this ledger + README |
| QCH-006 | P3 | `remove` docs | Said “first matching” but `retain` removed all | Doc vs behaviour | **Fixed** — docs say every matching key |
| QCH-007 | — | Unicode / IDN case fold | `to_ascii_lowercase` only | DNS/COM ASCII enough for v1 Fake store | **Rejected** |
| QCH-008 | — | Clear stale inline password on `apply_to_quick_connect` | Leftover QC password if chrome had one | Doc: does not touch credentials | **Rejected** — explicit non-touch |
| QCH-009 | — | Auto-record inside `connect_quick_connect` | Easy to forget caller record | Non-goal for this stub | **Rejected** |

## Fixes applied

- `history.rs` — HTTP(S) normalize/parse; apply rebuild; default-port collapse; persist-first `commit`; load/`reload` sanitize (blank host drop, dedupe, capacity) + persist when dirty; `remove` miss short-circuit
- `http_address.rs` / `connection_editor/mod.rs` — `format_http_address` + `pub(crate)` re-export
- Tests — HTTP port preserve; IPv6 brackets; password absent from history Debug; default-port dedupe; reload clamp; save-fail leaves memory; prior MRU/EmptyHost/clear/remove coverage retained
- Docs — `21-quick-connect.md` history table; README ledger row; this ledger

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → tests | QCH-001…006 | Fixed; reset |
| Adv-2 | Reverse: secrets → HTTP round-trip → commit atomicity → reload → default ports → EmptyHost → docs | QCH-007…009 rejected | Clean (1/2) |
| Adv-3 | Forward on post-fix surface (apply / commit / sanitize / cap 0) | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Reuse `parse_http_address` / `format_http_address` | `sanitize_loaded(&[…])` avoid load clone | — | Yes → reset | Fixed |
| Sim-2 | — | `try_new(…, host.as_str(), …)` in sanitize; `remove` skip clone on miss | Arc import hoist in tests | Yes → reset | Fixed |
| Sim-3 | SharedFake vs ControllableStore merge rejected (different fail control) | Cap-10 clone on mutate kept for commit atomicity | No validated bugs | None | Clean (1/3) |
| Sim-4 | Same | Same | Diff hygiene / in-scope only | None | Clean (2/3) |
| Sim-5 | Same | Same | No further churn | None | Clean (3/3) |

### Post-simplify adversarial re-run (required)

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: sanitize slice, remove short-circuit, HTTP format, commit order | None | Clean (1/2) |
| Adv-R2 | Reverse: password Debug, HTTP/IPv6 apply, EmptyHost, reload orphans, save-fail, default ports | None | Clean (2/2) |

No further simplify edits after Adv-R*; three consecutive clean simplify cycles remain the last simplify run.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui --no-default-features --features session --lib history
cargo test -p wormhole-ui --no-default-features --lib http_address
```

Result: **pass** — `--lib history` **16** ok; `--lib http_address` **4** ok (includes format round-trip). `git diff --check` clean for scoped paths.

## Residual notes

- GPUI recent-history chrome and durable store backends remain non-goals.
- Callers must still invoke `record_success*` after a successful session open.
- Context7 MCP unavailable in this environment.

# Adversarial ledger — clipboard paste → session glue

Scope:
- `rust/crates/wormhole-terminal/src/paste_glue.rs`
  (`paste_request_to_session`, `write_paste_chunks`, `PasteSessionError`,
  `PasteToSessionResult`, `paste_request_to_fake_session`)
- `rust/crates/wormhole-terminal/src/session.rs` (`FakeTerminalSession`,
  `close_after_n_writes`, body-free `Debug`)
- Call chain: `read_paste_text` → `build_paste_transaction` →
  `TerminalSession::write`
- Docs: `docs/migration/14-terminal-bridge.md`

Out of scope: WebView2 `paste-drain` / begin / chunk / end pump (C#
`TerminalBridge`); Win32 clipboard read implementation (see
`adversarial-ledger-terminal-paste.md`); auto-sudo password inject (see
`adversarial-ledger-clipboard-auto-sudo.md`); GPUI / live OS clipboard asserts.

Baseline (before review edits): `cargo test -p wormhole-terminal` (63 passed),
`cargo test -p wormhole-terminal --features clipboard-win` (69 passed).

Attack focus:
- Oversized / empty fail-closed (zero session writes)
- Closing at entry (no clipboard read) and closing mid-paste (partial writes OK)
- Secret paste body never in `Debug` / `Display` / errors
- Chunk boundary edges (CRLF, exact chunk size, multibyte scalar)
- `FakeTerminalSession` path only (no GPUI / live clipboard OS)

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| CP-001 | P1 | `paste_glue` tests / `FakeTerminalSession` | Mid-flight close between chunks documented but unpinned | Attack list: closing mid-paste; only entry `mark_closing` tested | **Fixed** — `close_after_n_writes` + `closing_mid_paste_fail_closed_after_partial_writes` |
| CP-002 | P2 | `paste_request_to_session` match `_` / `other` | Unexpected frames used `debug_assert!(false)` → fail-open in release (skip + `Ok`) | Hostile `SelectionCopy` would silently succeed with zero/partial writes | **Fixed** — `PasteSessionError::UnexpectedFrame` (body-free); `write_paste_chunks` helper + regression test |
| CP-003 | P3 | `14-terminal-bridge.md` | Paste→session section omitted mid-flight close / UnexpectedFrame / ledger link | Docs only mentioned entry closing | **Fixed** — docs + ledger index |
| CP-004 | P3 | tests | Exact `CLIPBOARD_PASTE_CHUNK_CHARS` single write + UTF-8 scalar boundary unpinned at glue layer | Chunker covered in `clipboard.rs`; session reassembly unpinned | **Fixed** — `exact_chunk_size_is_single_write`, `unicode_scalar_boundary_reassembles` |
| CP-005 | — | TOCTOU `is_closing` then `write` | Concurrent close between check and write | Lab stub; `write` re-checks closing | **Rejected** — not reachable under Fake single-threaded paste; real pump owns teardown |
| CP-006 | — | `force` unused in write path | Bracketed-paste ESC not wrapped by stub | Documented: page / xterm owns force semantics | **Rejected** — intentional Lab contract |
| CP-007 | — | Live OS clipboard / GPUI paste | Attack path forbids requiring live clipboard | Fake path sufficient | **Rejected** — out of scope |

## Fixes applied

- `FakeTerminalSession::close_after_n_writes` (shared by async `write` / `write_bytes_sync`)
- `write_paste_chunks` + `PasteSessionError::UnexpectedFrame` fail-closed (no frame body in errors)
- Regression tests: mid-paste close, unexpected frame, exact chunk, Unicode scalar boundary, Fake helper
- Docs: mid-flight / UnexpectedFrame / ledger link in `14-terminal-bridge.md`

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | CP-001, CP-002, CP-004 | Fixed; reset |
| Adv-2 | Reverse: Debug/body leakage → mid-flight lifecycle → docs/integration drift | CP-003 | Fixed; reset |
| Adv-3 | Security/privacy (result/error/Fake Debug; no auto-send; UnexpectedFrame body-free) | None | Clean (1/2) |
| Adv-4 | Integration: exports, Fake-only path, `clipboard-win` green, C# pump still out of scope | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | `write_paste_chunks` centralizes frame apply; drop duplicate Fake helper test (session module owns it) | No extra clipboard reads | Mid-paste + unexpected-frame coverage retained | Deduped test | Fixed; reset |
| Sim-2 | Reuse `read_paste_text` / `build_paste_transaction` (no parallel chunker) | Frame Vec from existing builder — no stream refactor | Dual `is_closing` check kept (glue + write) | None | Clean (1/3)* |
| Sim-3 | Lab `paste_request_to_fake_session` thin wrapper kept | `close_after` default 0 — no auto-sudo glue impact | Diff hygiene in-scope; feature default vs `clipboard-win` | None | Clean (2/3) |
| Sim-4 | Exports via `lib.rs` sufficient | No redundant allocations beyond paste builder | Body-free error asserts; README ledger row | None | Clean (3/3) |

\*Sim-2 onward clean after Sim-1’s tests-only dedupe (no production behavior change; adversarial Adv-3/Adv-4 remained the closing pair).

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-terminal
cargo test -p wormhole-terminal --features clipboard-win
```

Result: **pass** (`wormhole-terminal` 68 default / 74 with `clipboard-win`).

## Remaining blockers

- Full paste pump orchestration (WebView2 `paste-drain` / begin / chunk / end)
  remains C# `TerminalBridge` until surface cutover.
- Live Win32 clipboard round-trip against the OS clipboard is soft-fail only in CI
  (covered under `adversarial-ledger-terminal-paste.md`).

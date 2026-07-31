# Adversarial ledger — terminal paste chunking / ClipboardHook Debug

Scope:
- `rust/crates/wormhole-terminal/src/clipboard.rs` (`HostClipboard`,
  `FakeClipboard`, `Win32Clipboard`, `read_paste_text`,
  `build_paste_transaction`, `utf8_char_chunks`)
- `rust/crates/wormhole-terminal/src/messages.rs` (`ClipboardHook` `Debug`
  redaction for paste / selection bodies)
- Docs: `docs/migration/14-terminal-bridge.md`

Out of scope: full `TerminalBridge` pump wiring; C# mutation; auto-sudo
detector (see `adversarial-ledger-clipboard-auto-sudo.md`); live OS clipboard
content asserts in CI.

Baseline (before review edits): `cargo test -p wormhole-terminal` (48 passed),
`cargo test -p wormhole-terminal --features clipboard-win` (48 passed).

Attack focus:
- CRLF kept together (C# parity); `max_chars == 0` / empty → no chunks or `Empty`
- Soft 1 MiB limit fail-closed oversize
- Paste bodies never in Debug/logs
- `clipboard-win` feature still green
- No claim auto-send of clipboard

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| TP-001 | P1 | `win32::nul_terminated_u16` / `read_unicode_text` | Oversize clipboard silently truncated at unit cap → under-limit paste instead of reject | Cap stopped at `MAX` units without NUL peek; ASCII oversize became exact 1 MiB `Ok` | **Fixed** — peek one unit past a full window → `TooLarge`; `utf16_paste_to_string` fail-closed on unit/UTF-8 oversize |
| TP-002 | P1 | `win32::read_unicode_text` | Missing NUL inside `HGLOBAL` could walk past allocation | `nul_terminated_u16` read up to `MAX` without `GlobalSize` bound | **Fixed** — `max_units = min(cap, GlobalSize/2 - 1)` so peek stays in-bounds |
| TP-003 | P2 | tests | CRLF guard unpinned at production `CLIPBOARD_PASTE_CHUNK_CHARS` boundary | Only small `max_chars=3` vector | **Fixed** — `build_paste_transaction_keeps_crlf_at_production_chunk_boundary` |
| TP-004 | P2 | tests / `ClipboardHook` | `SelectionCopy` + `TerminalMessage::Clipboard` Debug redaction unpinned | Only `PasteChunk` Debug tested | **Fixed** — selection + `TerminalMessage` Debug body-omit tests |
| TP-005 | P3 | `14-terminal-bridge.md` / module docs | No explicit “never auto-send clipboard” contract | Attack focus forbid auto-send claim | **Fixed** — page `PasteRequest` only; docs deny auto-send |
| TP-006 | — | C# `characterCount--` → 0 on `max_chars==1` CRLF | C# can empty-chunk / stall; Rust takes whole `\r\n` | Latent C#; const is 16 KiB | **Rejected** — Rust progress-preserving divergence; covered by `crlf_at_max_chars_one` |
| TP-007 | — | UTF-16 `String.Length` vs Unicode scalar chunk sizing | Astral-plane chunk byte sizes differ from C# | Documented portable approximation | **Rejected** — CRLF + surrogate integrity preserved; size drift acknowledged |
| TP-008 | — | Live Win32 round-trip vs OS clipboard | CI must not assert foreign clipboard bodies | Soft-fail constructibility only | **Rejected** — out of CI policy |

## Fixes applied

- Win32 paste read: fail-closed oversize (no truncate); `GlobalSize`-bounded UTF-16 walk; `utf16_paste_to_string` dual unit/UTF-8 cap; `GlobalUnlock` always after lock
- CRLF production-boundary + Debug redaction regression tests; lone-CR chunk edge test
- Docs: no auto-send; soft 1 MiB; GlobalSize bound note

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | TP-001, TP-003, TP-004, TP-005 | Fixed; reset |
| Adv-2 | Reverse: Win32 ownership/bounds → C# `PostClipboardPasteInChunks` → Debug leakage → feature cfg | TP-001 confirm + TP-002 (`GlobalSize`) | Fixed; reset |
| Adv-3 | Security/privacy (Debug/Display omit bodies; no auto-send docs; empty/`max_chars==0`) | None | Clean (1/2) |
| Adv-4 | Integration drift vs C# paste constants / soft 1 MiB / `clipboard-win` green | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Shared `MAX_CLIPBOARD_PASTE_UTF8_BYTES` + `utf16_paste_to_string` | Single GlobalLock; unlock on all paths via `and_then` | Doc `GlobalSize` note; body-free error asserts | Docs | Clean (1/3)* |
| Sim-2 | No new paste helpers beyond C# parity | Chunk iterator still slice-only | CRLF / empty / zero-max tests sufficient | None | Clean (2/3) |
| Sim-3 | `ClipboardHook` Debug centralized redaction | No extra clipboard reads in helpers | Diff hygiene in-scope; feature default vs `clipboard-win` | None | Clean (3/3) |

\*Sim-1 was documentation/clarity only (no behavior change) after Adv-3/Adv-4; no further implementation churn.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-terminal
cargo test -p wormhole-terminal --features clipboard-win
```

Result: **pass** (wormhole-terminal 52 default / 58 with `clipboard-win`).

## Remaining blockers

- Full paste pump orchestration (WebView2 `paste-drain` / begin / chunk / end)
  remains C# `TerminalBridge` until surface cutover. Lab session-write glue
  (`paste_request_to_session` + `FakeTerminalSession`) is closed under
  [adversarial-ledger-clipboard-paste.md](adversarial-ledger-clipboard-paste.md).
- Live Win32 clipboard round-trip against the OS clipboard is soft-fail only in CI.

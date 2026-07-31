# Adversarial ledger — clipboard + auto-sudo detector

Scope:
- `rust/crates/wormhole-ssh/src/auto_sudo.rs` (detector stub)
- `rust/crates/wormhole-ssh/src/auto_sudo_glue.rs` (session glue ↔ FakeTerminalSession;
  password out-of-band / never Debug — parent review closed in
  [adversarial-ledger-auto-sudo-session-glue.md](adversarial-ledger-auto-sudo-session-glue.md))
- `rust/crates/wormhole-terminal/src/clipboard.rs` (`HostClipboard`,
  `FakeClipboard`, `Win32Clipboard`, paste chunk helpers)
- Docs: `06-ssh-spike.md` (auto-sudo), `14-terminal-bridge.md` (clipboard + sudo notes)

Out of scope (historical detector pass): TerminalBridge pump wiring; C# mutation.
Live SSH shell / GPUI still Pending for the glue stub.

Baseline (before review edits): `cargo test -p wormhole-ssh` (45 passed + 1
ignored), `cargo test -p wormhole-terminal` (34),
`cargo test -p wormhole-terminal --features clipboard-win` (34).

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| CAS-001 | P1 | `auto_sudo::looks_like_password_prompt` | Trailing `\n` / `\r\n` made last-line `rsplit` yield `""` → missed real sudo prompts | C# `[Pp]assword…:\s*$` matches `Password: \r\n`; Rust classified Ordinary | **Fixed** — strip terminating LF (`.NET` `$`) + end-anchored match with `\s` incl. CR |
| CAS-002 | P1 | `is_password_word_at` | Matched `PASSWORD:` / `PassWord:` via full ignore-case | C# `[Pp]assword` only flexes leading `P`/`p` | **Fixed** — exact `assword` suffix; regression tests |
| CAS-003 | P2 | `SudoPromptTail::as_lossy_str` docs | Claimed “Auto sudo sends the password…” | Detector-only contract; attack focus forbid send claim | **Fixed** — wording: never accepts/stores/sends/logs password |
| CAS-004 | P2 | colon scan | First-`:` only ≠ .NET greedy backtrack | `password: foo:` should match; first-colon rejected trailing ` foo:` | **Fixed** — try each same-line colon with `\s*$` remainder |
| CAS-005 | P2 | `Win32Clipboard::write_unicode_text` | `GlobalAlloc` leaked on `GlobalLock` / `SetClipboardData` failure | Classic Win32 ownership rule | **Fixed** — `GlobalFree(Some(hglobal))` on failure paths |
| CAS-006 | P2 | tests / feature gate | Gaps: CRLF prompts, casing, mid-line non-prompts, chunk size, default vs `clipboard-win` | Attack focus lanes unpinned | **Fixed** — focused tests + win32 soft-fail constructibility |
| CAS-007 | P3 | `utf8_char_chunks(…, 0)` | `max_chars == 0` infinite-looped empty chunks | Latent; constant is 16KiB but helper is shared | **Fixed** — early `None` when `max_chars == 0` |
| CAS-008 | — | `echo password:` / `MyPassword:` false positives | Same as C# substring + end-anchor | Live C# regex vectors | **Rejected** — intentional C# parity |
| CAS-009 | — | Full driver / password send | Detector-only at that pass | Spike non-goal then | **Superseded** — `AutoSudoSessionGlue` + `FakeTerminalSession` stub landed (live shell / GPUI still Pending; parent adversarial) |
| CAS-010 | — | Unicode `.NET` `\s` beyond ASCII | PTY prompts are ASCII whitespace | CultureInvariant ASCII set sufficient | **Rejected** — no reachable PTY need |

## Fixes applied

- `wormhole-ssh` `auto_sudo`: .NET-parity end anchor + `[Pp]assword` casing + colon backtrack; Debug still length+class only; docs deny send/store/log
- `wormhole-ssh` `auto_sudo_glue`: C# state machine over existing detector; password out-of-band; FakeTerminalSession inject; Debug redacts
- `wormhole-terminal` clipboard: Win32 `HGLOBAL` free on write failure; `nul_terminated_u16` non-`'static` lifetime; `utf8_char_chunks` zero-max guard; body-free error/Debug tests; `clipboard-win` cfg coverage
- Docs `06-ssh-spike.md` / `14-terminal-bridge.md`: detector + glue stub + clipboard notes (sudo inject ≠ clipboard paste)

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | CAS-001…CAS-006 | Fixed; reset |
| Adv-2 | Reverse: C# regex vectors / CRLF / casing / Win32 ownership / feature cfg | CAS-001/002 confirm + CAS-007 (`max_chars==0`) during post-simplify delta | Fixed; reset |
| Adv-3 | Security/privacy (no body logs; Debug length+class) + false-positive mid-line + tail 512 | None | Clean (1/2) |
| Adv-4 | Integration drift vs C# `SshAutoSudoDriver` / `TerminalBridge` paste constants; default build without Win32 | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Paste cap shared via `MAX_CLIPBOARD_PASTE_UTF8_BYTES` | Tail ≤512; no extra I/O | CAS-007 zero-chunk guard; doc clarity | Yes → reset | Fixed |
| Sim-2 | No new helpers beyond C# parity matcher | Hot path stays byte scan | Substring/`MyPassword` parity test | Docs/tests only | Clean (1/3)* |
| Sim-3 | FakeClipboard vs Win32 split unchanged | Chunk iterator no alloc beyond slices | Error Display omits bodies; feature default empty | None | Clean (2/3) |
| Sim-4 | Exports in `lib.rs` sufficient | No redundant clipboard reads in helpers | Diff hygiene in-scope | None | Clean (3/3) |

\*Sim-2 added a parity regression test only (no behavior change) after Sim-1’s chunk guard; Adv-3/Adv-4 remained the closing adversarial pair. A post-Sim-1 Adv re-check accepted only CAS-007 (already fixed) then went clean twice.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ssh
cargo test -p wormhole-ssh --no-default-features
cargo test -p wormhole-terminal
cargo test -p wormhole-terminal --features clipboard-win
```

Result (detector pass): **pass** (wormhole-ssh 57 passed + 1 ignored; wormhole-terminal 40 default / 40 with `clipboard-win`).
Glue stub adds `auto_sudo_glue` tests (always on; FakeTerminalSession; no tunnels churn).

## Remaining blockers

- Live auto-sudo against a real SSH shell / WebView2 pump / GPUI (glue + FakeTerminalSession only).
- Live Win32 clipboard round-trip against the OS clipboard is soft-fail only in CI (no assert on foreign clipboard contents).
- Parent adversarial of `auto_sudo_glue` **closed** in [adversarial-ledger-auto-sudo-session-glue.md](adversarial-ledger-auto-sudo-session-glue.md).

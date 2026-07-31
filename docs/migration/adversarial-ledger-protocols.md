# Adversarial ledger — protocols (terminal / serial / SSH)

**Scope:** `rust/crates/wormhole-terminal`, `rust/crates/wormhole-serial`, `rust/crates/wormhole-ssh`, `docs/migration/06-ssh-spike.md`  
**Date:** 2026-07-31  
**Gates:** 2 clean adversarial cycles + 3 clean iterative-review-simplify cycles (post-fix)

## Baseline

- `cargo test -p wormhole-terminal -p wormhole-serial` green before fixes (6 + 7 tests).
- `cargo check -p wormhole-ssh` / `--no-default-features` green.
- Compared against `Interop/Terminal/TerminalBridgeMessages.cs`, `TerminalBridge.cs` size caps, and `Services/Serial/SerialSession.cs`.

## Findings

| ID | Sev | Location | Issue | Disposition |
|---|---|---|---|---|
| P-A1 | P1 | `wormhole-terminal` messages | No payload/wire size caps; hostile WebView could force unbounded decode allocations | **Fixed** — caps mirror `TerminalBridge` (`MAX_OUTPUT_FRAME_BYTES`, input/paste/selection/wire); `MessageTooLarge` |
| P-A2 | P2 | `wormhole-terminal` messages | Invalid-message errors embedded full hostile wire strings | **Fixed** — preview truncated to 128 chars |
| P-A3 | P2 | `wormhole-terminal` messages | Missing `barrier`/`focus`/`fatal:*` control frames vs C# bridge | **Fixed** — encode/decode + `is_page_fatal_frame` |
| P-A4 | P1 | `wormhole-serial` `TokioSerialPort::close` | `close` was a no-op; `dispose` never released the COM handle | **Fixed** — `Option<SerialStream>`; `close` takes the stream |
| P-A5 | P1 | `wormhole-serial` session write | Write/flush failures did not signal unexpected close (C# does) | **Fixed** + regression test |
| P-A6 | P1 | `wormhole-serial` DsrDtr pause/resume | Async DTR tasks could invert line state under rapid pause/resume | **Fixed** — `flow_seq` generation gate |
| P-A7 | P2 | `wormhole-serial` DSR wait | DSR query failure did not fail the session | **Fixed** + regression test |
| P-A8 | P2 | `wormhole-serial` settings builder | Hardcoded `dtr_on_open(true)` ignored `SerialOpenOptions` | **Fixed** — DTR only via open options |
| P-A9 | P1 | `wormhole-ssh` `PasswordAuth` / SOCKS | `Debug` could leak passwords into logs | **Fixed** — redacted `Debug`; SOCKS errors omit credentials |
| P-A10 | P2 | `wormhole-ssh` resize | Zero cols/rows not rejected on shell resize | **Fixed** — `validate_shell_resize` |
| P-A11 | P2 | `wormhole-ssh` host key | Accept-any policy not pinned by a testable hook | **Fixed** — `accept_server_host_key` + tests |
| P-A12 | P3 | paste-begin byte count | Leading zeros accepted (`01`) unlike other canonical ints | **Fixed** |
| P-R1 | — | Terminal bridge high/low watermark | Full pump backpressure lives in C# `TerminalBridge`, not the codec/trait spike | **Rejected** — out of crate spike scope; channel stub already bounded |
| P-R2 | — | SOCKS5 CONNECT implementation | Still stub (`Socks5NotImplemented`) | **Rejected** — documented non-goal of `06-ssh-spike.md` |
| P-R3 | — | Mark/Space / 1.5 stop bits OS mapping | Approximated (Mark→Odd, Space→Even, 1.5→Two) | **Accepted residual** — domain values preserved; documented in settings |

## Simplify deltas (after adversarial)

- Deduplicated canonical integer parsing via `ensure_canonical_unsigned_text`.
- Enum parity tests use `as_i32()`.
- Serial write-success regression asserts recorded bytes.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-terminal -p wormhole-serial -p wormhole-ssh
cargo check -p wormhole-ssh
cargo check -p wormhole-ssh --no-default-features
```

**Result (final):** terminal 15, serial 15, ssh 7 passed + 1 ignored (live server); both SSH feature modes check clean.

## Gate confirmation

- Adversarial clean passes: **2** (independent orderings; renewed after simplify edits).
- Iterative-review-simplify clean passes: **3**.
- No accepted non-blocked findings remain.

# Adversarial ledger — MCP clean-shutdown vs WebView2 flush ordering Fake glue

**Scope:**
- `rust/crates/wormhole-mcp/src/shutdown_order.rs` (+ re-exports in `lib.rs` / `Cargo.toml` description)
- Docs: `07-tunnels-mcp.md`, `feature-matrix.md`, `README.md` ledger index; this ledger

**Out of scope:** Live WebView2 `CloseAllForShutdownAsync` / `CaptureBitwardenStorageAsync`;
live MCP Streamable HTTP bind; GPUI / WinUI `MainWindow` wiring; C# `PrepareForProcessExitAsync`
mutations; contested crates (`wormhole-http`, `wormhole-app` composition root).

**Compared against:** C# `MainWindow.PrepareForProcessExitAsync` surfaces
(`WebBrowserView.CloseAllForShutdownAsync`, Bitwarden storage capture, `IMcpServerHost.StopAsync`,
`CloseAllSessionsAsync`) + user brief / interop-inventory (“Bitwarden flush before exit”).

**Lab invariant (Fake glue):** explicit
`FlushHttpWebViews` → `FlushBitwardenWebView` → `StopMcpServer` → `CloseAllSessions`.
WebView/Bitwarden flush steps must precede MCP stop; wrong order →
[`ShutdownOrderError`] / test failure. C# source today runs bounded MCP stop before
`CloseAllForShutdownAsync`; the Lab Fake records the **target** ordering for GPUI shell
composition (do not mirror the inverted C# call order in tests).

**Authority:** full adversarial-review-fix (edit in scope; no child agents)  
**Baseline:** `cargo test -p wormhole-mcp` — 58 lib + 19 integration (pre-shutdown-order)  
**Final:** 69 lib + 19 integration green; `--no-default-features` check green  

Context7 MCP unavailable in this environment.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-mcp` | **pass** (69 unit + 19 integration) |
| `cargo check -p wormhole-mcp --no-default-features` | **pass** |

---

## Accepted findings and fixes

| ID | Sev | Location | Invariant / evidence | Fix | Verification |
|---|---|---|---|---|---|
| MSO-01 | P1 | `validate_shutdown_order` | Subsequence matcher allowed `StopMcpServer` before flushes when later steps “caught up” | Strict next-step match against [`CSHARP_PARITY_SHUTDOWN_ORDER`] | `mcp_before_webview_flush_fails_validation`, `mcp_stop_between_http_and_bitwarden_fails` |
| MSO-02 | P2 | `mcp_stopped_before_webview_flush` | Helper only compared first flush vs MCP; missed Bitwarden-after-MCP | Detect any flush step **after** `StopMcpServer` index | `bitwarden_after_mcp_stop_fails_validation` |
| MSO-03 | P2 | `prepare_for_process_exit` | MCP stop errors must not skip recorder / reorder flushes | Record `StopMcpServer` after bounded `stop()` attempt; swallow errors like C# | `prepare_swallows_mcp_stop_failure_still_records_order` |
| MSO-04 | P3 | docs / matrix | MCP shutdown-order row still Pending | Update `07-tunnels-mcp.md`, feature-matrix, README index | doc review + tests green |
| MSO-05 | P3 | `Debug` | Glue must not leak bearer tokens / URIs | Counts/flags only on `FakeAppExitShutdownGlue` | `debug_omits_bearer_and_uri_wording` |

---

## Rejected candidates

| Candidate | Reason |
|---|---|
| Mirror C# source call order (MCP `StopAsync` before `CloseAllForShutdownAsync`) | User brief + Lab invariant require WebView/Bitwarden flush **before** MCP stop in the Fake recorder |
| Wire into `wormhole-app` composition root | `wormhole-mcp` placement is enough; shell wiring is a later milestone |
| Live WebView2 / MCP HTTP in unit tests | Explicit non-goal; `HttpPlaceholderMcpHost` only |
| Collapse Bitwarden flush into HTTP flush step | Bitwarden `CaptureBitwardenStorageAsync` is a distinct parity surface in C# |
| Fail `prepare_for_process_exit` on MCP `stop` error | C# swallows MCP shutdown failures — recorder stays deterministic |
| Add `url` / WebView2 crates | No new deps; pure step recorder |
| Mutate C# `MainWindow.xaml.cs` | Out of scope |

---

## Adversarial clean passes (2 required)

### Clean pass 1 — order: contract → boundary → state → security

- Canonical four-step order pinned; strict validator rejects MCP-before-flush and sessions-before-MCP.
- `prepare_for_process_exit` always records flushes before MCP attempt; MCP timeout/error still records step.
- Partial prefix / empty sequence allowed; duplicates rejected.
- Debug omits bearer/token/URI wording; no live WebView2/MCP HTTP.
- **Accepted findings:** MSO-01..03 fixed pre-pass; none new.

### Clean pass 2 — order: test resistance → integration drift → operability

- 11 focused `shutdown_order` tests cover wrong-order oracles + placeholder host stop.
- `bind` / `approval` / `capability` / `session_registry` / `rmcp` integration tests untouched.
- `--no-default-features` compiles shutdown helpers without `rmcp`.
- **Accepted findings:** none.

`adversarial_clean_passes = 2`.

---

## Iterative-review-simplify (3 clean cycles)

| Cycle | Themes | Outcome |
|---|---|---|
| 1 | Reuse `McpServerHost` + `HttpPlaceholderMcpHost`; single glue struct | Clean |
| 2 | Strict validator vs subsequence; helper detects post-MCP flush | Clean (MSO-01/02) |
| 3 | Docs/matrix/ledger parity; test names as attack oracles | Clean |

`simplify_clean_passes = 3`. No further simplify delta.

---

## Regression tests added (`shutdown_order.rs`)

- `parity_shutdown_records_canonical_order`
- `mcp_before_webview_flush_fails_validation`
- `bitwarden_after_mcp_stop_fails_validation`
- `mcp_stop_between_http_and_bitwarden_fails`
- `close_sessions_before_mcp_stop_fails`
- `duplicate_step_fails_validation`
- `empty_recorded_sequence_is_valid`
- `partial_prefix_is_valid`
- `prepare_for_process_exit_records_order_and_stops_placeholder`
- `prepare_swallows_mcp_stop_failure_still_records_order`
- `debug_omits_bearer_and_uri_wording`

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-mcp
cargo check -p wormhole-mcp --no-default-features
```

**Result:** 69 unit + 19 integration pass; `--no-default-features` check pass.

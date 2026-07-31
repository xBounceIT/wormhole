# Adversarial ledger — WebView2 / wry surface-lab gates 3–5

Scope:
- `rust/crates/wormhole-surface-win/` (`webview` feature, child host, overlay controller, owner window)
- `rust/crates/surface-lab/` gates 3–5 + webview feature wiring
- `docs/migration/01-surface-lab.md` (gates 3–5 notes only)

Out of scope: C# app; RDP COM beyond build-break `unsafe extern` + existing GWLP_HWNDPARENT comments.

Baseline (before review edits): `cargo check`, `cargo check -p wormhole-surface-win --features webview`, `cargo check -p surface-lab --features webview` green.

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| WV-001 | P1 | `webview/host.rs` `set_bounds` | Degenerate bounds hid the controller; later non-degenerate bounds did not restore `desired_visible` | Layout ticks can briefly emit 0×N; host stayed hidden | **Fixed** — `desired_visible` + `sync_visibility`; create-time hide when degenerate |
| WV-002 | P1 | `webview/host.rs` inbox | Unbounded `Vec` IPC queue (no backpressure / size cap) | Hostile flood grows memory without bound | **Fixed** — `IpcInbox` cap 256 + 64KiB max; drop counters |
| WV-003 | P1 | `gate05_xterm.rs` | Raw `println!` of IPC bodies (terminal/clipboard may carry secrets) | Gate logged full `msg` | **Fixed** — `summarize_ipc_for_log` redacts `d:`/`b:`/`paste…` |
| WV-004 | P1 | `post_host_message` | Weak JS escaping (`'`/`\` only); newline / U+2028 breakout | Inject via host message | **Fixed** — `escape_js_string` double-quoted literal |
| WV-005 | P2 | `unique_user_data_dir` | Nanos-only path; no Drop cleanup | Concurrent collision risk; temp UDF leak | **Fixed** — pid+nanos+seq; `UserDataDirGuard` best-effort remove |
| WV-006 | P2 | host lifecycle | No `BrowserProcessExited` / recreate hooks | Architecture requires recreate + generation tokens | **Fixed** — Environment5 hook → `needs_recreate` + generation bump |
| WV-007 | P2 | `OverlayStackController` | Policy recorded but no visibility helper for chrome airspace | Gate 4 attack focus | **Fixed** — `effective_webview_visibility`; gate 4 applies to host when Runtime present |
| WV-008 | P2 | tests | Almost no Runtime-free regression coverage for webview helpers | Only zorder/broker stubs | **Fixed** — ipc/assets/env/host/bounds/zorder unit tests |
| WV-009 | P3 | `docs/migration/01-surface-lab.md` | Stale “stub only”; missing `--features webview` | Doc vs impl drift | **Fixed** — webview run + gates 3–5 notes |
| WV-010 | P2 | create path | Create with degenerate bounds left wry controller visible while `is_visible()==false` | Field/controller desync | **Fixed** — `set_visible(false)` after build when ineffective |
| WV-011 | — | shared CoreWebView2Environment | Always-unique UDF (no shared hardening env yet) | Spec allows shared later | **Rejected** — unique is safer for cert/proxy isolation at this spike |
| WV-012 | — | `ServerCertificateErrorDetected` | AlwaysAllow COM not wired in wry host | Future HTTPS path | **Partial** — pure `cert_policy_to_webview2_behavior` + create-path hook comment; COM subscription still blocked (lab ≠ production AlwaysAllow) |
| WV-013 | — | CoUninitialize | LabOwnerWindow never CoUninitialize | Process-lifetime lab STA | **Rejected** — multiple owners share thread; safe for lab |
| WV-014 | — | Full TerminalBridge | Gate 5 is echo stub / Assets host only | Out of surface-win spike | **Rejected** — lives in `wormhole-terminal` |
| WV-015 | build | `rdp/sentinel.rs` | Edition 2024 requires `unsafe extern` | Broke default `cargo check` mid-review | **Fixed** — minimal `unsafe extern "system"` (not RDP COM rewrite) |

## Fixes applied

- `webview/{host,ipc,assets,env,mod}.rs` — isolation, IPC, cert/proxy arg docs, BrowserProcessExited, drop order
- `zorder.rs` — `effective_webview_visibility` + tests
- `bounds.rs` — `SEED` + degeneracy test
- `surface-lab` gates 3–5 — degenerate restore, overlay hide, redacted IPC, recreate hook
- `docs/migration/01-surface-lab.md` — webview feature / gates 3–5
- `rdp/sentinel.rs` — `unsafe extern` only

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | WV-001…WV-010, WV-015 | Fixed; reset |
| Adv-2 | Tests-as-oracles → drop order → DPI → gate wiring → feature flags | WV-010 (create visibility) during re-pass | Fixed; reset |
| Adv-3 | Post-simplify delta: Drop field order (hook first, UDF last), IPC redact, feature deps | None | Clean (1/2) |
| Adv-4 | Reverse: security/PII logs → malformed IPC → OverlayStack → wry-not-gpui-wry spot-check | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Extract ipc/assets/env | Inbox `remove(0)` OK at 256 | Move BrowserExitHook Drop + field order; remove unused `Default` | Yes → reset | Fixed |
| Sim-2 | Gate PhysicalBounds dup — keep for clarity | No hot-path I/O | Drop order documented; dead_code allow on hook field | None | Clean (1/3) |
| Sim-3 | No missed local helpers for webview | No redundant env create in unit tests | Docs/tests aligned; feature flags reference real deps | None | Clean (2/3) |
| Sim-4 | Same | Same | Diff hygiene in-scope | None | Clean (3/3) |

Simplify Sim-1 changed code → Adv-3/Adv-4 re-run completed clean; Sim-2…4 clean with no further edits.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo check
cargo check -p wormhole-surface-win --features webview
cargo check -p surface-lab --features webview
cargo test -p wormhole-surface-win --lib
cargo test -p wormhole-surface-win --features webview --lib
```

Result: **pass** (default check green; webview lib tests 28 passed including webview helpers). Interactive smokes still need WebView2 Runtime + optional xterm vendor under `Assets/web`.

## Remaining blockers

- **xterm vendor**: full gate-5 UI needs staged `Assets/web/vendor/xterm` (+ addon-fit, `bridge.js`); lab falls back to echo stub.
- **WebView2 Runtime**: Evergreen Runtime required for live gates 3–5 HWND smokes / `SURFACE_LAB_INTERACTIVE`.
- **WV-012**: COM `ServerCertificateErrorDetected → AlwaysAllow` still unwired on
  `ChildWebViewHost::create` / surface-lab (**lab ≠ production**). Pure mapping
  `cert_policy_to_webview2_behavior(HttpCertPolicy) → Default|AlwaysAllow` exists
  under `webview` + unit tests; unique UDF already prevents policy leak when COM
  is added.

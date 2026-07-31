# 19 — Diagnostics + soak / benchmark harness stubs

**Status:** `wormhole-diagnostics` crate green · `--diagnostics` on `surface-lab` · soak **runner glue + placeholders** (no live soak / hardware gate pass claimed)  
**Date:** 2026-07-31  
**Crate:** `rust/crates/wormhole-diagnostics`  
**Adversarial ledgers:** [adversarial-ledger-diagnostics.md](./adversarial-ledger-diagnostics.md) (report/sidecars) · [adversarial-ledger-diagnostics-runner.md](./adversarial-ledger-diagnostics-runner.md) (`SoakRunner` glue)

---

## Goals

1. **Support diagnostics** — a secrets-free environment snapshot operators can paste into bug reports.
2. **Soak / benchmark stubs** — documented harness hooks and ignored/live placeholders so long-running stability work has a home without blocking CI.

Non-goals: live HTTP/GitHub phone-home, reading log bodies, Credential Manager / DPAPI / SQLite dumps, spawning sidecars, claiming soak or hardware gates passed.

---

## Diagnostics report (`wormhole-diagnostics`)

| Field | Source | Notes |
|---|---|---|
| `app_version` | `CARGO_PKG_VERSION` of `wormhole-diagnostics` | Rust migration crate version (not WinUI 0.9.0) |
| `rustc_version` | `rustc -V` (optional) | Omitted when rustc is not on `PATH` |
| `arch` / `os` | `std::env::consts` | e.g. `x86_64` / `windows` |
| `webview2` | Registry `pv` under EdgeUpdate Clients `{F3017226-…}` | Best-effort; soft failures (no panic); **no** COM `CreateCoreWebView2Environment` |
| `sidecars` | `wormhole_tunnels::sidecar::{candidate_paths, locate_among}` + secrets-dir filter | Presence only — never spawn / never read stdin JSON; never search `%LOCALAPPDATA%\Wormhole\{keys,tunnels}` |
| `logs_dir` | `%LOCALAPPDATA%\Wormhole\logs` | Path only (mirrors `wormhole_app::logs_dir`) |

### Hard rule: no secrets

The report **must not** include:

- passwords, tokens, CredMgr keys, DPAPI file contents
- tunnel secret blobs / OpenVPN profile text
- paths under `%LOCALAPPDATA%\Wormhole\keys` or `...\tunnels`
- log file bodies (path is enough)
- environment variable values that commonly hold secrets (`BW_SESSION`, etc.)

Unit tests assert the formatted text has no unredacted `password=` / `token=` / `secret=` assignments and no `Wormhole\keys` / `Wormhole\tunnels` path segments.

### How to print

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo run -p surface-lab -- --diagnostics
```

`--diagnostics` prints the report and exits (skips gate smokes / GPUI boot).

Programmatic:

```rust
use wormhole_diagnostics::{collect_report, format_report};
let text = format_report(&collect_report());
```

---

## Soak / benchmark harness

Documented stubs live in `soak` and lifecycle glue in `runner` (crate-root re-exports):

| Item | Behavior | CI |
|---|---|---|
| `SOAK_SESSION_HOURS` (= 8) | Constant for a future multi-hour live session soak | n/a |
| `soak_eight_hour_session_placeholder` | `#[ignore]` test — asserts the constant; does **not** sleep 8h | skipped unless `--ignored` |
| `quad_pane_layout_stress` | Fast pure-state stress of a local 4-pane model (mirrors `wormhole_ui::MAX_PANES`) | **runs** in `cargo test` |
| `SoakRunner` | Thin **start / cancel / poll / status / report** glue over the helpers | **runs** in `cargo test` |
| `FakeClock` / `SystemClock` | Injected monotonic clock; `FakeClock::set` never rewinds; tests complete planned duration without real wait | unit-only |

```rust
use std::time::Duration;
use wormhole_diagnostics::{FakeClock, SoakPhase, SoakRunner, SOAK_SESSION_HOURS};

let clock = FakeClock::new();
let mut runner = SoakRunner::new(clock.clone()); // planned = SOAK_SESSION_HOURS
runner.start().expect("start");
runner.poll(); // runs quad_pane_layout_stress batch while Running
clock.advance(Duration::from_secs(SOAK_SESSION_HOURS * 3600));
runner.poll();
assert_eq!(runner.status().phase, SoakPhase::Completed);
let text = runner.report().format(); // secrets-free (no hosts / creds / keys paths)
```

```powershell
# Default (includes fast quad-pane stress + SoakRunner FakeClock tests)
cargo test -p wormhole-diagnostics

# Manual ignored placeholder (still does not block 8 hours — stub only)
cargo test -p wormhole-diagnostics -- --ignored soak_eight_hour_session_placeholder
```

### Gate status (explicit)

- **Not claimed:** multi-hour live soak pass, RSS/handle leak budgets, WebView2 process-storm gates, RDP HWND leak gates, or any hardware lab sign-off.
- **Claimed:** unit/stub harness + start/cancel/status/report glue with `FakeClock` exists; `cargo test -p wormhole-diagnostics` (non-ignored) is green; `--diagnostics` prints a secrets-free report; soak `report().format()` stays secrets-free.

### Future soak (not implemented)

When a live harness exists:

1. Boot GPUI shell (or surface-lab) with N panes / sessions for `SOAK_SESSION_HOURS`.
2. Record RSS / handle counts / broker surface counts at start/end.
3. Fail on panic, WebView2 process exit storms, or RDP HWND leaks.
4. Keep the test `#[ignore]` so CI stays minutes, not hours.

### Future micro-benchmarks (not implemented)

Candidates (criterion or custom): inheritance resolve N nodes, SFTP queue serialize, SOCKS5 DOMAINNAME encode, pane layout tick. Out of scope for this stub.

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-diagnostics
cargo run -p surface-lab -- --diagnostics
```

Context7 MCP was unavailable at authoring time; dependencies use existing workspace pins (`windows`, `wormhole-tunnels`) only — no new crates.io deps. The quad-pane soak deliberately does **not** depend on `wormhole-ui` so diagnostics stays buildable while the shell crate evolves.

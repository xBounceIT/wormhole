# Adversarial ledger — terminal bridge + gate05 xterm

Scope:
- `rust/crates/wormhole-terminal/` (codec, backpressure, session trait)
- `rust/crates/surface-lab/` `gate05_xterm` + Assets/web resolution
- `rust/crates/wormhole-surface-win/` custom-protocol serve + IPC summarize (paste redaction)
- `docs/migration/14-terminal-bridge.md` (+ gate-5 notes in `01-surface-lab.md` as needed)

Out of scope: C# mutation; full TerminalBridge pump; committing `Assets/web/vendor/` binaries.

Baseline (before review edits): `cargo test -p wormhole-terminal` (22 passed),
`cargo check -p surface-lab --features webview` green.

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| TB-001 | P1 | `webview/assets.rs` / `host.rs` | Custom protocol served any host; no virtual-host gate | Handler used `request.uri().path()` only | **Fixed** — `serve_protocol_request` / `is_wormhole_virtual_host` require `wormhole.localhost` (or `wormhole` scheme) |
| TB-002 | P1 | `normalize_protocol_path` | `..` / absolute / drive paths only caught after join+canonicalize | `/../../…`, `/C:/…` reached filesystem join | **Fixed** — `is_safe_relative_asset_path` rejects before join; tests |
| TB-003 | P1 | `messages.rs` `invalid_message` | Byte slice preview could panic on UTF-8 char boundary | Hostile wire with multibyte at index 128 | **Fixed** — char-boundary clamp + regression test |
| TB-004 | P2 | `decode_input` | Empty / colon-bearing input (`b:1:u:`, `b:1:u:…:late`) accepted vs C# `TryParseInputFrame` | C# tests reject those frames | **Fixed** — reject empty payload and `:` in b64; encode path rejects empty too |
| TB-005 | P2 | `OutputBackpressure::with_watermarks` | Allowed `high == low` (collapsed hysteresis); C# requires `low < high` | `TerminalOutputPump` ctor message | **Fixed** — `assert!(high > low)` + `should_panic` test; exact watermark tests |
| TB-006 | P2 | gate05 / `echo_stub_html` | Fallback stub not clearly labeled as non-xterm | Interactive HTML said only “echo stub ready” | **Fixed** — on-page NOTE + Fetch-WebAssets.ps1 path |
| TB-007 | P2 | `find_assets_web` | Any `terminal.html` on relative probe paths accepted | Hostile cwd could satisfy probe | **Fixed** — `is_assets_web_layout` requires `Assets/web` leaf names |
| TB-008 | P2 | messages API | No `TryParseScopedGeometry` parity helper | C# rejects sub-min usable resize; raw decode alone | **Fixed** — `try_parse_scoped_geometry` + golden reject vectors |
| TB-009 | P2 | tests | Missing C# malformed input/ack/paste rejection coverage | Vectors only in C# tests | **Fixed** — `csharp_rejects_malformed_input_and_ack_frames` + classify extras |
| TB-010 | P2 | `classify_sessionless_replay_message` | Double `decode_message` on up to 8MiB wires | DoS/CPU; also easy to mishandle `PageFatal` | **Fixed** — single decode; `PageFatal` / malformed `fatal:` → RecoverableFatal |
| TB-011 | — | Percent-encoded `%2e%2e` | Speculative if runtime decoded after our checks | Canonicalize 404 / literal name | **Rejected** — fail-closed via missing file or `..` after decode |
| TB-012 | — | Full pump / `BuildSessionlessReplayMessages` | Not in Rust yet | Doc: pump still C# | **Rejected** — out of scope |
| TB-013 | — | IPC over-redacts `a:`/`r:` | ACKs/resizes logged as opaque | Existing policy | **Rejected** — preserve redaction posture |
| TB-014 | P3 | `14-terminal-bridge.md` | Stale vs virtual-host / geometry helper | Doc drift | **Fixed** — doc update in simplify |

## Fixes applied

- `wormhole-terminal`: input parity, classify single-decode, UTF-8-safe errors, watermark invariant, `try_parse_scoped_geometry`, expanded golden/malformed tests
- `wormhole-surface-win` webview: virtual-host serve, path hardening, Assets/web layout check, clear echo stub, `paste-begin` redact assertion
- `surface-lab` gate05: layout-gated manifest fallback via `is_assets_web_layout`
- `docs/migration/14-terminal-bridge.md`: gate-5 / crate surface notes

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | TB-001…TB-009 | Fixed; reset |
| Adv-2 | Reverse: security/UTF-8 → classify DoS → PageFatal disposition → IPC paste | TB-003, TB-010 (classify rewrite) | Fixed; reset |
| Adv-3 | Post-fix: golden classify matrix, host/path tests, watermark edges | None | Clean (1/2) |
| Adv-4 | Integration drift vs C# TerminalBridgeMessagesTests + redaction spot-check | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Gate05 uses shared `is_assets_web_layout` | Classify already single-decode | Doc comment accuracy; `paste-begin` redact assert; doc 14 | Yes → reset | Fixed |
| Sim-2 | No new helper duplication | No hot-path I/O in codec tests | Watermark/assert docs aligned | None | Clean (1/3) |
| Sim-3 | IPC/assets exports sufficient | No redundant canonicalize in happy path beyond serve | Redaction + stub NOTE preserved | None | Clean (2/3) |
| Sim-4 | Same | Same | Diff hygiene in-scope; vendor still fetch-script path | None | Clean (3/3) |

Sim-1 was docs/tests only (no behavior change) → Adv-3/Adv-4 remained the closing adversarial pair; no further implementation churn.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-terminal
cargo test -p wormhole-surface-win --features webview --lib
cargo check -p surface-lab --features webview
```

Result: **pass** (wormhole-terminal 28 tests; wormhole-surface-win webview lib tests green including assets/IPC; surface-lab webview check green).

## Remaining blockers

- **xterm vendor**: full gate-5 UI still needs `scripts/Fetch-WebAssets.ps1` (gitignored vendor).
- **WebView2 Runtime**: live HWND smokes / `SURFACE_LAB_INTERACTIVE` need Evergreen Runtime.
- **Pump orchestration**: remains in C# `TerminalBridge` until surface cutover.

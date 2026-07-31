# Adversarial ledger — UI / VNC / HTTP (+ AppServices wiring)

Scope:
- `rust/crates/wormhole-ui/`
- `rust/crates/wormhole-vnc/`
- `rust/crates/wormhole-http/`
- `rust/crates/wormhole-app/` AppServices optional `ui` / `vnc` / `http` wiring only
- `docs/migration/08-ui.md`, `09-vnc.md`, `10-http.md`

Out of scope: C# production code; tunnels/surface rewrites (unless one-line compile break).

Baseline (before review edits): `cargo test -p wormhole-ui -p wormhole-vnc -p wormhole-http -p wormhole-app` green (6 + 10 + 11 + 3 tests). Context7 MCP unavailable in this environment.

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| UVH-001 | P1 | `workspace.rs` `close_pane` | Pane ids renumbered `0..n-1` on close → tab `pane` assignments stale / silently remapped | Close pane 0 with tabs on pane 2 left tab pointing at missing / wrong id | **Fixed** — stable `PaneId` slots; split reuses lowest free id |
| UVH-002 | P1 | `shell.rs` | No coordinated close: workspace close did not clear tab assignments | Tab/workspace race attack focus | **Fixed** — `ShellState::close_pane` + `assign_tab_pane` (validates pane exists) |
| UVH-003 | P1 | `http` `build_forwarder_target` / SOCKS | Port `0` accepted for forwarder / SOCKS loopback | `https://127.0.0.1:0/` / `socks5://127.0.0.1:0` | **Fixed** — reject port 0; `Socks5Proxy::loopback` → `Result` |
| UVH-004 | P1 | `uri.rs` `validate_host` | Malformed hosts (`path`, `@`, embedded port, half brackets, whitespace) built into navigate URIs | Injection / bad authority strings | **Fixed** — `validate_host` + `HttpError::InvalidHost` |
| UVH-005 | P1 | `uri.rs` scheme | Arbitrary scheme (`javascript`, `https://evil`) accepted | Hostile `build_navigate_uri` caller | **Fixed** — only `http` / `https`; `InvalidScheme` |
| UVH-006 | P2 | `theme.rs` CSS helpers | Returned hardcoded `&'static str`, ignored `self` fields | Custom tokens would lie in CSS | **Fixed** — `to_css(rgb)` from field values |
| UVH-007 | P2 | `auth.rs` password length | Counted Unicode scalars, not DES **bytes** (RFC 6143) | Multi-byte passwords over 8 bytes accepted | **Fixed** — byte limit; `MAX_VNC_PASSWORD_BYTES`; char-boundary `from_lossy` |
| UVH-008 | P2 | `VncConnectOptions` | Need explicit audit that Debug never prints secret | Attack focus: no secret in Debug/Display | **Fixed** — custom Debug + redaction regression tests; no `Display` on `VncPassword` |
| UVH-009 | P2 | `HttpConnectionTarget::new` | SOCKS + `original_uri` both set → inconsistent route | Public constructor allowed both | **Fixed** — socks clears `original_uri`; route exclusive |
| UVH-010 | P2 | `lib` / docs / app | `effective_ignore_cert` not exported; docs drifted; app `--no-default-features` warn | Integration / feature-flag attack focus | **Fixed** — export + doc notes + smoke uses storage/secrets under no-default |
| UVH-011 | P3 | `protocol` / tests | Empty security offer / unknown version weakly pinned | Test resistance | **Fixed** — empty-offer + version negative tests |
| UVH-012 | — | IDN / punycode hosts | No ToASCII conversion | C# `UriBuilder` IDN | **Rejected** — deferred; forbidden-char reject still applies |
| UVH-013 | — | `VncPassword` zeroize-on-drop | Secret lingering in `String` | Memory scrubbing | **Rejected** — scaffold; no engine I/O yet |
| UVH-014 | — | IPv6 zone ids (`%eth0`) | Rejected by `looks_like_ipv6` | Rare for appliance URLs | **Rejected** — out of v1 navigate surface |
| UVH-015 | — | Raw `TabStrip::assign_pane` | Still allows any `PaneId` | Prefer `ShellState::assign_tab_pane` | **Rejected** — documented; coordinated API is the contract |

## Fixes applied

- `wormhole-ui`: stable panes, shell coordination, theme CSS from fields, regressions
- `wormhole-vnc`: byte-limited redacted passwords, options Debug, negotiate/empty-offer tests
- `wormhole-http`: host/scheme/port validation, SOCKS↔forwarder exclusivity, ignore-cert export + docs
- `wormhole-app`: http builder smoke; no-default-features hygiene
- docs `08-ui.md` / `09-vnc.md` / `10-http.md` aligned

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-1 | Contract → boundary → state → concurrency → security → integration → perf → tests | UVH-001…011 | Fixed; reset |
| Adv-2 | Reverse: security/PII → feature flags → tests-as-oracles → routing exclusivity | UVH-005 (scheme), UVH-009 (socks/original) during re-pass | Fixed; reset |
| Adv-3 | Forward lanes on post-fix surface | None | Clean (1/2) |
| Adv-4 | Reverse: Debug/Display secrets, pane≤4, SOCKS vs forwarder, `--no-default-features` | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Skip `build_target_uri` one-liner abstraction | No hot-path I/O | Drop redundant `' '` match arm; `contains(':')` | Yes → reset | Fixed |
| Sim-2 | No missed local helpers | Same | Remove unused `PaneId::is_slot` | Yes → reset | Fixed |
| Sim-3 | Same | Same | No further validated issues | None | Clean (1/3) |
| Sim-4 | Same | Same | Feature/docs/tests aligned | None | Clean (2/3) |
| Sim-5 | Same | Same | Diff hygiene in-scope | None | Clean (3/3) |

Simplify changed code → Adv-3/Adv-4 re-run completed clean; Sim-3…5 clean with no further edits.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ui -p wormhole-vnc -p wormhole-http -p wormhole-app
cargo test -p wormhole-ui --no-default-features
cargo test -p wormhole-vnc --no-default-features
cargo test -p wormhole-app --no-default-features
# Optional heavy features (checked during review):
# cargo check -p wormhole-ui --features gpui
# cargo check -p wormhole-vnc --features engine
```

Result: **pass** — ui 15, vnc 14, http 19, app 3 (default); no-default-features green for ui/vnc/app.

## Remaining blockers

- Live GPUI window / Fluent chrome still deferred (`gpui` feature is presence-only).
- Live VNC TCP/`vnc-rs` engine still deferred (`engine` feature is presence-only).
- WebView2 hosting for HTTP targets remains in `wormhole-surface-win` (not this scope).
- Context7 MCP was unavailable; pins left as previously documented in migration notes.

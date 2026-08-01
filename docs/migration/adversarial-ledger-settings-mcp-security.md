# Adversarial ledger — Settings MCP toggle + Security VM glue

**Scope:** `rust/crates/wormhole-ui/src/settings/mcp.rs` (new, feature `mcp`),
`rust/crates/wormhole-ui/src/settings/security.rs` (new), registration + re-exports
in `settings/mod.rs` and `lib.rs` (`pub use settings` blocks); `wormhole-ui/Cargo.toml`
(optional `wormhole-mcp` dep, `mcp` feature); `rust/Cargo.toml` workspace
`wormhole-mcp default-features = false`; `wormhole-app/Cargo.toml` `mcp` feature now
explicitly `wormhole-mcp/rmcp`.

**Out of scope:** live MCP server start/stop; WinRT Hello consent; `GetLastInputInfo`
(idle sampling lives in `wormhole-secrets-win::os_idle`); GPUI Settings pages.

**Compared against:** C# `ViewModels/SettingsViewModel.cs` MCP section
(`_suppressMcpToggle` re-entrancy guard, port double, token reveal/copy/regenerate)
and Security section (`IdleTimeoutOptions` = `[null, 1, 5, 15, 30, 60]`,
`TimeoutMinutesToIndex`, reauth-on-change semantics); `McpServerHost.cs` constants;
`wormhole-secrets-win::idle_lock::AppIdleLockGlue::should_lock` fail-closed table.

**Authority:** full adversarial-review-fix (reviewer subagent; parent re-verified)  
**Baseline:** wormhole-ui lib **443** (default) / **462** (mcp) — see ledger for pre-wave counts  
**Final:** wormhole-ui lib **443** (default) / **462** (mcp) + **17** doc + **5** integration; `wormhole-app --lib` check green

**Attack focus:** re-entrancy (nested toggle while applying, revert without re-fire),
persist-failure revert paths (double-save), hostile port/timeout inputs, token leakage
in any Debug/error render, feature-flag isolation (default build unchanged), C# parity
of presets/defaults/guards.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-ui` / `--features mcp` | **pass** (443 / 462 lib) |
| `cargo check -p wormhole-ui [--features mcp]` / `cargo check -p wormhole-app --lib` | **pass** |
| `git diff --check` (scoped) | **pass** |

---

## Accepted findings and fixes

| ID | Sev | Finding | Fix |
|---|---|---|---|
| F-1 | P3 | `security.rs` claimed C# maps unmatched stored timeout to "Never"; C# `TimeoutMinutesToIndex` maps unknown to index 3 = **15** | Comment corrected; deliberate clamp-to-None documented as lab decision |
| F-2 | P3 | Unused `solid_store` test helper | Removed |
| F-3 | P2 | Security persist-failure revert paths (mode/fallback/timeout) had zero coverage | 3 fail-injecting-store tests |
| F-4 | P2 | Failed-apply + nested-toggle-while-guarded (exact `_suppressMcpToggle` scenario) unpinned | Test: nested flip ignored, apply fails, revert without re-apply, guard released |
| F-5 | P2 | `set_port` persist-failure revert unpinned | Test (field+doc keep prior port, error surfaced, retry succeeds) |
| F-6 | P3 | Glue lacked `conceal_token` (C# hide path) | Added + test through Glue with UI-state refresh |
| F-7 | P3 | Hostile value via `reload` (not just construction) unpinned in both VMs | 2 tests: last valid kept, hostile never adopted, doc repaired on next save |
| F-8 | P3 | Glue cached UI state after a failed apply unpinned | Test (reverted `enabled`, guard released, error copied) |
| S-1 | P3 | Duplicate `ReentrantFailingHost` == `ReentrantHost` + scripted inner | Deduped to existing struct |

### Rejected candidates

Stop-failure non-revert asymmetry (criterion requires unconditional revert); C# `??= 15`
timeout defaulting on mode change (preserving user "Never" safer, out of criteria);
load-modify-save atomicity (single-threaded VM, codebase convention).

---

## Test command

```powershell
cd rust
cargo test -p wormhole-ui
cargo test -p wormhole-ui --features mcp
cargo check -p wormhole-ui --features mcp
cargo check -p wormhole-app --lib
```

**Counts:** mcp module **19** tests, security module **15** tests (post-review totals).
# Adversarial ledger — MCP tool runner + live open-tab scan glue

**Scope:** `rust/crates/wormhole-mcp/src/tool_runner.rs` (new), `src/live_tab_scan.rs` (new), `src/lib.rs` registration/re-exports.

**Out of scope:** live SSH `ShellCommandRunner` / rmcp HTTP dispatch (product host wires the seams); closed ledgers `mcp-approval-gate`, `mcp-session-registry`, `mcp-tools-list`, `mcp-shutdown-order`.

**Compared against:** C# `Services/Mcp/McpSshTools.cs` (4 tools, first-action-per-session approval, no open-connection/read-creds) and `Services/Mcp/McpSessionRegistry.cs` (open SSH tabs only).

**Authority:** full adversarial-review-fix (reviewer subagent; parent re-verified)  
**Baseline:** wormhole-mcp **96** unit tests  
**Final:** wormhole-mcp **105** unit + 19 integration (both default and `--no-default-features`)

**Attack focus:** line spoofing in `list_sessions` (OSC/control chars from a hostile SSH tab title → fabricated MCP lines), approval Deny/Cancel no-exec fail-closed, cross-tool approval caching, unknown/padded session ids, dispatch failure surfacing, exhausted Fake scripts, scan atomicity on invalid ids, source-error no-op, Debug/error redaction of command bodies.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-mcp` | **pass** (105 + 19) |
| `--no-default-features` | **pass** (105 + 11) |
| `cargo check -p wormhole-mcp` (both) | **pass** |
| `git diff --check` (scoped) | **pass** |

---

## Accepted findings and fixes

| ID | Sev | Finding | Fix |
|---|---|---|---|
| R1 | P2 | `render_sessions` rendered host/username/title unvalidated — OSC/control chars could inject fabricated lines into MCP client output | `sanitize_line_field` (control chars → space) on all rendered fields; ids stay validated |
| R2 | P3 | Test-resistance gaps (approval caching, Deny-leaves-unapproved, dispatch failure, padded ids, arg_len semantics, script exhaustion) | +9 regression tests (listed in ledger section) |

### Rejected candidates

Concurrent-mutation partial apply in `scan_and_sync` (host marshals scans to UI thread per C#); approval double-prompt race (C# per-call dialog parity); stale metadata on re-scan (documented contract); `ResultQueue` derive (`T: Default` constraint).

---

## Test command

```powershell
cd rust
cargo test -p wormhole-mcp
cargo test -p wormhole-mcp --no-default-features
```

**Counts:** tool_runner **15+**, live_tab_scan **12+**, full wormhole-mcp **105 unit + 19 integration**.
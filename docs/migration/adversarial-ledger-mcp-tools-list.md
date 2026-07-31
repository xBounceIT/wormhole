# Adversarial ledger — MCP tools/list → capability-report glue

**Scope:** `rust/crates/wormhole-mcp/src/capability.rs` —
`FakeMcpCapabilityServer`, `McpCapabilityReport`, `tools/list` mapping
(`capability_report_from_tools_list` / `capability_report_for_bind` /
`wormhole_tool_catalog`), `execute_tool` fail-closed, secrets-free `Debug` /
diagnostics, loopback bind helper reuse. Docs row in
`docs/migration/07-tunnels-mcp.md`. Builds on
[adversarial-ledger-mcp-http.md](adversarial-ledger-mcp-http.md) /
[adversarial-ledger-mcp-bind.md](adversarial-ledger-mcp-bind.md).  
**Out of scope:** HardwarePass / cutover; live MCP tool execution / SSH
registry; C# `Services/Mcp` mutations; Streamable HTTP host / bearer mint
(except capability surfaces must not invent token wording).  
**Authority:** full adversarial-review-fix (edit in scope; no child agents)  
**Baseline:** `cargo test -p wormhole-mcp` green (25 lib + 19 integration)  
**Final:** 30 lib + 19 integration green; `--no-default-features` check green  

**Attack focus:** blank / padded / duplicate / control-char tool names;
diagnostics line spoofing; off-loopback bind reuse; `tools_executable` /
`execute_tool` fail-closed; Debug / diagnostics bearer leaks; catalog drift vs
C# names / `wormhole_mcp_tools`.

Context7 MCP unavailable in this environment.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (independent attack order; re-run after simplify delta) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-mcp` | **pass** (30 unit + 19 integration) |
| `cargo check -p wormhole-mcp --no-default-features` | **pass** |
| `git diff --check` (scoped) | **pass** |

---

## Accepted findings and fixes

| ID | Sev | Location | Invariant / evidence | Fix | Verification |
|---|---|---|---|---|---|
| MTL-01 | P2 | `capability.rs` `summarize_tools` / `format_for_diagnostics` | Tool names with `\n` / NUL / other control chars reached diagnostics paste and could spoof `running:` / field lines | Reject names containing `char::is_control` | `summarize_rejects_control_chars_and_duplicates` |
| MTL-02 | P2 | `FakeMcpCapabilityServer::with_port_and_tools` | Construction validated via `summarize_tools` but stored the untrimmed `ToolsListResponse` → `tools_list()` disagreed with `capability_report().tool_names()` | `canonicalize_tools_list` stores trimmed names/descriptions | `with_port_and_tools_canonicalizes_trimmed_names` |
| MTL-03 | P2 | `summarize_tools` | Duplicate names (incl. after trim) produced ambiguous capability reports | Fail-closed on duplicate trimmed names | `summarize_rejects_control_chars_and_duplicates` |
| MTL-04 | P3 | docs / catalog rustdoc | Fail-closed docs omitted control/dup rules; catalog rustdoc implied full C# `[Description]` parity | Document Lab abbreviated descriptions + expanded fail-closed rules; refresh `07-tunnels-mcp.md` Capability glue row | doc review + tests still green |

---

## Rejected candidates

| Candidate | Reason |
|---|---|
| Require C# `[Description]` verbatim in catalog | Capability / `wormhole_mcp_tools` intentionally share abbreviated Lab copy; **names** are the C# contract |
| Reject empty/whitespace descriptions | Names drive diagnostics; empty desc is valid for Fake custom catalogs |
| Case-insensitive duplicate detection | MCP tool names are case-sensitive |
| Make `tools_executable` private / constructor-only | Public report fields allow a future live host to advertise executability; Fake path always sets `false` |
| Bound tools/list length (DoS) | In-memory Lab Fake / diagnostics only; unbounded Vec not a reachable network surface here |
| Wire live `execute_tool` / SSH registry | Explicit non-goal; must stay fail-closed |
| Mutate C# `Services/Mcp` | Out of scope |
| Live MCP HTTP round-trip for capability report | Out of scope (no HardwarePass / live tool execution) |

---

## Adversarial clean passes (2 required)

### Clean pass 1 — order: security → diagnostics → execute_tool → bind reuse → contract

- Control-char / blank / duplicate names fail-closed before diagnostics paste.
- `Debug` / diagnostics omit bearer/token wording; descriptions length-only in `Debug`.
- `execute_tool` unwired for every catalog tool (and unknown) while “running”.
- Off-loopback / mapped / zone-id rejected via existing bind helpers; `::1` bind → `http://127.0.0.1:{port}` endpoint.
- `tools_executable` always `false` on glue constructors.
- **Accepted findings:** none.

### Clean pass 2 — order: test resistance → integration drift → boundaries → lifecycle → operability

- Unit suite pins control/dup/canonicalize/`execute_tool`/IPv6 loopback endpoint.
- Catalog names shared with `wormhole_mcp_tools` via `wormhole_tool_catalog` (no second name table).
- Port `0`, hostile bind strings, padded duplicates covered.
- Fake start/stop is socket-free; stop clears `running`.
- `--no-default-features` still compiles capability helpers.
- **Accepted findings:** none.

`adversarial_clean_passes = 2` (re-confirmed after simplify delta: drop redundant `seen` vec in `summarize_tools`).

---

## Iterative-review-simplify (3 clean cycles)

Each cycle: Code Reuse → Code Efficiency → Code Quality and Bugs (+ simplify discipline).

| Cycle | Themes | Outcome |
|---|---|---|
| 1 | Reuse (dup check against `tools` instead of parallel `seen`); docs fail-closed accuracy | Applied → reset adversarial → 2 clean adv passes |
| 2 | Re-check canonicalize vs summarize; bind helper consumption; catalog/rmcp single source | Clean |
| 3 | Test matrix vs attack list; feature gating; no further validated churn | Clean |

`simplify_clean_passes = 3`.

---

## Regression tests added/updated

**`src/capability.rs` unit**
- Control-char / NUL / duplicate (incl. padded) names rejected
- `with_port_and_tools` canonicalizes trimmed name/description
- `execute_tool` fail-closed for every catalog tool + unknown while running
- IPv6 `::1` bind → `127.0.0.1` endpoint URL
- Diagnostics text has no bearer/token wording (canonical catalog)

**Docs**
- `07-tunnels-mcp.md` Capability glue row: control-char / duplicate / `execute_tool` fail-closed

---

## Final verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-mcp
cargo check -p wormhole-mcp --no-default-features
```

Results: green (30 lib unit + 19 integration); `--no-default-features` check green.

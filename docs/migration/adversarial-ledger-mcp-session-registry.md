# Adversarial ledger — MCP live SSH session registry Fake

**Scope:** `rust/crates/wormhole-mcp/src/session_registry.rs` (+ crate-root
re-exports in `lib.rs` / `Cargo.toml` description); capability rustdoc cross-ref;
docs `07-tunnels-mcp.md` (Session registry Fake row + status/non-goals),
`feature-matrix.md` (SSH MCP registration + MCP tools rows), `README.md` index;
this ledger.

**Out of scope:** Streamable HTTP `dispatch_tool` wiring; live SSH / russh;
approval UI; C# `Services/Mcp` mutations; bearer mint / CredMgr; capability
tools/list summarizer (already closed); contested crates (`wormhole-ssh`,
`wormhole-ui`, `wormhole-session`).

**Compared against:** C# `IMcpSessionRegistry` / `McpSessionRegistry` /
`McpSessionInfo` / `SshSessionViewModel.IsMcpConnected` (Connected-only list;
agent-readable unknown / not-connected errors). Lab Fake uses explicit
register/unregister instead of scanning UI tabs.

**Authority:** full adversarial-review-fix (edit in scope; no child agents)  
**Baseline:** `cargo test -p wormhole-mcp` green (43 lib + 19 integration) before
order/docs polish  
**Final:** 44 lib + 19 integration green; `--no-default-features` check green  

**Attack focus:** blank / padded / control-char ids; non-Connected register;
duplicate register; unknown unregister; list Connected-only + insertion order;
`get_connected` fail-closed; Debug / error strings never carry bearer/token;
no live MCP/SSH I/O; trait vs Fake boundary.

Context7 MCP unavailable in this environment.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (independent attack order; re-run after simplify — no code delta) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-mcp` | **pass** (44 unit + 19 integration) |
| `cargo check -p wormhole-mcp --no-default-features` | **pass** |
| `git diff --check` (scoped) | **pass** |

---

## Accepted findings and fixes

| ID | Sev | Location | Invariant / evidence | Fix | Verification |
|---|---|---|---|---|---|
| MSR-01 | P2 | `FakeMcpSessionRegistry::unregister` + `list_sessions` | Unregistering a middle id could silently reorder remaining sessions if `order`/`HashMap` drifted | Pin insertion-order retain; add regression | `unregister_middle_preserves_insertion_order` |
| MSR-02 | P3 | `capability.rs` rustdoc + `07` non-goals | Docs still implied “SSH registry” wholly TODO while Fake list/register glue shipped | Cross-ref Fake registry; clarify HTTP dispatch still unwired | doc review + tests green |
| MSR-03 | P3 | `feature-matrix.md` / `README.md` | SSH MCP registration row + ledger index lagged Lab Fake | Update matrix rows + README ledger index | index/matrix review |

---

## Rejected candidates

| Candidate | Reason |
|---|---|
| Put register/unregister on `McpSessionRegistry` trait | C# `IMcpSessionRegistry` has list/run/send/read only; Lab register is Fake-specific (tabs are the production source) |
| Wire `FakeMcpSessionRegistry` into `WormholeMcpHandler::dispatch_tool` | Explicit non-goal (“no live MCP execution”); HTTP `list_sessions` stays `[]` |
| Reject empty host / port `0` on register | C# allows missing-profile empties (`Host ?? ""`, `Port ?? 0`) |
| Case-fold session ids | C# uses ordinal `McpId.ToString() == sessionId` |
| Bound registry size (DoS) | In-memory Lab Fake only; not a network surface |
| Merge id canonicalize with tools/list name summarizer | Different domains / error copy; one-off merge churn > benefit |
| Redact username/host from `McpSessionInfo` Debug | Metadata is the MCP `list_sessions` surface (not CredMgr secrets); Fake registry Debug is already ids-only |
| Mutate C# `Services/Mcp` | Out of scope |
| Place glue in `wormhole-ssh` / `wormhole-session` | Prefer `wormhole-mcp`; avoid contested crates |

---

## Adversarial clean passes (2 required)

### Clean pass 1 — order: contract → boundary → state → concurrency → security

- Connected-only register; list filters Connected; unknown / blank / control-char fail-closed.
- Duplicate register / re-register-after-unregister; middle-unregister order pinned.
- Mutex + poison recover; no async/SSH I/O.
- Debug / errors omit bearer/token/password wording.
- **Accepted findings:** none.

### Clean pass 2 — order: test resistance → integration drift → boundaries → operability → security

- Unit suite pins Connected / duplicate / unknown / control / Debug / order.
- Trait is list-only; Fake owns register/unregister; HTTP dispatch untouched.
- `--no-default-features` still compiles session registry.
- Docs/matrix/ledger aligned with “Fake yes / live dispatch no”.
- **Accepted findings:** none.

`adversarial_clean_passes = 2`.

---

## Iterative-review-simplify (3 clean cycles)

Each cycle: Code Reuse → Code Efficiency → Code Quality and Bugs (+ simplify discipline).

| Cycle | Themes | Outcome |
|---|---|---|
| 1 | Reuse (local id canonicalize; no tools/list merge); efficiency (HashMap + order vec); quality (Connected gate + agent-readable errors) | Clean — no validated churn |
| 2 | Trait vs Fake boundary; Debug contracts; defensive Connected filter kept | Clean |
| 3 | Test matrix vs attack list; feature gating; docs parity | Clean |

`simplify_clean_passes = 3`. No simplify implementation delta → adversarial remains at 2 clean.

---

## Regression tests added/updated

**`src/session_registry.rs` unit**
- register / list / unregister round-trip + Connected metadata
- non-Connected / blank / control-char / duplicate register rejected
- unknown / blank unregister rejected
- `get_connected` resolve + fail-closed
- `with_sessions` seed / reject
- defensive list filter omits non-Connected
- re-register after unregister; middle-unregister preserves order
- status C# names; port `0` metadata allowed
- Debug / error strings never mention bearer/token/password

**Docs**
- `07-tunnels-mcp.md` Session registry Fake row + status/non-goals
- `feature-matrix.md` SSH MCP + MCP tools rows
- `README.md` ledger index

---

## Final verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-mcp
cargo check -p wormhole-mcp --no-default-features
```

Results: green (44 lib unit + 19 integration); `--no-default-features` check green.

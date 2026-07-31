# Adversarial ledger — MCP Streamable HTTP loopback bind hardening

**Scope:** `rust/crates/wormhole-mcp/src/bind.rs`, post-bind check in
`rmcp_handler.rs`, `McpError::InvalidBindAddress` / `NonLoopbackBind`,
MCP bind notes in `docs/migration/07-tunnels-mcp.md`, related unit +
`tests/host_lifecycle.rs` coverage. Builds on M-09 from
[adversarial-ledger-mcp-http.md](adversarial-ledger-mcp-http.md).  
**Out of scope:** HardwarePass / cutover; C# `Services/Mcp`; token/approval
surface except error Display must not invent bearer wording; live SSH tools.  
**Authority:** full adversarial-review-fix (edit in scope; no child agents)  
**Baseline:** `cargo test -p wormhole-mcp` green (14 lib + 19 integration)  
**Final:** 16 lib + 19 integration green; `--no-default-features` check green  

**Attack focus:** `0.0.0.0`, `[::]`, IPv4-mapped (public / unspecified / loopback),
hostname tricks, post-bind race, error string leaks, dual-stack / zone-id surprises.

Context7 MCP unavailable in this environment.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (independent attack order; re-run after simplify delta) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-mcp` | **pass** (16 unit + 19 integration) |
| `cargo check -p wormhole-mcp --no-default-features` | **pass** |
| `git diff --check` (scoped) | **pass** |

---

## Accepted findings and fixes

| ID | Sev | Location | Invariant / evidence | Fix | Verification |
|---|---|---|---|---|---|
| MB-01 | P2 | `bind.rs` `validate_loopback_bind` | Bind helpers accepted IPv4-mapped loopback (`::ffff:127.0.0.1`) via peer-oriented `is_loopback_ip`; dual-stack bind surprise | Canonical bind via std `is_loopback` only (`is_canonical_loopback_bind_addr`); peer path keeps `is_loopback_ip` | `peer_loopback_allows_mapped_but_bind_does_not`, mapped cases in `rejects_hostile_*` |
| MB-02 | P2 | `bind.rs` / tests | Alternate mapped-unspecified / mapped-public spellings (`[::ffff:0:0]`, expanded forms) under-pinned | Expand unit + integration hostile suites | `parse_loopback_bind_rejects_hostile_strings`, `rejects_hostile_bind_strings_and_hosts` |
| MB-03 | P2 | `bind.rs` | `[::1%1]:8765` parses as loopback SocketAddr with non-zero scope and passed bind validation | Require `scope_id() == 0` for IPv6 bind | `rejects_ipv6_loopback_with_zone_id` |
| MB-04 | P3 | `error.rs` / tests | `InvalidBindAddress` Display not covered by token-leak assertions (only `NonLoopbackBind`) | Assert `InvalidBindAddress` / mapped reject strings have no `token`/`bearer` | `error_display_has_no_token_material` |
| MB-05 | P3 | `lib.rs` / `bind.rs` | Dead misleading exports `is_unspecified_v4`, `reject_if_non_loopback` | Remove unused public aliases | compile + tests |
| MB-06 | P3 | `rmcp_handler.rs` `start` | Redundant `validate_bind_addr` after `loopback_v4` (already validates) | Drop duplicate call; keep public `validate_bind_addr` for callers | `rmcp_bind_health_*`, `rmcp_host_rejects_non_loopback_bind` |

---

## Rejected candidates

| Candidate | Reason |
|---|---|
| Reject IPv4-mapped loopback for **peers** | Intentional: middleware uses `is_loopback_ip`; Host header / dual-stack clients may present mapped form |
| Expand `is_hostile_bind_literal` for every mapped spelling | Early list is best-effort; parse → `validate_loopback_bind` is the fail-closed path |
| DNS-resolve hostnames to detect loopback CNAMEs | Fail-closed without resolution (`localhost` literal only + IP parse) |
| Integration test that forces `ensure_bound_loopback` failure | Cannot make OS return non-loopback for a `127.0.0.1` bind without mocking; unit pins helper; start drops listener before `serve` |
| Treat post-bind ensure failure as distinct error variant | `NonLoopbackBind` / `InvalidPort` already typed; churn > benefit |
| Mutate C# MCP host | Out of scope |

---

## Adversarial clean passes (2 required)

### Clean pass 1 — order: security → dual-stack → post-bind → hostname → errors

- Wildcards / LAN / public / mapped / scoped `::1` rejected for bind; peers still accept mapped loopback.
- `start`: `loopback_v4` → bind → `ensure_bound_loopback` before `axum::serve`; failure drops listener, `running` stays false.
- Host helpers reject DNS-like / trailing-dot / mapped hosts; no bearer wording in bind errors.
- **Accepted findings:** none.

### Clean pass 2 — order: test resistance → integration → contract → concurrency → boundaries

- Hostile string suites pin alternate mapped forms + zone id; health bind still `127.0.0.1` only.
- Port `0`, empty / malformed strings, `localhost:port` (unparseable SocketAddr) fail closed.
- Lifecycle mutex unchanged; bind failure rollback still covered.
- **Accepted findings:** none.

`adversarial_clean_passes = 2` (re-confirmed after simplify delta: alias removal + redundant `validate_bind_addr` drop).

---

## Iterative-review-simplify (3 clean cycles)

Each cycle: Code Reuse → Code Efficiency → Code Quality and Bugs (+ simplify discipline).

| Cycle | Themes | Outcome |
|---|---|---|
| 1 | Reuse (drop dead aliases; drop duplicate validate in `start`); docs bind table | Applied → reset adversarial → 2 clean adv passes |
| 2 | Re-check bind/peer split, hostile parse, post-bind ordering | Clean |
| 3 | Test matrix vs attack list; `InvalidBindAddress` Display; feature gating | Clean |

`simplify_clean_passes = 3`.

---

## Regression tests added/updated

**`src/bind.rs` unit**
- Mapped loopback rejected for bind, accepted for peer helper
- Hostile strings: mapped public/unspecified/loopback, expanded forms, `+`, zone id
- Host fail-closed: mapped, `localhost.`, case-insensitive `LOCALHOST`
- `InvalidBindAddress` / mapped reject Display has no token/bearer material

**`tests/host_lifecycle.rs`**
- Integration hostile bind/host list expanded (mapped + zone + `localhost:port`)

**Docs**
- `07-tunnels-mcp.md` bind helpers row: all IPv4-mapped + scoped IPv6 loopback rejected for bind

---

## Final verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-mcp
cargo check -p wormhole-mcp --no-default-features
```

Results: green (16 lib unit + 19 integration); `--no-default-features` check green.

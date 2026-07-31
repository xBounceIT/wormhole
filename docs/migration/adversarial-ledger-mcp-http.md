# Adversarial ledger — MCP Streamable HTTP loopback

**Scope:** `rust/crates/wormhole-mcp/`, MCP sections of `docs/migration/07-tunnels-mcp.md`  
**Authority:** adversarial-review-fix (edit in scope; no C# production mutations; no Go sidecars)  
**Baseline (pre-fix):** `cargo test -p wormhole-mcp` green (0 lib + 11 integration)  
**Attack surface:** loopback bind/peer; bearer on all routes incl. `/health`; tokens never logged; CredMgr vs MemoryTokenStore; approval fail-closed; port 0 rejected; tools/list names vs C#; no SSRF via stubs; feature `rmcp` gating

---

## Accepted findings and fixes

| ID | Sev | Location | Invariant / evidence | Fix | Verification |
|---|---|---|---|---|---|
| M-01 | P1 | `token.rs` / hosts | Concurrent `get_or_create` could mint multiple tokens (C# uses `_tokenGate`) | Shared `get_or_create_token` / `regenerate_token` under `AsyncMutex` | `concurrent_get_or_create_shares_one_token` |
| M-02 | P1 | `rmcp_handler.rs` start/stop | CAS-only lifecycle raced with in-flight bind (second `start` could observe `running` while first still binding / failing) | `lifecycle: AsyncMutex`; set `running` only after successful bind | `rmcp_start_rolls_back_when_bind_fails` |
| M-03 | P1 | `stub.rs` start | Token mint failure after CAS left `is_running == true` | Reset `running` on token error | `placeholder_start_rolls_back_running_on_token_failure` |
| M-04 | P2 | `token.rs` `extract_bearer_token` | Only `"Bearer "` / `"bearer "` — C# is `OrdinalIgnoreCase` (`BEARER`) | Case-insensitive prefix + `is_authorized` | `bearer_scheme_is_case_insensitive`, `bearer_helpers_match_csharp_case_rules` |
| M-05 | P2 | placeholder `get_or_create` | Empty stored token accepted (Rmcp path regenerated) | Treat empty as missing in shared mint helper | `empty_stored_token_is_regenerated`, `placeholder_rejects_empty_stored_token` |
| M-06 | P2 | `MemoryTokenStore` | `Debug` could leak token material | Redacting `Debug` (`[REDACTED]`) | `memory_token_store_debug_redacts` |
| M-07 | P2 | tests / middleware | `/health` bearer pinned but MCP `/` + AutoDeny + SSRF stubs unpinned | Bearer on POST `/`; AutoDeny default; `dispatch_tool` URL-like sessionId never opens sockets | `rmcp_bind_health_and_reject_bad_token`, `approval_defaults_to_fail_closed`, `tool_stubs_fail_closed_and_never_fetch_urls`, `regenerate_rotates_live_bearer` |
| M-08 | P2 | `CredMgrTokenStore` | Fixed MCP guid must match C# `a7f3c1e2-…` | Assert id + peek under `feature = "secrets"` | `cred_mgr_store_uses_fixed_mcp_credential_id` |
| M-09 | P2 | `bind.rs` | Hostile bind spellings (`0.0.0.0`, `[::]`, LAN, IPv4-mapped public) only lightly covered | Explicit unspecified + IPv4-mapped fail-closed; `parse_loopback_bind` / `validate_loopback_host`; post-bind `ensure_bound_loopback` | `rejects_hostile_*` unit tests + `rejects_hostile_bind_strings_and_hosts` |

Follow-up bind hardening (mapped loopback / zone-id / Display / dead aliases) closed in [adversarial-ledger-mcp-bind.md](adversarial-ledger-mcp-bind.md).

---

## Rejected candidates

| Candidate | Reason |
|---|---|
| Integration test non-loopback *peer* | Listener binds `127.0.0.1` only; remote peers cannot connect. Middleware rejects non-loopback IPs; bind-side covered by `validate_loopback_bind` / `validate_bind_addr` / hostile string suite |
| Cache `wormhole_mcp_tools()` statically | Pre-existing alloc on list; not a contract bug; churn > benefit |
| Cryptographically stronger tokens | Already 32-byte CSPRNG URL-safe; matches C# |
| Wire live SSH session registry | Explicit non-goal; stubs must stay network-free |
| Mutate C# `Services/Mcp` | Out of scope |
| Rewrite Streamable HTTP stack | Out of scope — bind/auth surface only |

---

## Adversarial clean passes (2 required)

### Clean pass 1 — order: concurrency → security → state → contract → tests

- Token gate + lifecycle mutex; bind/token failure leaves `running == false`.
- Loopback bind/peer; bearer on `/health` and MCP `/`; tokens absent from tracing/`Debug`; AutoDeny; tool stubs no I/O.
- Tools names match C# `McpSshTools`; port `0` rejected; `rmcp` feature off builds placeholder.
- **Accepted findings:** none.

### Clean pass 2 — order: integration → boundaries → test resistance → operability → security

- CredMgr id parity (`secrets`); Memory store default; regenerate invalidates live bearer.
- Boundaries: empty token, `BEARER` scheme, missing/wrong auth, occupied port bind fail.
- Operability: idempotent start/stop; `--no-default-features` check green.
- **Accepted findings:** none.

`adversarial_clean_passes = 2` (re-confirmed after simplify delta: removed dead placeholder cache + redundant `sync_expected_token` in `start`).

---

## Iterative-review-simplify (3 clean cycles)

Each cycle: Code Reuse → Code Efficiency → Code Quality and Bugs (+ simplify discipline).

| Cycle | Themes | Outcome |
|---|---|---|
| 1 | Reuse (`get_or_create_token` / `is_authorized`); quality (drop write-only `cached`; drop double sync in `start`); docs MCP table | Applied → reset adversarial → 2 clean adv passes |
| 2 | Re-check host/middleware/tool dispatch; no further validated churn | Clean |
| 3 | Docs/`07` parity; feature gating; regression suite still pins attack list | Clean |

`simplify_clean_passes = 3`.

---

## Regression tests added/updated

**`src/token.rs` unit**
- bearer case-insensitive; empty expected fail-closed; Debug redaction; concurrent mint; empty store regenerate

**`src/bind.rs` unit**
- canonical loopback accept; port 0; hostile IPv4/IPv6/mapped; parse/host string fail-closed; error display has no token material

**`tests/host_lifecycle.rs`**
- AutoDeny default; empty token; start rollback on store failure; MCP `/` bearer; regenerate rotates; bind failure rollback; tool stub SSRF/deny; CredMgr id (`--features secrets`); hostile bind strings/hosts

---

## Final verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-mcp
cargo test -p wormhole-mcp --features secrets
cargo check -p wormhole-mcp --no-default-features
```

Results: bind hardening unit suite + integration (default) / with `secrets`; `--no-default-features` check green.

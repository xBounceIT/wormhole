# Adversarial ledger — Tunnel payload DPAPI store

**Scope:**
- `rust/crates/wormhole-secrets-win/src/key_tunnel.rs` — `TunnelPayloadStore` / `DpapiTunnelPayloadStore` / `FakeTunnelPayloadStore`; `write`/`read`/`delete_tunnel_payload(_under)`
- Confinement before I/O; missing delete → `Ok(())`; never unprotect on delete
- Fail-closed outside `tunnels\`; Debug never echoes secrets; SQLite metadata-only
- Docs: `docs/migration/04-secrets.md`, `docs/migration/07-tunnels-mcp.md`; index in `docs/migration/README.md`

**Reconcile:** Sibling [adversarial-ledger-key-dpapi-crud.md](adversarial-ledger-key-dpapi-crud.md) already closed coherent key+tunnel CRUD (non-atomic write parity, delete-never-unprotect, Fake copies). This ledger is the **tunnel-focused** gate: sibling `keys\` isolation, Fake ↔ DPAPI tunnel contract, hostile store/read/delete on `DpapiTunnelPayloadStore`, docs for tunnels-only consumers. **Do not regress** `KeyMaterialStore` / `keys\`.

**Out of scope:** HardwarePass / cutover; live VPN / `TunnelManager::establish`; CredMgr; Hello / Bitwarden; Azure VPN tokencache helpers; symlink follow (lexical-only); merging public key+tunnel types into one generic.

**Authority:** full adversarial-review-fix (edit in scope)  
**Attack focus:** path escape into `keys/`; empty root; join-replacement; secret in Debug/errors; delete+read; Fake vs DPAPI contract  
**Baseline:** `cargo test -p wormhole-secrets-win` — 1 failing oracle (`windows(11)` vs 12-byte needle) before this review  
**Final:** **94 passed**

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix; re-run after simplify rustdoc/test delta) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-secrets-win` | **pass** (94) |

---

## Accepted findings

### TUN-01 — Vacuous / brittle substring oracles (`P1`) — **fixed**

- **Where:** `key_tunnel.rs` tests (defensive-copy windows; on-disk plaintext scan)
- **Invariant:** Byte-window assertions must use `needle.len()`; mismatched window sizes never equal the needle (vacuous fail or vacuous “no plaintext” pass)
- **Evidence:** Baseline panic on `windows(11)` vs `b"caller-owned"` (12); `windows(10)` vs `b"10.0.0.2"` (8) could never detect a regression that left plaintext on disk
- **Impact:** False confidence on defensive copies / ciphertext opacity
- **Fix:** Full-slice equality for Fake defensive copies; on-disk scans use `marker.len()` / `endpoint.len()`
- **Regression:** `fake_key_and_tunnel_defensive_copies_isolate_caller_buffers`, `dpapi_tunnel_payload_store_crud_under_temp`

### TUN-02 — Sibling `keys\` escape under-pinned (`P1`) — **fixed**

- **Where:** tunnel write/read/delete helpers + `DpapiTunnelPayloadStore`
- **Invariant:** Tunnel CRUD under `tunnels\` must not create/touch sibling `keys\<id>.dpapi`; lexical `tunnels\..\keys` / empty / `..\Windows` roots fail closed before I/O
- **Evidence:** Path helpers reject `..` roots, but no tunnel-specific regression proved sibling `keys\` stayed empty for the same guid
- **Impact:** A confinement regression could silently write tunnel secrets into the key store tree
- **Fix:** Temp sibling roots; assert keys dir empty after tunnel write; escape-to-keys + join-replacement rejected; keys untouched
- **Regression:** `tunnel_payload_never_writes_sibling_keys_dir`

### TUN-03 — Fake ↔ DPAPI tunnel contract gaps (`P2`) — **fixed**

- **Where:** `FakeTunnelPayloadStore` tests vs `DpapiTunnelPayloadStore`
- **Invariant:** Missing read `None`; overwrite; empty blob; missing delete `Ok`; call counts; Debug length-only (no payload fragments)
- **Evidence:** Fake tunnel CRUD test lacked call-count / overwrite / empty-blob pins that key Fake and DPAPI tunnel store already had
- **Fix:** Align Fake tunnel test with key Fake + DPAPI empty/overwrite/Debug contracts
- **Regression:** `fake_tunnel_payload_store_crud_and_debug_redacts`

### TUN-04 — DPAPI tunnel hostile path + delete/read opacity (`P2`) — **fixed**

- **Where:** `DpapiTunnelPayloadStore`; delete helpers; corrupt ciphertext
- **Invariant:** Hostile/empty root rejects **store/read/delete** before I/O; post-delete read `None`; corrupt tunnel read → `DpapiUnprotect` without marker echo; delete never unprotects; on-disk file has no plaintext markers
- **Evidence:** Prior DPAPI tunnel test only hostile-tested **delete**; corrupt-tunnel read redaction and post-delete `None` under-asserted vs keys
- **Fix:** Store/read/delete hostile + empty root; ciphertext marker scan; symmetric corrupt-tunnel read assert before delete
- **Regression:** `dpapi_tunnel_payload_store_crud_under_temp`, `delete_key_and_tunnel_never_unprotects_corrupt_ciphertext`, `key_and_tunnel_payload_roundtrip_under_temp`

### TUN-05 — Docs incomplete for tunnel-only consumers (`P3`) — **fixed**

- **Where:** `04-secrets.md` Path confinement / coverage; `07-tunnels-mcp.md` Tunnel secret payloads; README index
- **Fix:** Tunnel row documents delete-never-unprotect + no sibling `keys\` escape; coverage splits key vs tunnel ledgers; `07-tunnels-mcp` restores `→` arrows, links this ledger; README index row

### SIM-01 — Trait delete contract + Fake empty blob (`P3` simplify) — **fixed**

- **Where:** `TunnelPayloadStore` rustdoc; Fake tunnel CRUD test
- **Fix:** Trait documents deletes must not unprotect; Fake empty-blob round-trip pins Fake ↔ DPAPI parity

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Merge Fake/Dpapi key+tunnel into one generic public type — distinct DI surfaces match C# / CredMgr pattern; [key-dpapi-crud REJ-01](adversarial-ledger-key-dpapi-crud.md); churn > clarity |
| REJ-02 | — | Switch tunnel writes to `write_protected_file_atomic` — intentional C# `CredentialService` non-atomic parity (caches stay atomic) |
| REJ-03 | — | Symlink / junction escape past lexical confine — residual; same class as dpapi-paths |
| REJ-04 | — | `SecretsError::Io` may embed OS paths after successful confine — not secret material; escapes fail closed before I/O |
| REJ-05 | — | Bound tunnel payload size like CredMgr 2560 — opaque DPAPI files have no C# size ceiling |
| REJ-06 | — | Touch `azure_vpn_token_cache_path_under` dead_code warning — out of tunnel-payload scope |
| REJ-07 | — | Live `TunnelManager` / provider wiring — explicit non-goal |

---

## Adversarial cycles

| Pass | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-1 | Security (keys escape / Debug) → Boundary → Contract → Test resistance | TUN-01..04 | Fixed; reset |
| Adv-2 | Integration drift vs key store → docs → reverse oracle audit | TUN-05 | Fixed; reset |
| Adv-3 | Concurrency (Fake) → State (delete+read) → Performance | None | Clean (1/2) |
| Adv-4 | Attack-list reverse: Fake↔DPAPI → join-replacement → empty root → SQLite metadata-only | None | Clean (2/2) |
| Post-simplify Adv-A | Trait rustdoc + empty-blob delta; sibling keys still isolated | None | Clean (1/2) |
| Post-simplify Adv-B | Never-unprotect corrupt path; ciphertext opacity; keys CRUD untouched | None | Clean (2/2) |

---

## Simplify passes (iterative-review-simplify)

| Cycle | Reuse | Efficiency | Quality | Disposition |
|---|---|---|---|---|
| 1 | Keep parallel key/tunnel APIs (REJ-01) | No hot-path I/O change | Trait delete rustdoc + Fake empty blob | **SIM-01** → reset (+ adv re-run) |
| 2 | No new shared abstraction | Same | Contracts + docs aligned | Clean (1/3) |
| 3 | Same | Same | Sibling isolation + hostile matrix intact | Clean (2/3) |
| 4 | Diff hygiene / ledger / README | Same | Coverage links tunnel ledger | Clean (3/3) |

---

## Attack lane outcomes (summary)

| Lane | Outcome |
|---|---|
| Path escape into `keys/` | Sibling dir empty; `tunnels\..\keys` → `PathNotConfined` before I/O |
| Empty root | Helpers + `DpapiTunnelPayloadStore` reject; no vacuous `starts_with("")` |
| Join-replacement | `..\Windows` / hostile roots rejected on write/read/delete |
| Secret in Debug/errors | Store Debug = lengths / `tunnels_root_len`; `PathNotConfined` / `DpapiUnprotect` free of markers |
| Delete + read / never unprotect | Missing delete `Ok`; corrupt delete succeeds; post-delete `None` |
| Fake vs DPAPI | Missing/overwrite/empty/delete/Debug/call counts aligned |
| SQLite metadata-only | Secrets crate holds opaque blobs only; docs + `07-tunnels-mcp` |

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-secrets-win
```

Expected: **94 passed**.

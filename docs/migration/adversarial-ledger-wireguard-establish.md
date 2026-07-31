# Adversarial ledger — WireGuard establish-path glue

**Scope:**
- `rust/crates/wormhole-tunnels/src/providers/wireguard/establish.rs` — `establish_wireguard`, lookup traits / Fakes, `PayloadStoreSecretLookup`
- Shape gate via `providers/secret_shape.rs` (`interface_private_key`) — exercised through establish (no live WG)
- Docs: `docs/migration/07-tunnels-mcp.md` WireGuard establish section; index in `docs/migration/README.md`

**Out of scope:** Live `wormhole-wgproxy` / network; rewriting Go sidecars; OpenVPN/Cisco/Fortinet/etc. establish modules (except confirming they **reuse** WG lookups / `PayloadStoreSecretLookup`); C# production mutations.

**Authority:** full adversarial-review-fix (edit in scope; no child agents)  
**Baseline:** `cargo test -p wormhole-tunnels --lib providers::wireguard` — 11 establish/provider tests green before review  
**Final:** `cargo test -p wormhole-tunnels` — **321** lib + **21** lease + **24** sidecar green

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix; re-confirmed after simplify oracle tighten) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-tunnels` | **pass** |

---

## Accepted findings

### WG-01 — Soft / vacuous shape-error oracle (`P2`) — **fixed**

- **Where:** `bad_secret_shape_rejects_without_echoing_blob`
- **Invariant:** Fail-closed wrong-shape must be typed `Establish` and pin `interface_private_key` wording; never pass via a loose `|| "WireGuard"` branch
- **Evidence:** Assertion accepted any error string containing `"WireGuard"` (e.g. unrelated kind mismatch prose)
- **Fix:** `matches!(Establish)` + require `interface_private_key`; shared `assert_no_secret_echo` also bans endpoint echo
- **Regression:** `bad_secret_shape_rejects_without_echoing_blob`

### WG-02 — Happy path did not pin snapshot/secret forward (`P2`) — **fixed**

- **Where:** `establish_wireguard` + `FakeTunnelProvider` (ignores `_config` / `_secret_blob`)
- **Invariant:** Glue must pass the loaded `TunnelConfigSnapshot` (id/kind/name/`updated_at`) and exact secret bytes to `TunnelProvider::establish`
- **Evidence:** Existing happy-path only asserted lookup call counts + `Up`; a regression that passed `&[]` or a wrong snapshot after the shape gate would still pass
- **Fix:** Test-local `CapturingWgProvider` (Debug redacts; never dumps secret) + forward assertions
- **Regression:** `establish_forwards_snapshot_and_secret_bytes`

### WG-03 — Invalid JSON / whitespace / cross-kind shape under-pinned (`P2`) — **fixed**

- **Where:** establish glue shape gate path
- **Invariant:** Empty-key-after-trim, invalid JSON, non-object JSON, and OpenVPN-shaped blobs fail closed as `Establish` **without** echoing markers (serde error stringification must stay redacted)
- **Evidence:** Only PascalCase editor blob was covered at establish layer; `parse_json_object` uses `map_err(|_| …)` today but lacked establish-level regression
- **Fix:** Focused establish tests with unique markers in sibling fields where needed (avoid vacuous marker asserts)
- **Regression:** `whitespace_only_key_rejects_without_echoing_blob`, `invalid_json_secret_rejects_without_echoing_blob`, `non_object_json_secret_rejects_without_echoing_blob`, `openvpn_shaped_secret_rejects_for_wireguard`

### WG-04 — Capturing Debug redaction asserted after `take_last` (`P2`) — **fixed**

- **Where:** `establish_forwards_snapshot_and_secret_bytes`
- **Invariant:** Debug must omit secret **while** the capture still holds it
- **Evidence:** Prior assert ran after `take_last()`, so `has_last` was false and the no-echo check could not catch a Debug dump regression
- **Fix:** Format Debug before `take_last`; assert `has_last` + no marker
- **Regression:** same test

### WG-05 — PayloadStore I/O mapping / Fake Debug contracts under-pinned (`P2`) — **fixed**

- **Where:** `PayloadStoreSecretLookup`; `FakeTunnelConfigLookup` / `FakeTunnelSecretLookup` Debug
- **Invariant:** Store read errors map to `Establish` without inventing secret material; Fake config Debug is ids-only; Fake secret Debug is length-only; reuse existing `TunnelPayloadStore` (no duplicate store)
- **Evidence:** Happy-path adapter test only; no failing-store mapping test; config Debug name omission untested
- **Fix:** `FailingTunnelStore` Io mapping test; config Debug ids-only test
- **Regression:** `payload_store_adapter_maps_store_err_without_echoing_marker`, `fake_config_lookup_debug_is_ids_only`

### WG-06 — Docs mojibake / ledger discoverability (`P3`) — **fixed**

- **Where:** `07-tunnels-mcp.md` WireGuard establish section; README ledger index; adversarial ledgers bullet
- **Fix:** Restore `→` arrows; document whitespace/invalid-JSON fail-closed + no store duplication; link this ledger; README row

### SIM-01 — Soft invalid-JSON oracle (`P3` simplify) — **fixed**

- **Where:** `invalid_json_secret_rejects_without_echoing_blob`
- **Fix:** Require `"JSON"` in error text (drop loose `|| "WireGuard"`)

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Live WireGuard / spawn `wormhole-wgproxy` in establish glue tests — explicitly out of scope |
| REJ-02 | — | Zeroize secret `Vec<u8>` on drop — beyond C# / stub surface; sibling tunnel ledgers deferred |
| REJ-03 | — | Assert `record.id == config_id` in establish — production `get_by_id` + Fake key by `record.id`; siblings omit; speculative |
| REJ-04 | — | Promote `CapturingWgProvider` into shared `FakeTunnelProvider` — Fake intentionally ignores blobs for lease coalesce; keep test-local |
| REJ-05 | — | Treat `secret_len` tracing field as secret leakage — length-only ops signal; docs forbid payload/JSON only |
| REJ-06 | — | Duplicate `TunnelPayloadStore` inside tunnels crate — forbidden; `PayloadStoreSecretLookup` adapts secrets-win |

---

## Adversarial cycles

### Clean pass 1 — concurrency → security → state → contract → tests

- Lookups Mutex + poison recovery; no mid-establish shared pool state in this glue.
- Secrets absent from Debug / Establish text / tracing payload; wrong-kind paths skip secret read.
- Fail-closed ConfigNotFound / SecretMissing / WrongKind / Establish ordering preserved.
- **Accepted findings:** none.

### Clean pass 2 — integration → boundaries → test resistance → operability → security

- OpenVPN/Cisco/etc. still import WG lookup traits / `PayloadStoreSecretLookup` (no duplicated stores).
- Boundaries: empty, whitespace key, PascalCase, invalid/non-object JSON, OpenVPN shape, provider/config kind mismatch.
- Capturing forward + Debug-before-take; soft oracles removed.
- **Accepted findings:** none.

`adversarial_clean_passes = 2`.

---

## Iterative-review-simplify (3 clean cycles)

Each cycle: Code Reuse → Code Efficiency → Code Quality and Bugs (+ simplify discipline).

| Cycle | Themes | Outcome |
|---|---|---|
| 1 | Reuse (`assert_no_secret_echo`, `PayloadStoreSecretLookup`); efficiency (single get/read; early kind gates); quality (oracles) | SIM-01 only; then clean |
| 2 | Keep Capturing test-local vs Fake; no extra I/O; docs/ledger parity | Clean |
| 3 | Re-check fail-closed matrix + no secret in Debug/errors; exports unchanged | Clean |

`simplify_clean_passes = 3`. Post-simplify adversarial re-check stayed clean (test-oracle-only delta).

---

## Regression tests added/updated

- `establish_forwards_snapshot_and_secret_bytes`
- `whitespace_only_key_rejects_without_echoing_blob`
- `invalid_json_secret_rejects_without_echoing_blob`
- `non_object_json_secret_rejects_without_echoing_blob`
- `openvpn_shaped_secret_rejects_for_wireguard`
- `fake_config_lookup_debug_is_ids_only`
- `payload_store_adapter_maps_store_err_without_echoing_marker`
- Tightened: `bad_secret_shape_rejects_without_echoing_blob`, `fake_secret_lookup_debug_redacts_payload`

---

## Final verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-tunnels
```

Results: **321** lib + **21** lease + **24** sidecar passed (recorded at ledger close).

# Adversarial ledger — import UnsupportedProtocol / HTTP-HTTPS-Serial soft-skip

**Scope:** `rust/crates/wormhole-import/` (`try_map_protocol`, `ImportError::UnsupportedProtocol`, `plan_nodes` soft-skip), `docs/migration/12-import.md`  
**Authority:** adversarial-review-fix (edit in scope; no C# mutations; no SQLite commit path)  
**Attack focus:** soft-skip must not abort whole import; must not silently map HTTP→SSH; clear UnsupportedProtocol (Telnet/other); fail-closed hostile XML still holds; docs SSH/RDP/VNC-only accurate  
**Baseline (pre-fix):** `cargo test -p wormhole-import` green (32 lib + 4 integration)

---

## Accepted findings and fixes

| ID | Sev | Location | Invariant / evidence | Fix | Verification |
|---|---|---|---|---|---|
| U-01 | P2 | `mremoteng` plan tests | Telnet/RAW soft-skip unpinned (C# has TELNET skip test); HTTP/HTTPS/Serial covered only | `soft_skips_telnet_and_raw_without_aborting_siblings` | unit |
| U-02 | P2 | `mremoteng` plan tests | Container `Protocol=HTTP` → folder `protocol=None` + SSH children untested | `container_unmapped_protocol_still_plans_ssh_children` | unit |
| U-03 | P2 | plan / domain | With `domain` feature, `ProtocolType` includes Http/Https/Serial — no assert planned nodes never carry those | `assert_no_gap_protocol_mapping` + fixture integration pin | unit + `sample_fixture_never_maps_…` |
| U-04 | P2 | `plan_nodes` | All-unsupported tree could still be wrongly assumed to hard-fail | `all_unsupported_connections_plan_succeeds_empty` | unit |
| U-05 | P3 | skipped samples | Empty `Protocol` → `(unspecified)` sample (C# parity) untested | `soft_skips_empty_protocol_as_unspecified_sample` | unit |
| U-06 | P3 | `ImportError::UnsupportedProtocol` | Message named HTTP/HTTPS/Serial only; Telnet unclear | Display lists Telnet + “other protocols”; docs note soft-skip continues | `rejects_http_https_serial_telnet_as_unsupported` |
| U-07 | P3 | `12-import.md` | Telnet row implied plan emits `UnsupportedProtocol` | Clarify classification vs `plan_nodes` soft-skip | doc |

### Simplify delta (post-adversarial)

| ID | Sev | Location | Change |
|---|---|---|---|
| S-01 | P2 | `walk` soft-skip | Use `map_protocol` (C# `TryMapProtocol` false → skip) instead of allocating `UnsupportedProtocol` on every unmapped container; `try_map_protocol` remains the public classification API |

---

## Rejected candidates

| Candidate | Reason |
|---|---|
| Soft-skip Connection with `InheritProtocol=true` + `Protocol=HTTP` should inherit parent SSH | C# skips on on-disk protocol first; intentional parity |
| Walk children of soft-skipped Connection | mRemoteNG Connections are leaves; C# returns early the same way |
| Map mRemoteNG HTTP→`ProtocolType::Http` | Explicit non-goal; AGENTS.md SSH/RDP/VNC-only |
| Share `assert_no_gap_protocol_mapping` via testkit | Over-broad for a crate-local helper |
| Normalize double-spaced `12-import.md` | Pre-existing formatting; out of soft-skip attack focus |
| Soften hostile XML (DOCTYPE / `..` / size) | Prior import-vpn ledger; must remain fail-closed |

---

## Adversarial clean passes (2 required)

Reset after each fix batch and after simplify implementation deltas.

### Clean pass 1 — order: security → boundaries → contract → concurrency → tests

- Soft-skip early-return before password decrypt; no HTTP→SSH; DOCTYPE/`..`/size still fail-closed.
- Empty / whitespace / Telnet / RAW / ICA / all-unsupported / container-HTTP covered.
- `try_map_protocol` classification + `plan_nodes` soft-skip contract documented.
- **Accepted findings:** none.

### Clean pass 2 — order: integration → test resistance → state → operability → security

- Fixture still skips `appliance-https` / `console-serial`; planned protocols only Ssh/Rdp/Vnc/None.
- Domain `ProtocolType::{Http,Https,Serial}` never appear on `PlannedNode` via import mapping.
- Skipped leaves do not increment `connection_count`; siblings still planned.
- **Accepted findings:** none.

`adversarial_clean_passes = 2` (after post-simplify re-loop on `map_protocol` walk; docs U-07 only).

---

## Iterative-review-simplify (3 clean cycles)

Each cycle: Code Reuse → Code Efficiency → Code Quality and Bugs (+ simplify discipline).

| Cycle | Themes | Outcome |
|---|---|---|
| 1 | Reuse (C# TryMapProtocol shape); efficiency (no UnsupportedProtocol alloc on container gaps); quality (clear soft-skip comment) | Applied S-01 → adversarial re-looped to 2 clean |
| 2 | No further duplication worth extracting; soft-skip sample format single-use; tests pin classification via `try_map_protocol` | Clean |
| 3 | Docs classification vs plan wording accurate; no overclaim of HTTP/Serial import; hostile XML tests untouched | Clean |

`simplify_clean_passes = 3`.

---

## Regression tests added/updated

- `protocol::rejects_http_https_serial_telnet_as_unsupported` (Telnet/RAW/ICA/trim; never remap to SSH)
- `mremoteng::soft_skips_http_https_serial_connection_leaves` (assert no gap protocol mapping)
- `mremoteng::soft_skips_telnet_and_raw_without_aborting_siblings`
- `mremoteng::container_unmapped_protocol_still_plans_ssh_children`
- `mremoteng::all_unsupported_connections_plan_succeeds_empty`
- `mremoteng::soft_skips_empty_protocol_as_unspecified_sample`
- `tests/mremoteng_sample.rs`: Telnet/RAW/ICA in parity; `sample_fixture_never_maps_https_or_serial_to_planned_protocol`

---

## Final verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-import
```

Results: **41 passed** (36 lib + 5 integration).

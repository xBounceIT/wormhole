# Adversarial ledger — WireGuard sidecar control plane

**Scope:** `rust/crates/wormhole-tunnels/` (especially `sidecar/`, WireGuard provider), `docs/migration/07-tunnels-mcp.md`, minimal workspace glue  
**Authority:** adversarial-review-fix (edit in scope; no Go sidecars under `tools/`; no C# production mutations)  
**Preserved:** `EstablishRefGuard` / lease coalesce semantics from prior tunnels review  
**Baseline (pre-fix):** `cargo test -p wormhole-tunnels` green (10 unit + 13 lease + 4 sidecar tests)

---

## Accepted findings and fixes

| ID | Sev | Location | Invariant / evidence | Fix | Verification |
|---|---|---|---|---|---|
| S-01 | P1 | `sidecar/process.rs` `read_ready_line` | `BufReader::read_line` unbounded — hostile sidecar without `\n` can grow memory until timeout | Cap read with `take(MAX_HANDSHAKE_LINE_BYTES+1)` + `read_until` | `oversized_stdout_is_rejected_and_process_dies` |
| S-02 | P1 | `sidecar/process.rs` stderr | Piped stderr never drained → OS pipe fill can deadlock sidecar (C# pumps stderr) | Background discard drain on stderr; post-READY stdout drain | `stderr_flood_does_not_deadlock_handshake` |
| S-03 | P1 | `sidecar/protocol.rs` | Trailing garbage / injection (`READY 1 evil`, control chars); oversized echo in errors | Digits-only port; reject controls; max 64 bytes; redact error snippets | unit + `parse_ready_and_socks_lines` |
| S-04 | P1 | `sidecar/locate.rs` `WORMHOLE_SIDECAR_DIR` | `..` / NUL in env can walk outside intended staging dir | `validate_sidecar_dir`; skip unsafe env; `locate_among` requires expected exe name | `sidecar_dir_rejects_path_traversal`, `locate_among_skips_wrong_file_name` |
| S-05 | P1 | lifecycle | Hang / bad READY / timeout must not leave Up or zombies | `kill_on_drop` + `Drop` `start_kill` + WireGuard `shutdown` on handshake Err; stdin EOF first | `hang_handshake_times_out_and_kill_reaps_child`, `bad_ready_line_…` |
| S-06 | P1 | coalesce + real provider | Lease coalesce only tested with `FakeTunnelProvider` | Concurrent establish via `WireGuardProvider` + delayed fake sidecar → one spawn | `wireguard_manager_coalesce_uses_one_sidecar_spawn` |
| S-07 | P2 | secrets | Stdin JSON must never appear in logs/errors | No payload logging; hang-path error asserts marker absent; fake sidecar never echoes stdin | `hang_handshake_…`, fake binary contract |
| S-08 | P2 | `WireGuardProvider::resolve_binary` | After S-04 name filter, test override `fake-tunnel-sidecar.exe` falsely `BinaryNotFound` | Explicit override uses `is_file()` only; search path still name-checked | all WireGuard+fake sidecar tests |

---

## Rejected candidates

| Candidate | Reason |
|---|---|
| Post-READY SOCKS liveness probe | Deferred (same as prior tunnels ledger); skeleton has no probe; READY is the connect gate |
| Zeroize `secret_blob` after stdin write | Caller-owned until secrets crate wires establish; not logged |
| Rewrite Go sidecars / change C# | Explicitly out of scope |
| Fail locate entirely when `WORMHOLE_SIDECAR_DIR` invalid | Skipping unsafe env + warn preserves fall-through to staged/tools paths; misconfig still yields BinaryNotFound if nothing found |
| Sync Drop without graceful stdin EOF | Intentional kill fallback; graceful path is async `shutdown` |
| Mutating `TunnelManager` / `EstablishRefGuard` | Preserved; no defect found in this pass |

---

## Adversarial clean passes (2 required)

### Clean pass 1 — order: concurrency → security → state → contract → tests

- Coalesce + `EstablishRefGuard` cancel/orphan paths unchanged; real-provider coalesce pinned.
- Secrets absent from tracing/errors; path `..`/NUL rejected; handshake bounded.
- Missing binary → `BinaryNotFound` through manager; never `Up` without READY.
- **Accepted findings:** none.

### Clean pass 2 — order: integration → boundaries → test resistance → operability → security

- Override vs search-path name trust; fake-sidecar modes cover hang/oversized/bad/stderr/delay.
- Boundary: empty secret, port 0, trailing junk, wrong exe name, pool eviction on bad READY.
- Operability: stderr/stdout drains; kill-on-drop; stdin-EOF shutdown.
- **Accepted findings:** none.

`adversarial_clean_passes = 2` (after post-simplify re-loop; no further implementation delta).

---

## Iterative-review-simplify (3 clean cycles)

Each cycle: Code Reuse → Code Efficiency → Code Quality and Bugs (+ simplify discipline).

| Cycle | Themes | Outcome |
|---|---|---|
| 1 | Reuse (`spawn_pipe_drain`, `validate_sidecar_dir`); efficiency (removed nested `BufReader` in drain); quality (unified `redact_handshake_line`) | Applied → reset adversarial → re-looped to 2 clean |
| 2 | Fake vs production provider separation intentional; Drop+`kill_on_drop` belt-and-suspenders kept; no hot-path churn | Clean |
| 3 | Docs/`07-tunnels-mcp.md` parity; lease suite untouched; no further validated edits | Clean |

`simplify_clean_passes = 3`.

---

## Regression tests added/updated

- `tests/sidecar_control_plane.rs` — oversized stdout, bad READY, hang timeout, stderr flood, path traversal, WireGuard coalesce, failure pool eviction, secret-not-in-error
- `sidecar/protocol.rs` unit — injection, controls, oversized error redaction
- `sidecar/locate.rs` unit — `..`/NUL, wrong file name skip
- `src/bin/fake_tunnel_sidecar.rs` — `--hang` / `--oversized` / `--bad-ready` / `--stderr-flood` / `--delay-ready`
- `tests/lease_coalesce.rs` — unchanged; still green (EstablishRefGuard preserved)

---

## Final verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-tunnels
cargo check -p wormhole-tunnels --no-default-features
```

Results: all green (14 lib unit + 13 lease + 11 sidecar control-plane).

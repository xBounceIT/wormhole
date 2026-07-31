# Adversarial ledger — mRemoteNG import + WatchGuard/Stormshield/Azure/Cisco wiring

**Scope:** `rust/crates/wormhole-import/`, `rust/crates/wormhole-tunnels/` providers for WatchGuard / Stormshield / Azure VPN / Cisco (+ shared `spawn` / `secret_shape`), `rust/crates/wormhole-testkit/fixtures/` import fixtures only, `docs/migration/12-import.md` (+ `07-tunnels-mcp.md` shape note)  
**Authority:** adversarial-review-fix (edit in scope; no Go sidecars; no C# mutations)  
**Preserved:** WireGuard / Fortinet READY bounds, locate `..`/NUL, lease `EstablishRefGuard` coalesce; SFTP untouched  
**Baseline (pre-fix):** `cargo test -p wormhole-import -p wormhole-tunnels` green

---

## Accepted findings and fixes

| ID | Sev | Location | Invariant / evidence | Fix | Verification |
|---|---|---|---|---|---|
| I-01 | P1 | `mremoteng.rs` XML | DOCTYPE/DTD accepted → XXE / entity-bomb surface (C# Inspect uses `DtdProcessing.Prohibit`) | Reject `Event::DocType` | `rejects_doctype_xxe` |
| I-02 | P1 | `parse_xml_path` / `inspect_xml` / backup | Unbounded `fs::read`; no path `..`/NUL gate | `limits::read_file_capped` (64 MiB + path validate) | `parse_path_rejects_parent_components`, `inspect_path_rejects_parent_dir` |
| I-03 | P1 | `backup::inspect_backup_json` | Unknown encryption treated as plaintext; full payload arrays materialized | Slim inspect envelope; `validate_encryption` | `inspect_rejects_unsupported_encryption` |
| I-04 | P1 | `crypto` + plan | AES-GCM stub must fail closed (already) — pin no forged plaintext + Debug redaction | Keep stub; redact `password_plaintext` / cipher / `Protected` in Debug | crypto units + `planned_node_debug_redacts_password` |
| I-05 | P2 | `mremoteng` tree | Unbalanced `Node` stack could leave incomplete tree | Fail if stack non-empty at EOF | `rejects_unbalanced_node` |
| I-06 | P2 | node count | Shallow-wide hostile XML unbounded | `MAX_NODE_COUNT` (100_000) | unit gate in parse |
| V-01 | P0 | `ovpn_backed` / OpenVPN | Editor DPAPI JSON / empty `profile_ovpn` + fake/`mock` READY → pretend Up | `require_openvpn_establish_secret` before spawn | `ovpn_backed_wrong_shape_…`, azure/wg unit shape tests |
| V-02 | P0 | `cisco.rs` | PascalCase `Host` editor blob + fake READY → pretend Up | `require_cisco_establish_secret` (`host`) | `cisco_wrong_shape_…` |
| V-03 | P2 | errors | Shape errors must not echo secrets | No blob in `TunnelError::Establish` messages | marker asserts in shape tests |

---

## Rejected candidates

| Candidate | Reason |
|---|---|
| Port BouncyCastle 16-byte-nonce AES-GCM now | Explicitly stubbed in spike; fail-closed is correct |
| Rewrite Go sidecars / mutate C# | Out of scope |
| Validate Fortinet/WireGuard JSON schemas | Out of attack focus; do not regress those providers |
| Soften path `..` reject for absolute `C:\a\..\b` | Intentional traversal gate for user-supplied paths |
| Zeroize secret_blob after stdin write | Caller-owned; not logged; prior tunnels ledger |

---

## Adversarial clean passes (2 required)

Reset after each fix batch and after simplify deltas that touched implementation.

### Clean pass 1 — order: security → boundaries → contract → concurrency → tests

- DOCTYPE rejected; path `..`/NUL; 64 MiB cap; encryption enum; Debug redaction; crypto stub.
- Shape gate: WG/SS/Azure/OpenVPN need `profile_ovpn`; Cisco needs `host`; secrets absent from errors.
- BinaryNotFound still returned for *valid* shape + missing exe; lease coalesce unchanged for Fake/WG/Forti.
- **Accepted findings:** none.

### Clean pass 2 — order: integration → test resistance → state → operability → security

- Fake sidecar READY cannot Up on editor blobs (integration).
- Fixture still skips HTTPS/Serial; `AAAAAA==` placeholder never decrypts to plaintext.
- OpenVPN lease missing-binary test uses valid shape JSON (no false Establish).
- **Accepted findings:** none.

`adversarial_clean_passes = 2` (after post-simplify re-loop; no further implementation delta).

---

## Iterative-review-simplify (3 clean cycles)

Each cycle: Code Reuse → Code Efficiency → Code Quality and Bugs (+ simplify discipline).

| Cycle | Themes | Outcome |
|---|---|---|
| 1 | Reuse (`require_*_establish_secret`); efficiency (slim backup inspect); quality (Protected/cipher Debug redact) | Applied → adversarial re-looped to 2 clean |
| 2 | Provider duplication for WG/Fortinet intentional; shape helpers shared; no hot-path churn | Clean |
| 3 | Docs/`12-import.md` + `07-tunnels-mcp.md` parity; fixture README unchanged (no secrets); no further validated edits | Clean |

`simplify_clean_passes = 3`.

---

## Regression tests added/updated

- `wormhole-import`: DOCTYPE, unbalanced Node, path `..`, encryption reject, Debug redact, limits units
- `wormhole-tunnels` `secret_shape` + ovpn_backed/cisco units: editor blob / empty profile / PascalCase Host
- `sidecar_control_plane.rs`: `ovpn_backed_wrong_shape_…`, `cisco_wrong_shape_…`
- `lease_coalesce.rs`: OpenVPN missing-binary uses valid `profile_ovpn` JSON

---

## Final verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-import -p wormhole-tunnels
```

Results: all green (import 15 unit + 4 integration; tunnels 32 lib unit + 14 lease + 24 sidecar).

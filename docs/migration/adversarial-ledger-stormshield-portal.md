# Adversarial ledger — Stormshield portal / cache / ConfirmTrust Fake glue

**Scope:** `rust/crates/wormhole-tunnels/src/providers/stormshield/portal.rs` (new)
+ registration in `stormshield/mod.rs` + `pub(crate)` seam promotions in
`stormshield/establish.rs` + crate-root export block in `lib.rs`.

**Out of scope:** live portal HTTPS / OpenVPN spawn; credential-store persistence of
trust consent; SSO (SNS SAML) live flow; other provider dirs.

**Compared against:** C# `Services/Tunneling/Stormshield/*` (portal config download,
DPAPI profile cache, single-use OTP reuse guard, `ConfirmTrust`,
`ExtractOpenVpnRemotes`), `Services/Tunneling/WindowsPhysicalNetworkPathService.cs`;
prior ledgers `adversarial-ledger-physical-path.md` and
`adversarial-ledger-stormshield-establish.md`.

**Authority:** full adversarial-review-fix (reviewer subagent; parent re-verified)  
**Baseline:** tunnels lib **394**; stormshield portal module **27**  
**Final:** tunnels lib **403**; portal module **36**; stormshield module total **51**

**Attack focus:** OTP reuse window boundary (strict `<` vs `<=`), cache currency
marker gate (`LooksLikeOpenVpnProfile`), transport preflight against the profile's
`remote` hosts (not `settings.server`), empty/whitespace password handling, CRLF
normalization, ConfirmTrust cancel fail-closed, physical-path Unknown fail-closed,
Debug redaction of OTP/passwords.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (+ delta re-attack on simplify relocation) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-tunnels --lib` | **pass** (403) |
| `cargo check -p wormhole-tunnels --lib` / `--features secrets` | **pass** |
| `git diff --check` (scoped) | **pass** |

---

## Accepted findings and fixes

| ID | Sev | Finding | Fix |
|---|---|---|---|
| SSP-1 | P3 | Whitespace-only password passed validation (`is_empty()` vs C# `IsNullOrWhiteSpace`) | Trim check |
| SSP-2 | P2 | Transport preflight classified `settings.server` instead of the profile `remote` hosts; profiles with no usable `remote` never failed closed | New `extract_ovpn_remote_hosts` (C# tokenizer/opaque-block/connection-scope parity, CRLF normalization); `require_physical_path` takes a host slice, per-host fail-closed + empty-hosts guard; `establish_stormshield_portal` gates + preflights real transport destinations |
| SSP-3 | P3 | Cache currency lacked the C# `LooksLikeOpenVpnProfile` marker gate — valid-schema HTML/garbage cached body was reused | `looks_like_openvpn_profile` + gate in `stormshield_cache_record_is_current` |
| SSP-4 | P3 | OTP reuse window `age <= window` vs C# strict `<` (rejected at exactly 90 s) | Strict comparison |
| SSP-5 | P3 | Stale `mod.rs` doc "Portal HTTPS / config-hash cache / SSO remain TODO" contradicted delivered glue | `mod.rs` header + doc-matrix rows for the two new fail-closed rows |

## Regression tests added (9)

`cached_profile_without_usable_remote_fails_closed`, `fresh_profile_without_remote_fails_closed_before_sidecar`,
`transport_unknown_profile_remote_fails_closed`, `cache_body_not_looking_like_ovpn_treated_as_miss`,
`extract_ovpn_remote_hosts_parses_remotes_and_skips_noise`, `extract_ovpn_remote_hosts_empty_without_usable_remote`,
`extract_ovpn_remote_hosts_normalizes_crlf_and_cr`, `looks_like_openvpn_profile_marker_gate`,
`require_physical_path_fails_closed_on_empty_hosts`; strengthened OTP boundary (89/90/91 s) +
whitespace-password preflight; fixtures updated (`ethernet_probe` remote override, seeded profile markers).

### Rejected candidates

Stale per-fetcher TLS-failure semantics (live in unported managed client; Fake scripts
state); C# trust-consent persist/gate (credential store unported); port-range
validation on portal URL (explicitly unported); `thumbprint_prefix` duplication with
`tls_trust_prompt.rs` (out-of-scope module).

---

## Test command

```powershell
cd rust
cargo test -p wormhole-tunnels --lib providers::stormshield
cargo test -p wormhole-tunnels --lib
```

**Counts:** portal **36/36**; full tunnels lib **403**.
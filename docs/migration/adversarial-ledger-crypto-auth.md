# Adversarial ledger — mRemoteNG AES-GCM + ovpn `auth_glue`

**Scope:** `rust/crates/wormhole-import/` (AES-GCM / password decrypt), `rust/crates/wormhole-tunnels/src/providers/auth_glue/` (+ `OpenVpnSidecarConfig` / establish shape), fixtures under `wormhole-testkit` used by import decrypt tests; docs `12-import.md` / `07-tunnels-mcp.md` / `04-secrets.md` as needed  
**Authority:** full adversarial-review-fix (edit in scope)  
**Baseline:** `cargo test -p wormhole-import -p wormhole-tunnels` green before review  
**Compared against:** `Services/MRemoteNg/MRemoteNgCrypto.cs`, `OpenVpnSidecarConfig.cs`, `AzureVpnTunnelProvider.AadAuthUsername`

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix; re-run after simplify) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-import -p wormhole-tunnels` | **pass** |

---

## Accepted findings

### CRYPTO-01 — AEAD negative paths under-tested (`P1`) — **fixed**

- **Where:** `wormhole-import/src/crypto.rs` tests
- **Invariant:** 16-byte nonce layout; reject truncated / wrong-tag / tampered AAD (salt) / flipped ciphertext; never forge plaintext
- **Evidence:** Round-trip + wrong-password covered; salt/tag/ciphertext mutation and truncated tag lacked regressions
- **Fix:** Added `tampered_aad_salt_fails_closed`, `flipped_tag_byte_fails_closed`, `truncated_tag_fails_closed`, `flipped_ciphertext_byte_fails_closed`, empty-ciphertext min-blob round-trip, layout constant asserts
- **Regression:** those unit tests + existing fixture vector `lab-secret`

### CRYPTO-02 — PBKDF2 key wipe not panic-safe (`P2`) — **fixed**

- **Where:** `decrypt_password_utf8`
- **Invariant:** Match C# `CryptographicOperations.ZeroMemory(key)` in `finally`
- **Evidence:** Manual `key.zeroize()` after a closure skipped wipe on panic between derive and return
- **Fix:** `Zeroizing<[u8; 32]>` for the derived key
- **Regression:** existing decrypt suite (behavior unchanged)

### CRYPTO-03 — Decrypt errors must not echo passwords (`P2`) — **fixed** (coverage)

- **Where:** `DecryptError` Display/Debug
- **Evidence:** Unit struct already opaque; missing explicit regression
- **Fix:** `decrypt_error_display_and_debug_do_not_echo_password`

### AUTH-01 — Secret-bearing types leaked via `Debug` (`P1`) — **fixed**

- **Where:** `OpenVpnSidecarConfig`, `ResolvedOvpnMaterials`, WatchGuard / Stormshield / Azure cache records
- **Invariant:** No plaintext password / refresh token / profile in errors/Debug (parity with `PlannedNode` redaction)
- **Evidence:** `#[derive(Debug)]` printed `password`, `challenge_response`, `refresh_token`, `profile_ovpn`
- **Fix:** Custom `Debug` with `[REDACTED]`; shared `redact_nonempty`
- **Regression:** `debug_redacts_*`, `materials_debug_redacts_secrets`, `azure_cache_debug_redacts_refresh_token`

### AUTH-02 — Auth-glue / cache fail-closed gaps under-tested (`P1`) — **fixed**

- **Where:** `builders.rs`, `cache.rs`
- **Invariant:** Azure username forced to `AzureAD`; empty/malformed cache / DPAPI failures fail closed without echoing secrets; constructed JSON passes establish shape gate
- **Evidence:** Weak “no echo” test used malformed JSON **without** a secret present; missing wrong-username override, empty refresh/hash, wrong schema, whitespace Azure password
- **Fix:** Stronger decode/builder tests; DPAPI wrong-entropy assert (Windows + `secrets`); Azure override + whitespace reject
- **Regression:** listed auth_glue unit tests

### AUTH-03 — WatchGuard/Stormshield builder duplication (`P3`) — **fixed** (simplify)

- **Where:** `builders.rs`
- **Fix:** Shared `passthrough_sidecar_config` (behavior preserved)

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Empty cipher → Rust `Ok(None)` vs C# `TryDecryptUtf8` false — intentional API; plan path gated by `password_requires_decrypt` / C# `PasswordFieldRequiresDecryption` |
| REJ-02 | — | Azure DPAPI/JSON miss-as-null in C# vs Rust `Err` — intentional fail-closed; never echoes blob |
| REJ-03 | — | Constant-time password compare — N/A; fail-closed is KDF+GCM tag check |
| REJ-04 | — | Huge `KdfIterations` DoS — matches C# / external format |
| REJ-05 | — | Zeroize GCM plaintext on UTF-8 failure — C# only zeros key; out of scope hardening |
| REJ-06 | — | Interactive SAML / Entra WebView2 / OTP — explicitly out of scope |
| REJ-07 | — | Azure identity-hash / max-age on cache read — C# interactive path; decode spike only |
| REJ-08 | — | `redact_option` helper for `Option<String>` Debug fields — over-abstract for two call sites |

---

## Adversarial cycles

1. **Cycle 1 (findings):** CRYPTO-01/03, AUTH-01/02 accepted → fixed + regressions → reset  
2. **Cycle 2 (findings):** CRYPTO-02 accepted → Zeroizing → reset  
3. **Clean pass 1:** Security → boundaries → contract; no accepted findings (independent of cycle 1 order)  
4. **Clean pass 2:** C# parity / integration drift / test resistance; REJ-01..08; no accepted findings  
5. **Post-simplify adversarial re-run:** 2 clean passes on `passthrough_sidecar_config` + `redact_nonempty` delta (no accepted findings)

---

## Iterative-review-simplify cycles

1. **Cycle 1 (fixes):** reuse (`passthrough_sidecar_config`, `redact_nonempty`); quality (vacuous azure whitespace assertion cleaned; dead `debug_assert` removed)  
2. **Clean pass 1:** reuse / efficiency / quality — no validated findings  
3. **Clean pass 2:** same — no findings  
4. **Clean pass 3:** same — no findings  

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-import -p wormhole-tunnels
```

Focused: `cargo test -p wormhole-import --lib crypto::` · `cargo test -p wormhole-tunnels --lib providers::auth_glue::`

---

## Residual / out-of-scope notes

- Concurrent workspace WIP elsewhere (`wormhole-update`, SOCKS forwarder) briefly broke `cargo test`; not part of this ledger’s accepted findings. A one-line `use std::net::SocketAddr` in `socks5.rs` tests was required to keep the tunnels package compiling for the required gate.
- Fixture `mremoteng-sample.xml` / known vector unchanged and still green.

# Adversarial ledger — WatchGuard establish-path glue

**Scope:** `rust/crates/wormhole-tunnels/src/providers/watchguard/establish.rs` (+ re-exports in `watchguard/mod.rs` / `providers/mod.rs` / `lib.rs`); docs `07-tunnels-mcp.md` WatchGuard establish section  
**Authority:** full adversarial-review-fix (edit in scope; do **not** rewrite `WatchguardProvider::establish` OpenVPN spawn / live Firebox HTTP)  
**Baseline:** `cargo test -p wormhole-tunnels --lib providers::watchguard::establish` green (14 tests) before review  
**Compared against:** sibling establish glue (OpenVPN / Cisco / Azure / Stormshield) + Firebox auth stub contracts (`resolve_firebox_*`)

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (post-fix; re-run after simplify) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-tunnels` | **pass** (full crate suite) |
| Focused establish tests | **16** (was 14; +shape / empty-creds / portal Null OTP / stdin capture) |

---

## Accepted findings

### WGE-01 — Portal Null OTP fail-closed under-pinned (`P2`) — **fixed**

- **Where:** `establish_watchguard_portal` + docs Fail-closed row
- **Invariant:** `NullOtpPrompt` / cancel → `TunnelError::Cancelled` on **both** CRV1 and portal; never echo password; provider not called
- **Evidence:** only `null_otp_on_crv1_*` existed; portal share of the contract was docs-only
- **Fix:** `null_otp_on_crv1_and_portal_fails_closed_without_echo`
- **Regression:** that test

### WGE-02 — CRV1 / portal stdin field fork under-pinned at establish→provider (`P2`) — **fixed**

- **Where:** `establish_watchguard_crv1` / `establish_watchguard_portal` tests
- **Invariant:** CRV1 keeps account password + OTP in `challenge_response`; portal OTP→OpenVPN `password` and omits challenge; Recording Debug never dumps stdin
- **Evidence:** `FakeTunnelProvider` discards the blob; portal test name claimed the quirk without asserting fields (Azure establish uses a recording Fake for the same reason)
- **Fix:** test-local `RecordingWatchguardProvider` (length-only `Debug`); strengthen CRV1 / portal / push tests + `auth_then_secret_store` challenge assert
- **Regression:** those tests

### WGE-03 — Empty Firebox credentials on auth establish paths under-pinned (`P2`) — **fixed**

- **Where:** `establish_watchguard_crv1` / `_portal` → `FireboxCredentials::validated`
- **Invariant:** empty / whitespace-only username or password → `TunnelError::Establish` before provider; errors never echo password markers (Cisco sibling pins the same on auth path)
- **Evidence:** validated covered in `firebox_auth` only; establish glue lacked end-to-end pin
- **Fix:** `auth_path_empty_credentials_fail_without_echo`
- **Regression:** that test

### WGE-04 — Whitespace `profile_ovpn` / invalid JSON secret under-pinned (`P2`) — **fixed**

- **Where:** `establish_watchguard` → `require_openvpn_establish_secret`
- **Invariant:** whitespace-only `profile_ovpn` and non-JSON blobs fail closed before provider; never echo secret markers (OpenVPN sibling pins both)
- **Evidence:** empty + PascalCase editor blob covered; whitespace / invalid JSON not
- **Fix:** `whitespace_profile_and_invalid_json_reject_without_echo`
- **Regression:** that test

### WGE-05 — Missing establish ledger / README / docs link (`P3`) — **fixed**

- **Where:** `docs/migration/README.md`, `07-tunnels-mcp.md`
- **Invariant:** closed review discoverable; Fail-closed wording matches Null OTP on both paths + shape / empty-creds
- **Evidence:** auth ledger existed; establish-path glue lacked its own ledger row / section link
- **Fix:** this ledger + README row + WatchGuard establish section + adversarial list link
- **Regression:** doc review

### WGE-06 — Auth-path fail-closed docs under-stated empty creds (`P3`) — **fixed** (simplify)

- **Where:** `establish_watchguard_crv1` / `_portal` rustdoc
- **Fix:** document empty username / whitespace-only password → `Establish` (never echoes)
- **Regression:** doc review + empty-creds test

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Wire live Firebox HTTP / SAML / portal download — explicitly out of scope |
| REJ-02 | — | Rewrite `WatchguardProvider::establish` / ovpnproxy spawn — forbidden by review authority |
| REJ-03 | — | Add `last_secret` to shared `FakeTunnelProvider` — broader fake surface; Azure/WatchGuard keep test-local recording |
| REJ-04 | — | Zeroize password/OTP on `Drop` — hardening beyond C# / stub surface |
| REJ-05 | — | Duplicate wrong-kind tests on portal/crv1 — shared `load_watchguard_record`; secret-path + missing-config auth paths already pin fail-closed |
| REJ-06 | — | Extract shared Recording provider crate helper — one-off test double; sibling Azure keeps local |
| REJ-07 | — | `secret_len` in tracing — length only; same as OpenVPN / Stormshield / Azure establish |
| REJ-08 | — | Align `PayloadStoreSecretLookup` import path with OpenVPN — both resolve; Stormshield uses crate re-export |

---

## Adversarial cycles

1. **Cycle 1 (findings):** WGE-01..05 accepted → portal Null OTP / stdin capture / empty creds / whitespace+JSON / docs → reset  
2. **Clean pass 1:** Security → boundaries → contract (redaction, Cancelled, CRV1 vs portal fields, shape gate, empty creds) — no accepted findings  
3. **Clean pass 2:** Integration drift / test resistance (exports; Fake vs Recording Debug; no live Firebox; REJ-01..08) — no accepted findings  
4. **Post-simplify adversarial re-run:** 2 clean passes on rustdoc fail-closed delta + ledger — no accepted findings  

---

## Iterative-review-simplify cycles

1. **Cycle 1 (fixes):** quality — CRV1/portal rustdoc empty-creds; test helpers `expect_tunnel_err` / `assert_no_secret_echo`; Recording Debug length-only  
2. **Clean pass 1:** reuse / efficiency / quality — no validated findings (REJ shared Recording / import-path taste)  
3. **Clean pass 2:** same — no findings  
4. **Clean pass 3:** same — no findings  

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-tunnels --lib providers::watchguard::establish
cargo test -p wormhole-tunnels
```

---

## Residual / out-of-scope notes

- Portal HTTP download, SAML WebView2, and AuthPoint push web long-poll remain unwired — profile text is caller-supplied.
- Data plane remains shared `wormhole-ovpnproxy` via `WatchguardProvider` (not exercised by these unit tests).
- Context7 MCP was unavailable in this workspace; review used in-repo sibling establish / auth ledgers and crate sources.
- Concurrent Fortinet establish WIP blocked crate compile via `unwrap_err` requiring `Debug` on `Arc<dyn TunnelInstance>`; replaced those two sites with `match` so `cargo test -p wormhole-tunnels` could run (behavior unchanged).

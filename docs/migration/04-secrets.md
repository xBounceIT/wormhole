# 04 — Secrets crate (`wormhole-secrets-win`)

**Status:** Phase-1 API green (`cargo test -p wormhole-secrets-win`)  
**Crate:** `rust/crates/wormhole-secrets-win`  
**Pin:** `windows = "=0.61.3"` (CredMgr + DPAPI features) — see [deps-pins.md](deps-pins.md)

Windows-only secrets surface that must stay **byte-compatible** with the shipping
.NET app so a Rust host can open existing `%LOCALAPPDATA%\Wormhole` profiles.

Targets: `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc`. Non-Windows
builds compile stubs that return `SecretsError::UnsupportedPlatform`.

---

## Compatibility rule

| Store | Must match C# exactly |
|---|---|
| CredMgr target | `Wormhole:` + `Guid.ToString()` (D-format, lowercase hyphens) |
| CredMgr type / persist | `CRED_TYPE_GENERIC` + `CRED_PERSIST_LOCAL_MACHINE` |
| CredMgr username | `Guid.ToString()` |
| CredMgr comment | `Wormhole credential` |
| Key / tunnel files | `\<guid:N>.dpapi` under `keys\` / `tunnels\` — paths **confined** (no `..` / absolute escape); see Path confinement |
| Azure tokencache | `\<guid:N>.tokencache` under `azurevpn-cache\` — paths **confined** (same helpers); **not** keys/tunnels stores |
| DPAPI scope | CurrentUser (`CryptProtectData` without `CRYPTPROTECT_LOCAL_MACHINE`) |
| Optional entropy | Per table below (null vs UTF-8 name vs `Guid.ToByteArray()`) |

`.NET Guid.ToByteArray()` is **mixed-endian** (Microsoft GUID layout). In Rust use
`uuid::Uuid::to_bytes_le()` / `wormhole_secrets_win::guid_to_dotnet_bytes` — **not**
RFC 4122 `as_bytes()`.

### Path confinement (keys / tunnels / azurevpn-cache)

Private-key and tunnel-payload files must stay under
`%LOCALAPPDATA%\Wormhole\keys\` and `…\tunnels\` respectively. Entra refresh-token
blobs stay under `…\azurevpn-cache\` (distinct store — do **not** reuse keys/tunnels).

| Helper | Behavior |
|---|---|
| `key_path` / `tunnel_path` | Default profile paths; `Result` — fails if the resolved root contains `..` |
| `key_path_under` / `tunnel_path_under` / `azure_vpn_token_cache_path_under` | Same join under an injectable root (unit tests use `tempfile`) |
| `confined_file_under` | Single-segment file name under a root; rejects separators / absolute / `..` |
| `ensure_confined_under` | Lexical prefix check; rejects empty root (`starts_with("")` is vacuous), `..` in root or path, and absolute / prefix escapes |
| `write_key_payload(_under)` / `read_*` / `delete_key_payload(_under)` / tunnel siblings | Null-entropy DPAPI CRUD **only after** path confinement (hostile root → no mkdir / read / delete) |
| `write_azure_vpn_token_cache(_under)` / `read_*` / `clear_*` | Tunnel-id entropy + **atomic** DPAPI CRUD under `azurevpn-cache\` (confined); opaque bytes only |
| `KeyMaterialStore` / `DpapiKeyMaterialStore` / `FakeKeyMaterialStore` | Private-key CRUD stub under `keys\` (opaque blob by credential id); Fake Debug length-only; store/read defensive copies; delete never unprotects |
| `TunnelPayloadStore` / `DpapiTunnelPayloadStore` / `FakeTunnelPayloadStore` | Tunnel secret CRUD stub under `tunnels\` — **distinct** from keys (same non-atomic write as C# CredentialService); SQLite `TunnelConfigs` metadata-only; Fake Debug length-only; store/read defensive copies; delete never unprotects; fails closed outside `tunnels\` (no sibling `keys\` escape) |
| `AzureVpnTokenCacheStore` / `DpapiAzureVpnTokenCacheStore` / `FakeAzureVpnTokenCacheStore` | Entra refresh-token blob CRUD under `azurevpn-cache\` (opaque JSON bytes; identity/schema in `wormhole-tunnels::auth_glue`); Fake Debug length-only; clear never unprotects |
| `SecretsError::PathNotConfined` | Escape rejected — **Display/Debug never embed the path string or key material** |

Lexical only (no symlink follow) — same class as settings / import path guards.
Single-segment names also reject Windows join-replacement forms (`D:evil`, `\Windows\…`).
**Never** log key, tunnel, or refresh-token plaintext; prefer `redact_secret` and length-only diagnostics.
See [adversarial-ledger-dpapi-paths.md](adversarial-ledger-dpapi-paths.md),
[adversarial-ledger-key-dpapi-crud.md](adversarial-ledger-key-dpapi-crud.md),
[adversarial-ledger-tunnel-payload-dpapi.md](adversarial-ledger-tunnel-payload-dpapi.md), and
[adversarial-ledger-entra-token-cache.md](adversarial-ledger-entra-token-cache.md).

---

## Entropy table

| Path / blob | Entropy | Implemented in crate? |
|---|---|---|
| `keys\<id:N>.dpapi` | **none** (`null`) | Yes — `key_path` / `KeyMaterialStore` write/read/delete (confined); metadata stays in SQLite |
| `tunnels\<id:N>.dpapi` | **none** (`null`) | Yes — `tunnel_path` / `TunnelPayloadStore` write/read/delete (confined); SQLite metadata-only |
| `app-auth.dpapi` | UTF-8 `Wormhole.AppAuthentication.v1` | Path + entropy + stub unlock (`app_auth`); Hello availability / WinRT gap in `hello` |
| `bitwarden-browser-storage.dpapi` | UTF-8 `Wormhole.BitwardenBrowser.SharedStorage.v1` | Entropy + path helpers; storage protocol later |
| `stormshield-cache\<id:N>.ovpncache` | `tunnelConfigId.ToByteArray()` | Path + `tunnel_id_entropy`; cache JSON decode in `wormhole-tunnels::auth_glue` |
| `watchguard-cache\<id:N>.ovpncache` | `tunnelConfigId.ToByteArray()` | Path + `tunnel_id_entropy`; cache JSON decode in `wormhole-tunnels::auth_glue` |
| `azurevpn-cache\<id:N>.tokencache` | `tunnelConfigId.ToByteArray()` | Path + `tunnel_id_entropy` + confined CRUD (`AzureVpnTokenCacheStore`); JSON / identity / max-age in `wormhole-tunnels::auth_glue` (`AzureVpnRefreshTokenCache`) |

Constants:

```text
APP_AUTHENTICATION_V1            = "Wormhole.AppAuthentication.v1"
BITWARDEN_BROWSER_SHARED_STORAGE = "Wormhole.BitwardenBrowser.SharedStorage.v1"
```

### Fortinet (no DPAPI blob)

Fortinet SAML does **not** persist secrets via DPAPI. Embedded login uses a
dedicated WebView2 profile under `%LOCALAPPDATA%\Wormhole\fortinet-saml-webview2\`
and yields an ephemeral `SVPNCOOKIE` / `auth_id` sent only on sidecar stdin
(`FortinetSamlAuthService`). List it here so agents do not invent a Fortinet
`.dpapi` file.

Related WebView2 profiles (cookies = secret *data*, not CredMgr):

| Profile root | Role |
|---|---|
| `fortinet-saml-webview2\` | Embedded Fortinet SAML |
| `azurevpn-webview2\` | Entra interactive sign-in (refresh token still in `azurevpn-cache`) |
| `watchguard-saml-webview2\` | WatchGuard SAML portal |
| `bitwarden-browser-webview2\` | Bitwarden extension tabs (sync via DPAPI shared storage) |

---

## CredMgr API (password store CRUD)

High-level set/get/delete over Windows Credential Manager — mirrors C#
`StorePasswordAsync` / `ReadPasswordAsync` / `DeletePasswordAsync`. Distinct from
DPAPI key / tunnel payload files (`keys\` / `tunnels\`).

| Item | Value |
|---|---|
| Prefix | `Wormhole:` |
| Target example | `Wormhole:a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b91` |
| MCP fixed id | `a7f3c1e2-9b6d-4e8a-bf21-7c0d2e5a4b91` (`MCP_TOKEN_CREDENTIAL_ID`) |
| Max secret | **2560** UTF-16 bytes (Windows 7+ / `CRED_MAX_CREDENTIAL_BLOB_SIZE` = 5×512) — count with `password_utf16_byte_len` (`encode_utf16` × 2). **Not** `str::len() * 2` (UTF-8 false-reject on BMP) and **not** `chars().count() * 2` (scalar under-count → false-accept on surrogate pairs). At-limit (2560) is allowed (`>`). |
| Oversize | Rejected **before** `CredWriteW` / fake insert via `ensure_password_fits_cred_mgr` → `SecretsError::PasswordTooLarge { bytes }` (size only; never the password). `FakePasswordStore` Debug exposes entry UTF-16 lengths + call counts only. |
| DI | `PasswordStore` trait — `WinCredPasswordStore` (thin adapter over free helpers) / `FakePasswordStore` (in-memory unit tests; no Win32 vault; Mutex-safe; Debug lengths + call counts only) |
| Missing delete | `Ok(())` for both backends (C# best-effort); missing read → `Ok(None)` |
| Blob shape | Length-prefixed UTF-16 (embedded NUL survives); `CredReadW` buffer freed via Drop guard |

Rust:

```rust
use wormhole_secrets_win::{
    credential_target, store_password, read_password, delete_password,
    ensure_password_fits_cred_mgr, FakePasswordStore, PasswordStore, MCP_TOKEN_CREDENTIAL_ID,
};

store_password(&id, "secret")?;
let pw = read_password(&id)?; // Ok(None) if missing
delete_password(&id)?;        // missing → Ok(())

// Unit tests: in-memory store (no Win32 vault); same 2560-byte pre-write guard.
let fake = FakePasswordStore::new();
fake.store(&id, "secret")?;
```

**Never** log password material. Prefer `redact_secret` before logging around auth;
`SecretsError` / `FakePasswordStore` Debug never embed the password string.

**Storage glue:** `wormhole-storage::credential_glue` creates/renames/deletes
`CredentialProfiles` **metadata** only. When deleting, callers may pass
`CredentialSecrets` (tests: `MemoryCredentialSecrets`, or an adapter over
`FakePasswordStore` + `FakeKeyMaterialStore`) so CredMgr / `keys\` cleanup stays
out of band after the SQLite row is gone. Password bodies never enter SQLite.

### Credential picker search (UI metadata only)

Saved-credential **picker filtering** (C# `CredentialPickerSearch.Filter`) lives in
`wormhole-ui::credential_picker` — `CredentialProfileRow` metadata (`id` / `name` /
`username` / `domain`), `FakeCredentialList`, and case-insensitive substring filter.
That glue **never** reads CredMgr / DPAPI; empty query returns all rows in stable order.
See [20-connection-editor.md](20-connection-editor.md).

---

## DPAPI API

```rust
use wormhole_secrets_win::{
    protect, unprotect, write_protected_file, read_protected_file,
    write_protected_file_atomic, key_path, tunnel_path,
    write_key_payload_under, read_key_payload_under, delete_key_payload_under,
    write_tunnel_payload_under, read_tunnel_payload_under, delete_tunnel_payload_under,
    DpapiKeyMaterialStore, FakeKeyMaterialStore, KeyMaterialStore,
    DpapiTunnelPayloadStore, FakeTunnelPayloadStore, TunnelPayloadStore,
    APP_AUTHENTICATION_V1, tunnel_id_entropy,
};

// keys / tunnels — null entropy (prefer payload helpers: confined path + I/O)
let blob = protect(key_bytes, None)?;
let plain = unprotect(&blob, None)?;

write_protected_file(&key_path(&cred_id)?, key_bytes, None)?;
// tunnels — same non-atomic write as C# CredentialService (caches use atomic separately)
write_protected_file(&tunnel_path(&tunnel_id)?, secret, None)?;

// Private-key CRUD stub (opaque blob only — metadata stays in SQLite / domain)
let keys = DpapiKeyMaterialStore::under(&keys_root);
keys.store(&cred_id, key_bytes)?;
let _ = keys.read(&cred_id)?;
keys.delete(&cred_id)?; // missing → Ok(()); never unprotects on delete

// Tunnel payload CRUD stub — distinct from KeyMaterialStore (tunnels\ root).
// SQLite TunnelConfigs = metadata only; secrets only in DPAPI files.
let tunnels = DpapiTunnelPayloadStore::under(&tunnels_root);
tunnels.store(&tunnel_id, secret)?;
let _ = tunnels.read(&tunnel_id)?;
tunnels.delete(&tunnel_id)?; // missing → Ok(()); never unprotects on delete

// Tests: in-memory fakes (no DPAPI); Debug never echoes secret bytes
let fake_key = FakeKeyMaterialStore::new();
fake_key.store(&cred_id, key_bytes)?;
let fake_tun = FakeTunnelPayloadStore::new();
fake_tun.store(&tunnel_id, secret)?;

// Alternate roots: confine under a temp `keys` / `tunnels` directory
write_key_payload_under(&keys_root, &cred_id, key_bytes)?;
let _ = read_key_payload_under(&keys_root, &cred_id)?;
delete_key_payload_under(&keys_root, &cred_id)?;
write_tunnel_payload_under(&tunnels_root, &tunnel_id, secret)?;
let _ = read_tunnel_payload_under(&tunnels_root, &tunnel_id)?;
delete_tunnel_payload_under(&tunnels_root, &tunnel_id)?;

// named / per-tunnel
protect(verifier, Some(APP_AUTHENTICATION_V1))?;
protect(json, Some(&tunnel_id_entropy(&tunnel_id)))?;
```

---

## Redaction

Never log passwords, key material, refresh tokens, or session keys.

| Helper | Behavior |
|---|---|
| `redact_secret` | Always `"[redacted]"` |
| `redact_truncated` | Trim + cap at **500 Unicode scalars** (not raw UTF-8 bytes) |
| `redact_env_and_cli_secrets` | Case-insensitive Bitwarden CLI sanitize: `--session`/`=` , `BW_SESSION=`, `--code`/`=`, `WORMHOLE_BW_PASSWORD=` (optional spaces around `=`), then truncate |

[`SecretsError`](../../rust/crates/wormhole-secrets-win/src/lib.rs) never carries secret payloads — `Display`/`Debug` only expose ops, Win32 codes, sizes, and I/O messages. `EmptyPassword` is intentionally payload-free (fail-closed transient `store`).


---

## Public API surface (summary)

| Module | Exports |
|---|---|
| `cred_mgr` | `CREDENTIAL_PREFIX`, `CREDENTIAL_COMMENT`, `MAX_PASSWORD_UTF16_BYTES`, `MCP_TOKEN_CREDENTIAL_ID`, `credential_target`, `password_utf16_byte_len`, `ensure_password_fits_cred_mgr`, `store_password`, `read_password`, `delete_password`, `PasswordStore`, `WinCredPasswordStore`, `FakePasswordStore` (tests; Debug never echoes secrets) |
| `dpapi` | `protect`, `unprotect`, `write_protected_file`, `write_protected_file_atomic`, `read_protected_file`, `delete_protected_file_if_exists` |
| `entropy` | `APP_AUTHENTICATION_V1`, `BITWARDEN_BROWSER_SHARED_STORAGE_V1`, `guid_to_dotnet_bytes`, `tunnel_id_entropy`, accessors |
| `paths` | `wormhole_app_data_dir`, `keys_dir`, `tunnels_dir`, `azure_vpn_cache_dir`, `key_path` / `tunnel_path` (`Result`), `key_path_under` / `tunnel_path_under` / `azure_vpn_token_cache_path_under`, `confined_file_under`, `ensure_confined_under`, `app_authentication_path`, `bitwarden_browser_shared_storage_path`, Bitwarden WebView2 / extension path helpers, Stormshield/WatchGuard/Azure cache dirs + paths |
| `key_tunnel` | `KeyMaterialStore` / `DpapiKeyMaterialStore` / `FakeKeyMaterialStore`; `TunnelPayloadStore` / `DpapiTunnelPayloadStore` / `FakeTunnelPayloadStore`; `write`/`read`/`delete_*_payload` (+ `_under`) — null entropy, path-confined, coherent non-atomic write (C# CredentialService); Fake Debug length-only + defensive copies; delete never unprotects; metadata stays out of DPAPI blobs |
| `azure_vpn_token_cache` | `AzureVpnTokenCacheStore` / `DpapiAzureVpnTokenCacheStore` / `FakeAzureVpnTokenCacheStore`; `write`/`read`/`clear_azure_vpn_token_cache` (+ `_under`) — tunnel-id entropy, atomic write, path-confined under `azurevpn-cache\`; opaque bytes only |
| `app_auth` | `protect_app_authentication`, `unprotect_app_authentication`, read/write/unlock store helpers, `AppAuthUnlock` (Debug redacts plaintext) |
| `hello` | `AvailabilityProbe` / `HelloPrompt` traits, `StubHelloPrompt` (fail-closed), `FakeHelloPrompt` (tests, no UI), free helpers `is_remote_desktop_session` / `check_hello_availability` / `request_hello_verification`, `WINRT_HELLO_GAP`, `REMOTE_DESKTOP_UNAVAILABLE_MESSAGE` |
| `bitwarden_session` | `BitwardenSession` trait, `StubBitwardenSession` (fail-closed), `FakeBitwardenSession` (tests, no `bw`), `BitwardenSessionKey` (Debug redacts), `BITWARDEN_CLI_SESSION_GAP`, free helpers `unlock_bitwarden_session` / `bitwarden_session_status` |
| `transient_session` | `TransientSessionCredentialStore` trait, `MemoryTransientSessionCredentialStore` (production in-process), `FakeTransientSessionCredentialStore` (tests; Debug length-only + call counts); **never** SQLite / CredMgr / DPAPI; empty password → `SecretsError::EmptyPassword` |
| `redact` | `REDACTED`, `REDACT_TRUNCATE_DEFAULT`, `redact_secret`, `redact_truncated`, `redact_env_and_cli_secrets` |
| root | `Result`, `SecretsError` (includes `InvalidPathSegment`, `PathNotConfined`, `EmptyPassword`) |

---

## App lock / Windows Hello

```rust
use wormhole_secrets_win::{
    check_hello_availability, unlock_app_authentication_store,
    protect_app_authentication, AppAuthUnlock, AvailabilityProbe, FakeHelloPrompt,
    HelloPrompt, StubHelloPrompt, WINRT_HELLO_GAP,
};

// Always unavailable until WinRT UserConsentVerifier is wired (or remote-session message).
let hello = check_hello_availability();
assert!(!hello.available); // stub / remote / WinRT gap — never claims ready

// Trait surface (DI): StubHelloPrompt == production fail-closed; FakeHelloPrompt for tests.
let stub = StubHelloPrompt;
assert!(!AvailabilityProbe::check_availability(&stub).available);
assert!(!HelloPrompt::request_verification(&stub, 0, "Unlock").verified);

// Tests: script outcomes without interactive biometric / WinRT UI.
let fake = FakeHelloPrompt::winrt_gap();
assert!(!fake.check_availability().available);

// Stub unlock: DPAPI-unprotect app-auth.dpapi (PBKDF2 verify is a higher layer).
match unlock_app_authentication_store()? {
    AppAuthUnlock::Missing => { /* no verifier configured */ }
    AppAuthUnlock::Unlocked { plaintext } => { /* parse JSON verifiers */ }
}
let _ = protect_app_authentication(br#"{"Version":1}"#)?;
```

**Interactive WinRT gap:** C# uses `Windows.Security.Credentials.UI.UserConsentVerifier`
(+ optional `RequestVerificationForWindowAsync` with owner HWND). That projection is
**not wired** in this crate yet; unlock via PIN/password fallback against the DPAPI store.
`StubHelloPrompt` / `request_hello_verification` never return `verified: true`. Never log
biometric material or caller prompt strings that may embed secrets. `FakeHelloPrompt` is for
tests only (no biometric UI); its `Debug` omits freeform outcome messages (booleans + call
counts only) and never retains the caller prompt.

**Unlock prompt UI glue** (lock overlay — C# `MainWindow.TryUnlockWithWindowsHelloAsync`)
lives in `wormhole-app::hello_unlock` (not this crate): `HelloUnlockGlue` maps
availability / verification → Success / Cancelled / Unavailable; production
`with_stub()` fail-closed; tests use `FakeHelloUnlockUi` (scripted outcomes; Debug never
retains prompts / biometric material) or glue over `FakeHelloPrompt`. No GPUI / no live
WinRT. See [15-cutover.md](15-cutover.md).

Bitwarden WebView2 **profile folder fingerprinting** (args + cert + route key; HTTPS-only)
lives in `wormhole-http::bitwarden`; absolute roots are the path helpers above (single-segment
validation rejects traversal). See [10-http.md](10-http.md) and [15-cutover.md](15-cutover.md).

### Bitwarden CLI session (stub)

Distinct from Bitwarden **browser** WebView2 profiles / shared-storage paths above
(`paths` + `wormhole-http::bitwarden`). This module is CLI unlock / memory-only
`BW_SESSION` only — **not** production-wired.

```rust
use wormhole_secrets_win::{
    unlock_bitwarden_session, BitwardenSession, FakeBitwardenSession, StubBitwardenSession,
    BITWARDEN_CLI_SESSION_GAP,
};

// Production: always locked; never spawns bw; never holds BW_SESSION;
// ignores BW_SESSION / WORMHOLE_BW_PASSWORD env (no silent unlock).
let stub = StubBitwardenSession;
assert!(!stub.unlock("master").unlocked);
assert!(stub.session_key().is_none());
assert_eq!(unlock_bitwarden_session("x").message, BITWARDEN_CLI_SESSION_GAP);

// Tests: script unlock without a bw process (opaque keys only; empty /
// whitespace master password and empty key fail closed).
let fake = FakeBitwardenSession::with_session_key("opaque-test-session");
assert!(fake.unlock("ignored-password").unlocked);
assert_eq!(fake.session_key().unwrap().expose(), "opaque-test-session"); // not Debug
assert!(!fake.unlock("").unlocked); // empty password fails closed + clears held key
assert!(fake.session_key().is_none());
```

Session keys are **memory-only** (never SQLite / backup). `BitwardenSessionKey` Debug/Display
redact the value — assert via `expose()`, never `format!("{:?}", key)`. `is_empty()` is
whitespace-aware (parity with C# `HasSessionKey`). Never log master
passwords or `BW_SESSION` / `WORMHOLE_BW_PASSWORD` — use `redact_env_and_cli_secrets`.
Settings fields for CLI path / region live in `wormhole-storage` / `wormhole-ui`; this
crate owns the unlock/session contract only.

**CLI gap:** C# `BitwardenCliVaultClient` / `BitwardenProcessRunner` spawn `bw unlock`
and keep the session key in memory. That process bridge is **not** wired yet;
`StubBitwardenSession` always fails closed.

---

## Transient session credentials (ephemeral / process-local)

Mirrors C# `ITransientSessionCredentialStore` — passwords for ephemeral Quick
Connect / session tabs that must **not** land in SQLite, CredMgr, or DPAPI.
Keyed by a `Uuid` that is either a session id or a connection **node** id
(C# names the parameter `sessionId`; Quick Connect stores under `node.Id`,
shell release uses `profile.NodeId`).

| Item | Value |
|---|---|
| Trait | `TransientSessionCredentialStore` — `store` / `read` / `remove` / `clear` |
| Production | `MemoryTransientSessionCredentialStore` (mutex `HashMap`; process lifetime) |
| Tests | `FakeTransientSessionCredentialStore` (same contract + call / reject counters) |
| Persistence | **None** — memory only; cleared when the owning tab leaves the shell |
| Empty password | Fail closed → `SecretsError::EmptyPassword` (C# `ThrowIfNullOrEmpty`); callers with no password skip `store` |
| Whitespace | Accepted (parity with C# `ThrowIfNullOrEmpty`, which does not treat `" "` as empty) |
| Debug | Entry count + UTF-8 lengths (+ Fake call counts) only — never password strings |

```rust
use wormhole_secrets_win::{
    FakeTransientSessionCredentialStore, MemoryTransientSessionCredentialStore,
    TransientSessionCredentialStore,
};

let store = MemoryTransientSessionCredentialStore::new();
store.store(&node_id, "session-only")?; // empty "" → EmptyPassword
let pw = store.read(&node_id);          // Option; never log
store.remove(&node_id);                 // missing → no-op
store.clear();                          // shell tab-collection reset

// Unit tests: instrumented fake (Debug length-only).
let fake = FakeTransientSessionCredentialStore::new();
fake.store(&node_id, "opaque-test")?;
```

Distinct from CredMgr [`PasswordStore`] (persisted `Wormhole:<guid>`) and from
Bitwarden CLI session keys. QC accept path may instead pass the password only
via `ConnectOptions::password` — see [21-quick-connect.md](21-quick-connect.md).

---

## Test

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-secrets-win
```

Coverage: target/path/entropy formatting (no OS), DPAPI round-trips (null / named / tunnel-id), protected file I/O + atomic overwrite, CredMgr round-trip (empty / Unicode / embedded NUL / 2560 UTF-16-byte ceiling incl. astral surrogate pins / concurrent — [adversarial-ledger-credmgr-size.md](adversarial-ledger-credmgr-size.md)), **CredMgr password CRUD glue** (`store`/`read`/`delete`; `Wormhole:<guid:D>`; missing delete Ok; `WinCredPasswordStore` ≡ free helpers; `FakePasswordStore` multi-id + concurrent Debug-safe; CredFree Drop guard — [adversarial-ledger-credmgr-crud.md](adversarial-ledger-credmgr-crud.md)), redaction case / `=` forms / UTF-8 truncate safety, app-auth protect/unlock + wrong-entropy / Debug redaction, Hello remote-session + WinRT-gap fail-closed stubs (`AvailabilityProbe` / `HelloPrompt` / `FakeHelloPrompt` without interactive UI; Fake `Debug` omits freeform messages — [adversarial-ledger-hello-stub.md](adversarial-ledger-hello-stub.md)), Bitwarden CLI session stub (`StubBitwardenSession` / `FakeBitwardenSession` + key Debug redaction), Bitwarden path segment rejection, **transient session credential store** (`TransientSessionCredentialStore` / `MemoryTransientSessionCredentialStore` / `FakeTransientSessionCredentialStore`; put/get/clear by session or node key; empty password fail-closed; never SQLite; Debug length-only + concurrent — [adversarial-ledger-transient-credentials.md](adversarial-ledger-transient-credentials.md)), **keys/tunnels/azurevpn-cache path confinement** (`ensure_confined_under` empty-root + `..` / absolute / prefix-escape rejects; `key_path_under` / `tunnel_path_under` / `azure_vpn_token_cache_path_under` + temp-dir payload round-trips; write/read/**delete|clear** hostile roots rejected before I/O with untouched temp dirs; `PathNotConfined` never embeds path or key material — [adversarial-ledger-dpapi-paths.md](adversarial-ledger-dpapi-paths.md)), **private-key DPAPI CRUD stub** (`KeyMaterialStore` + DPAPI + Fake; non-atomic write matching C# CredentialService; Fake defensive copies + concurrent Debug-safe; delete never unprotects — [adversarial-ledger-key-dpapi-crud.md](adversarial-ledger-key-dpapi-crud.md)), **tunnel payload DPAPI CRUD stub** (`TunnelPayloadStore` / `DpapiTunnelPayloadStore` / `FakeTunnelPayloadStore`; confinement before I/O; no sibling `keys\` escape; missing delete Ok; never unprotect on delete; Fake ↔ DPAPI contract; Debug length-only — [adversarial-ledger-tunnel-payload-dpapi.md](adversarial-ledger-tunnel-payload-dpapi.md)), **Azure VPN Entra refresh-token cache store** (`AzureVpnTokenCacheStore` + DPAPI + Fake; atomic write + tunnel-id entropy; clear on logout; never unprotects; never logs tokens; sibling keys/tunnels escape fail-closed — [adversarial-ledger-entra-token-cache.md](adversarial-ledger-entra-token-cache.md)).

---

## Explicit non-goals (this crate)

- Backup PBKDF2 + AES-GCM (still separate; mRemoteNG password AES-GCM lives in `wormhole-import`)
- Full interactive Azure / Stormshield / WatchGuard auth (OTP / SAML / Entra UI) — opaque tokencache blobs + entropy here; identity/schema + sidecar construction in `wormhole-tunnels::auth_glue`
- Fortinet cookie persistence (none by design)
- Domain / InheritanceResolver
- WinRT `UserConsentVerifier` UI (documented gap)
- Bitwarden extension download / cookie seeding (profile paths + HTTP arg builders only)
- Bitwarden `bw` process spawn / install / sync / credential catalog (session trait stub only)
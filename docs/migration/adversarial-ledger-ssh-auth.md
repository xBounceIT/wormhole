# Adversarial ledger — SSH auth (`SshAuthMethod` / authenticators)

**Scope:** `rust/crates/wormhole-ssh/src/auth.rs`, `SshConnectOptions.auth` + connect fail-fast in `client.rs`, `FakeAuthenticator` / `RusshAuthenticator`, auth section of `docs/migration/06-ssh-spike.md`  
**Out of scope:** `known_hosts.rs` (do not rewrite)  
**Date:** 2026-07-31  
**Authority:** full adversarial-review-fix (edit in scope)  
**Gates:** 2 clean adversarial cycles + 3 clean iterative-review-simplify cycles (renewed after simplify)

## Baseline

- `cargo test -p wormhole-ssh` — green (pre-fix auth already had FakeAuthenticator + Debug redaction).
- `cargo test -p wormhole-ssh --no-default-features` — green (auth/`client` gated off).

## Findings

| ID | Sev | Location | Issue | Disposition |
|---|---|---|---|---|
| SSH-A1 | P1 | `auth.rs` `PrivateKeySource::Path` | Relative / `..` paths loaded via CWD with no API contract | **Fixed** — `validate_private_key_path` + `PrivateKeySource::absolute_path`; reject relative and `ParentDir` |
| SSH-A2 | P1 | `auth.rs` `load_private_key` | Passphrase could appear in russh/`PrivateKeyLoad` error text | **Fixed** — `sanitize_key_load_message`; regressions for missing path + wrong encrypted passphrase |
| SSH-A3 | P1 | `client.rs` `connect_password_shell` | Agent/KBI failed only after dial/handshake (not fail-fast) | **Fixed** — `ensure_auth_method_supported` before network; connect tests assert `AuthNotImplemented` |
| SSH-A4 | P2 | `RusshAuthenticator` | `?` on russh auth errors could forward opaque messages next to secret locals | **Fixed** — `auth_transport_error` maps to `SshError::Other` without interpolating password/passphrase |
| SSH-A5 | P2 | `authenticate_with` | Stub arms used `unreachable!` after ensure | **Fixed** — defensive `AuthNotImplemented` returns (fail closed, no panic) |
| SSH-A6 | P3 | docs `06-ssh-spike.md` | Auth section omitted path contract / pre-dial stub semantics | **Fixed** |
| SSH-R1 | — | Symlink absolute path → sensitive file | Caller-trusted absolute path by contract | **Rejected** — same as file-picker / known keys dir trust boundary |
| SSH-R2 | — | Live `connect_timeout` dials TEST-NET | Outside FakeAuthenticator auth-unit rule; ignored live server remains `#[ignore]` | **Rejected** — auth unit tests stay offline; timeout test is client transport coverage |
| SSH-R3 | — | Constant-time compare of key `Bytes` in `Eq` | Not a secret-oracle in this spike | **Rejected** |

## Simplify deltas (after adversarial)

- Trimmed unused `AuthAttempt::{Agent,KeyboardInteractive}` variants (stubs never recorded).
- `FakeAuthenticator` uses `take().unwrap_or(Ok(()))`.
- Dropped duplicate `password_debug_is_redacted` from `client` tests (kept in `auth`).

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ssh
cargo test -p wormhole-ssh --no-default-features
```

**Result (final):** default features — 56 passed + 1 ignored (live server); `--no-default-features` — 30 passed. Auth module: 16 unit tests (FakeAuthenticator / offline only).

## Gate confirmation

- Adversarial clean passes: **2** (independent orderings; renewed after simplify edits).
- Iterative-review-simplify clean passes: **3**.
- No accepted non-blocked findings remain.

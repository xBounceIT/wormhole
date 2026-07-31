# SSH library spike — russh

**Status:** crate `wormhole-ssh` scaffold (auth methods + shell behind feature `client`; known_hosts + verify-on-connect + host-key prompt glue + agent availability probe + agent↔auth select glue + auto-sudo detector + session glue stub always on)  
**Date:** 2026-07-31  
**Context7 MCP:** unavailable in this environment; versions from crates.io / docs.rs.

## Decision

**Choose [`russh`](https://crates.io/crates/russh) `=0.62.4`** for Wormhole's Rust SSH client.

Workspace pin uses **`ring`** (not `aws-lc-rs`): on Windows MSVC, `aws-lc-sys` requires NASM and failed this environment's Build Tools. Revisit `aws-lc-rs` only if NASM is standardized in the agent toolchain.

| Library | Pin researched | Async | Pure Rust | SOCKS5 / custom stream | Notes |
|---|---|---|---|---|---|
| **russh** | **0.62.4** | Tokio-native | Yes (`ring` crypto; `aws-lc-rs` needs NASM on Windows MSVC) | **`client::connect_stream`** — any `AsyncRead+AsyncWrite` | Active fork of thrussh; PTY/shell/SFTP ecosystem; MSRV 1.85 matches workspace |
| thrussh | 0.42.0 | Tokio | Yes | Similar stream connect | Upstream quieter; russh is the maintained continuation |
| ssh2 / async-ssh2 | ssh2 0.9.6 | Via blocking / wrappers | **No** (libssh2 + OpenSSL) | Possible but awkward | Native deps fight unpackaged Windows shipping story |
| async-ssh2-tokio | 0.13.0 | High-level | Depends on backend | Limited | Convenience wrapper; less control for VPN routing |

## Why russh fits Wormhole

1. **VPN / SOCKS5 hook points** — today's C# path dials the sidecar SOCKS5 then runs SSH.NET over that socket. russh's `connect_stream` is the same shape: dial SOCKS (or direct TCP) first, then hand the stream to SSH. See `wormhole_ssh::transport::{SshTransport, open_transport}`.
2. **Auth methods + interactive shell** — `SshAuthMethod` on `SshConnectOptions` (password, private-key path/bytes, agent stub, keyboard-interactive stub). `connect_password_shell` dispatches auth then `request_pty` + `request_shell` (xterm-256color). Maps to C# `SshAuthMethodsBuilder`. Agent **availability** is a separate always-on probe (`is_agent_available` / `FakeAgent`); connect-prep **select glue** includes/excludes Agent from the method list based on that probe (fail closed on probe error). Wire agent auth stays `AuthNotImplemented`.
3. **Testable auth backend** — `SshAuthenticator` + `FakeAuthenticator` unit-test password/key load without a network; agent/kbi return `AuthNotImplemented`. Agent presence / select glue uses `FakeAgent` / `FakeFallibleAgent` (offline).
4. **SFTP later** — `russh-sftp` companion (not pinned yet) for the file-transfer dialog path.

## SOCKS5 design (hook only in this spike)

```text
ConnectionProfile.tunnel_enabled
        │
        ▼
 TunnelManager lease → Socks5Endpoint(127.0.0.1:ephemeral)
        │
        ▼
 open_transport(SshTransport::Socks5(ep), target_addr)
        │  (TODO: SOCKS5 CONNECT handshake)
        ▼
 russh::client::connect_stream(config, stream, handler)
        │
        ▼
 authenticate_* → channel_open_session → PTY + shell
```

`SshTransport::Socks5` currently returns `SshError::Socks5NotImplemented` so call sites compile and tests assert the hook exists without needing a live proxy.

## Feature flags

| Feature | Default | Effect |
|---|---|---|
| `client` | **on** | Pulls `russh`, `tokio`, `async-trait`, `wormhole-terminal`; exposes connect/shell APIs |

`cargo check -p wormhole-ssh` exercises the default `client` feature.
`cargo check -p wormhole-ssh --no-default-features` must still compile (transport/client modules gated off; **known_hosts**, **verify-on-connect**, **host-key prompt glue**, **agent probe**, **agent↔auth select glue**, **auto-sudo detector**, and **auto-sudo session glue** always build).

## Host-key known_hosts

`KnownHostsStore` persists pins at `%LOCALAPPDATA%\Wormhole\known_hosts` (line format: `host[:port] SHA256:…`). Fingerprints match C# `SshHostKeyValidator.ComputeFingerprint` (`SHA256:` + unpadded Base64 of SHA-256 over host-key bytes). Corrupt / hostile lines are **skipped on load** (soft-fail); saves use a unique temp file + atomic replace (Windows `MoveFileEx` overwrite). Mismatch **never** silently overwrites a pin.

| Policy | Unknown | Match | Mismatch |
|---|---|---|---|
| `TrustOnFirstUse` | accept + save | accept | reject (pin unchanged) |
| `RejectMismatch` | reject | accept | reject (pin unchanged) |

`accept_server_host_key(accept_any, store, host, fingerprint, policy)` is the russh `check_server_key` gate: `accept_any_host_key` remains the Quick Connect escape hatch; otherwise the store + policy decide (mismatch surfaces as `SshError::HostKeyMismatch` from the hook). `SshConnectOptions` carries `host_key_policy` + optional `known_hosts`.

### Host-key verify-on-connect (always on)

Thin connect-path decision **before** any prompt / pin / dial:

`verify_host_key_on_connect(store, host, fingerprint, mismatch_policy)` →
`HostKeyConnectVerdict::{Accept, Reject, Prompt}` against a [`HostKeyPinStore`]
(`FakeKnownHosts` in unit tests).

| Case | Verdict | Notes |
|---|---|---|
| Known match | `Accept` | C# `Trust` |
| Unknown (no pin) | `Prompt(Unknown)` | Lab: UI confirm before pin. C# silent TOFU + post-connect pin for saved nodes |
| Mismatch + `HostKeyMismatchPolicy::Reject` (default) | `Reject` | C# `SshHostKeyMismatchException` / failure overlay parity |
| Mismatch + `HostKeyMismatchPolicy::Prompt` | `Prompt(Changed)` | Lab overwrite UX → prompt glue may Accept-pin |
| Empty / hostile host or empty fingerprint | `Err` | Fail closed — never `Accept` |

Session wrappers: `wormhole_session::verify_ssh_host_key` / `_fake` (bare host + port →
`host_identity`; empty bare host fails closed before forming `:port`).

**LabOnly:** Fake store / unit tests; no GPUI; no live SSH; no profile SQLite pin sync.
Not HardwarePass.

### Host-key prompt glue (always on)

When verify returns Prompt, session / UI connect can call
`resolve_host_key_prompted(store, prompt, host, fingerprint)` (internally verifies with
`HostKeyMismatchPolicy::Prompt`):

| Decision | Behavior |
|---|---|
| Trust / Accept | pass (no prompt) |
| Unknown | [`HostKeyPrompt`] → **Accept** pins / **Reject** → `HostKeyRejected` (fail closed, store unchanged) |
| Changed | [`HostKeyPrompt`] → **Accept** may overwrite pin after explicit accept / **Reject** → `HostKeyMismatch` (fail closed, pin unchanged) |

| Item | API |
|---|---|
| Trait | `HostKeyPrompt` / `NullHostKeyPrompt` (always reject) |
| Tests | `FakeKnownHosts` (in-memory) + `FakeHostKeyPrompt` (scripted Accept/Reject; empty queue rejects) — no live SSH |
| Session | `wormhole_session::gate_ssh_host_key` / `gate_ssh_host_key_fake` wraps bare `host`+`port` → `host_identity` then the glue (orchestrator wiring still Pending) |

`Debug` may include SHA256 fingerprints (the public pin form) but never raw host-key bytes. Real dialog UI is still Pending. File-store Accept rolls back the in-memory pin if `save` fails.

Password, key passphrase, key bytes, and SOCKS credentials are redacted in `Debug` output. This file store is a **spike** — not production SSH UI / profile-pin parity.

## Auth methods (`client` feature)

| Method | Status | Notes |
|---|---|---|
| `Password` | Live | russh `authenticate_password` |
| `PrivateKey` (`Path` / `Bytes` + optional passphrase) | Live load + russh publickey | Passphrase decrypts the key only (never sent as login password) |
| `Agent` | Stub auth + live **probe** + **select glue** | Wire auth: `SshError::AuthNotImplemented("agent")` — fail closed **before** dial. Availability + connect-prep include/exclude: see below |
| `KeyboardInteractive` | Stub | `SshError::AuthNotImplemented("keyboard-interactive")` — fail closed **before** dial |

**Private key path contract:** `PrivateKeySource::Path` must be an **absolute** path with no `..` components (`validate_private_key_path` / `PrivateKeySource::absolute_path`). Relative / traversal paths are **not** auto-loaded against CWD. Prefer `PrivateKeySource::bytes` for DPAPI-decrypted or other in-memory PEM. Password, passphrase, and key bytes are redacted in `Debug`; load errors strip any accidental passphrase substring. Unit tests use `FakeAuthenticator` only (no network).

**Connect-prep Agent select:** before dial, preferred methods that include Agent should run `select_auth_methods_for_connect` / `filter_ssh_auth_methods_for_connect` (always-on glue). Available → keep Agent; unavailable → drop Agent; probe `Err` → fail closed (`AgentAuthSelectError`). Probe is skipped when Agent is not a candidate. Does not reimplement the availability probe.

## SSH agent availability probe (always on)

Separate from wire auth: `SshAgentProbe` / `is_agent_available` / `probe_agent` answer whether a local agent **endpoint** looks present. They never list identities, sign challenges, or send SSH agent protocol bytes (open/stat + drop only). Secrets are not involved; `Debug` for `FakeAgent` exposes only `available` + `source`.

| Item | API / behavior |
|---|---|
| Trait | `SshAgentProbe::{is_agent_available, probe}` → `AgentAvailability { available, source }` |
| Tests | `FakeAgent::{available, unavailable}` — no network, no pipes |
| Windows | `PlatformAgentProbe` checks bounded named-pipe `SSH_AUTH_SOCK` if set, else `\\.\pipe\openssh-ssh-agent` (`OPENSSH_AGENT_PIPE`). Named-pipe open+drop only (no agent protocol). `ERROR_PIPE_BUSY` / sharing-violation / access-denied ⇒ present; missing ⇒ absent |
| Windows `SSH_AUTH_SOCK` bounds | Accept only `\\.\pipe\NAME` / `//./pipe/NAME` with a safe NAME (≤256 bytes total; no `\`, `/`, empty, `.`, `..`). Reject UNC, filesystem paths, other `\\.\` / `\\?\` devices, relative / overlong / empty — ignore env and fall through to default pipe |
| Non-Windows | `SSH_AUTH_SOCK` must be absolute, no `..`, ≤256 bytes; then `exists()` — otherwise unavailable |
| Pageant | **Not probed** yet (shared-memory / WM_COPYDATA) — OpenSSH named-pipe only on Windows |
| Auth select glue | `select_auth_methods_for_connect` / `filter_ssh_auth_methods_for_connect` / `agent_auth_allowed` — include/exclude Agent from connect prep; `FallibleAgentProbe` + `FakeFallibleAgent` for error path; probe errors fail closed |
| Auth | Still `AuthNotImplemented("agent")` until a russh agent client lands — fail closed **before** dial |

No feature flag: the probe + select glue have no russh dependency and stay available under `--no-default-features` (`filter_ssh_auth_methods_for_connect` needs `client` for `SshAuthMethod`).

## Auto sudo (detector + session glue stub)

C# `Services/Ssh/SshAutoSudoDriver.cs` sends `sudo su` after first shell
output, then watches a 512-byte UTF-8 tail for
`[Pp]assword[^\r\n]*:\s*$` (`.NET` `$` / `\s`, including trailing CRLF) before
typing the saved password (echo-off). No prompt within 10s → password is
**not** sent.

Rust splits this into an always-on **detector** and a thin **session glue** stub
(no `client` feature / no GPUI):

### Prompt detector (`auto_sudo`)

| Item | API |
|---|---|
| Classify | `classify_sudo_output` / `classify_sudo_line` → `SudoOutputClass::{Ordinary,PasswordPrompt}` |
| Rolling tail | `SudoPromptTail` (`TAIL_CAPACITY` = 512) |
| Constants | `ELEVATION_COMMAND` (`"sudo su"`), `PROMPT_TIMEOUT_SECS` (10) |

The detector **never** accepts, stores, sends, or logs a password. `Debug` for
`SudoPromptTail` emits length + class only. Casing matches C# `[Pp]assword`
(leading `P`/`p` only).

### Session glue (`auto_sudo_glue`)

Wires the existing detector into the C# state machine against a write sink:

| Item | API |
|---|---|
| Glue | `AutoSudoSessionGlue` — `on_output` / `on_output_fake` / `on_timeout` / `finish` |
| Sink | `AutoSudoTerminal` + existing `wormhole_terminal::FakeTerminalSession` (unit tests) |
| Secret | `AutoSudoPassword` — out-of-band; `Debug` is `[REDACTED]` + utf8 length only |
| Steps | `AutoSudoStep::{Idle,SentElevation,SentPassword,FinishedWithoutPassword}` |

First non-empty chunk → write `ELEVATION_COMMAND` + `\r` (chunk **not** tailed).
Later chunks append to `SudoPromptTail`; on `PasswordPrompt` inject password +
`\r` once and clear the secret. `on_timeout` finishes **without** sending the
password. Sync write errors never include payload bytes and **fail closed**
(secret cleared / `Done`) — unlike C# fire-and-forget writes that keep waiting
until the 10s prompt timeout. Live SSH shell / WebView2 pump / GPUI wiring
remains Pending — Fake terminal only.

## Non-goals (this spike)

- Host-key mismatch **UI dialog** (prompt trait + Fake store glue exist; GPUI/WinUI dialog Pending)
- Per-node SQLite `SshKnownHostFingerprint` sync (file store first; profile pin later)
- Real SSH agent / keyboard-interactive wire protocols (availability probe + connect-prep select glue only; auth still stubs)
- Pageant detection (OpenSSH named-pipe probe only on Windows)
- Live auto-sudo against a real SSH shell / WebView2 pump (glue + Fake terminal only)
- Real SOCKS5 dialer implementation
- Wiring into GPUI / WebView2 terminal bridge
- Cross-process merge of concurrent known_hosts writers (last atomic writer wins)

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-ssh
cargo test -p wormhole-ssh --no-default-features
cargo check -p wormhole-ssh
cargo check -p wormhole-ssh --no-default-features
# verify-on-connect + prompt glue + auto-sudo + agent probe + agent↔auth select always on (Fake store / FakeAgent offline).
# Optional live server:
# $env:WORMHOLE_SSH_HOST=...; $env:WORMHOLE_SSH_USER=...; $env:WORMHOLE_SSH_PASSWORD=...
# cargo test -p wormhole-ssh -- --ignored
```

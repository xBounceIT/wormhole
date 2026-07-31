# SFTP — serialized ops + transfer queue (`wormhole-sftp`)

**Status:** types + serialization gate + fake backend green · SOCKS5 tunnel target selection stub · file-transfer dialog glue (SSH context → SOCKS + cancel queue) · transfer progress callback glue (Fake chunks; no live SFTP) · live `russh-sftp` channel wiring deferred  
**Date:** 2026-07-31  
**C# mirrors:** `Services/ISftpService.cs`, `Services/Ssh/SftpSession.cs`, `Services/Sftp/FileTransferOrchestrator.cs`, `Services/SftpService.cs` (SOCKS when tunnel present), `Services/FileTransferDialogService.cs` / `SshSessionViewModel.CanOpenFileTransfer`, `ViewModels/Sessions/Transfer/TransferItemViewModel.ProgressFraction`

---

## Invariant (do not regress)

SSH.NET's `SftpClient` is **not thread-safe**. Wormhole serializes every SFTP call for a
session through a single gate:

| C# | Rust |
|---|---|
| `FileTransferOrchestrator` `SemaphoreSlim(1,1)` + `RunSerializedAsync` | `SerializedSftpSession` `tokio::sync::Mutex` + worker-owned gate |
| Pane refresh / rename / mkdir funnel through the orchestrator | Same — public methods on `SerializedSftpSession` always take the gate |
| Cancel must not release the gate while a worker still holds the client | Worker task owns the mutex until the backend future completes (caller waits on oneshot); transfer rows → `Cancelled` if enqueue is dropped mid-op |

Overlapping upload + directory refresh **must not** interleave on the backend. The package
test `serialize_queue::concurrent_ops_never_overlap_on_backend` asserts
`FakeSftpBackend::peak_in_flight == 1` under concurrent callers. Abort mid-op is pinned by
`cancel_mid_op_does_not_overlap_backend`.

### Cancel / single-flight (worker-owned gate)

| Caller abort timing | Worker behavior | Gate | Follow-up |
|---|---|---|---|
| Mid-op (oneshot dropped after acquire) | Backend future runs to completion | Held until complete | Next op waits, then succeeds (`cancel_mid_op_does_not_overlap_backend`) |
| While queued for the mutex | Skip backend (`tx.is_closed`) | Released immediately after acquire check | Next op succeeds; skipped waiter does not increment `ops_completed` (`cancel_while_queued_skips_backend_then_next_succeeds`) |
| Mid `enqueue_and_run_file` | Session worker same as mid-op | Same | Job → `Cancelled`; next enqueue Completes (`cancel_transfer_marks_job_cancelled`) |
| `enqueue_and_run_file` waiting on gate | Skip backend for waiter | Released after skip check | Holder stays `Completed`; waiter `Cancelled`; next Completes (`cancel_queued_transfer_skips_then_next_completes`) |

Gate ownership in `SerializedSftpSession::drive` matches the C# anti-pattern fix (worker owns mutex until backend future finishes). `JobStatusGuard` / `cancel_if_running` never overwrite terminal strip statuses. Regressions above pin cancel-then-next.

---

## Crate layout

| Module | Role |
|---|---|
| `SftpOps` | Async trait mirroring `ISftpSession` methods |
| `SerializedSftpSession<B>` | Single-flight wrapper around any backend |
| `TransferQueue` / `TransferRequest` / `TransferJob` | Queue model for the transfer strip |
| `report_progress` / `run_fake_transfer` / `TransferProgress` | Progress callback glue (cumulative bytes → %, cancel-aware) |
| `FakeSftpBackend` | In-memory FS for unit tests |
| `select_sftp_transport` / `SftpTransport` | Direct vs SOCKS5 from optional tunnel lease (stub) |
| `FakeTunnelSocks` | In-memory tunnel SOCKS view for unit tests (no network) |
| `ConnectedSshContext` / `FileTransferDialogState` | Dialog glue: Connected SSH → SOCKS select → queue (`open_from_ssh_session`) |
| feature `russh` | Optional `russh-sftp =2.3.0` link (compile marker) |

### Transfer progress callback glue (stub)

C# `SftpSession` Upload/Download pass `IProgress<long>` cumulative byte counts;
`TransferItemViewModel.ProgressFraction` is 0 when `ExpectedBytes <= 0`, else
`Clamp(transferred / expected)`. Cancel is checked inside the SSH.NET progress
callback (`ThrowIfCancellationRequested`).

Rust parity lives in `wormhole_sftp::report_progress` / `report_to_callback` /
`run_fake_transfer`:

- Signed inputs mirror C# `long` so negatives fail closed (`TransferProgressError::Invalid`)
- `total_bytes` `None` / `0` → unknown (no percent); known `t > 0` → `percent` 0..=100
- Percent mul overflow fail closed; transferred > total clamps to 100 (sparse/EOF parity)
- Cancel flag checked before each report / Fake chunk (`Cancelled`)
- Snapshots and errors carry sizes only — no paths or credential-shaped text
- `run_fake_transfer` drives chunked cumulative reports up to `fake_payload_len` (no forced snap to total; no network / live SFTP)

Strip UI binding and live russh progress hooks remain host / follow-up work.
Review: [adversarial-ledger-sftp-progress.md](adversarial-ledger-sftp-progress.md).

### File-transfer dialog glue (stub)

C# opens the dual-pane dialog only from a **Connected** SSH tab
(`CanOpenFileTransfer`). Rust parity is `open_from_ssh_session` /
`FileTransferDialogState`:

- `None` / disconnected / blank/`trim`-empty host → `SftpError::SshSessionRequired` (fail closed)
- Connected → `select_sftp_transport` (Direct or SOCKS5; tunnel without SOCKS / port `0` still fails closed); `remote_host` is trimmed
- `start_transfer` delegates to `TransferQueue::enqueue_and_run_file` (existing cancel / single-flight; concurrent starts stay peak_in_flight == 1)
- No credentials on the glue surface; `Debug` omits secret-shaped fields
- Dual-pane UI / conflict overlays / live russh dial remain host / follow-up work

Fake-backed tests live in `dialog::tests` (`open_with_fake`). Review: [adversarial-ledger-sftp-dialog.md](adversarial-ledger-sftp-dialog.md).

### SOCKS5 tunnel target selection (stub)

C# `SftpService.ConnectAsync` routes like the SSH terminal: **no tunnel → direct**;
**tunnel present → require `Socks5Endpoint`** and dial the real host through SOCKS5
(`ProxyTypes.Socks5`). A tunnel without SOCKS **fails closed** (never silently leak
bytes on the public network). Unlike HTTP, there is **no** local-forwarder fallback.

Rust parity lives in `wormhole_sftp::select_sftp_transport` + `SftpTransport::{Direct,Socks5}`
with `FakeTunnelSocks` for offline unit tests (pure data — no sockets). SOCKS selection
keeps the real SSH host/port as the CONNECT target (transport carries the proxy only).
Port `0` → `InvalidSocksPort` (fail closed). Review: [adversarial-ledger-sftp-socks.md](adversarial-ledger-sftp-socks.md).
Live SOCKS CONNECT + `russh` session wiring stays deferred (same hook story as
`wormhole-ssh` / `06-ssh-spike.md`).

### `russh-sftp` pin

[`russh-sftp`](https://crates.io/crates/russh-sftp) **2.3.0** resolves cleanly next to
workspace `russh =0.62.4` (it does **not** depend on `russh` itself — protocol codec +
client helpers over an async stream). Enable with:

```powershell
cargo test -p wormhole-sftp --features russh
```

Live `russh` channel → SFTP client connect is a follow-up once `wormhole-ssh` exposes a
reusable authenticated session. Route selection (`select_sftp_transport`) already mirrors
C# SOCKS-when-tunnel; dial still uses the SSH transport hook.

---

## Non-goals (this spike)

- Full flatten / conflict-prompt UI (stays with host / GPUI dialog)
- Credential / host-key connect path (use `wormhole-ssh` + secrets later)
- SFTP as a standalone session protocol tab (C# also opens SFTP from SSH tabs)

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-sftp
cargo test -p wormhole-sftp --features russh
```

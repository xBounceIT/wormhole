# Adversarial ledger — SFTP file-transfer dialog glue

**Scope:** `rust/crates/wormhole-sftp/src/dialog.rs` (`ConnectedSshContext`, `open_from_ssh_session` / `open_with_fake`, `FileTransferDialogState::start_transfer`), fail-closed/`Debug` notes in `error.rs` as surfaced by open, `docs/migration/11-sftp.md` dialog section, feature-matrix SFTP dialog row, README ledger link  
**Authority:** adversarial-review-fix (edit in scope; no C# mutations; no HardwarePass/cutover; no live russh dial)  
**Preserved:** `select_sftp_transport` fail-closed table, `TransferQueue` cancel / single-flight, `public_message` redaction, unsafe-name rejection  
**Baseline (pre-fix):** `cargo test -p wormhole-sftp` green; dialog open + thin start_transfer tests present; concurrent/`mid-queue` dialog pins thin; padded host stored raw  
**Compared against:** C# `SshSessionViewModel.CanOpenFileTransfer`, `FileTransferDialogService` (open gate only — no credentials on glue)

---

## Accepted findings and fixes

| ID | Sev | Location | Invariant / evidence | Fix | Verification |
|---|---|---|---|---|---|
| DIALOG-01 | P2 | `open_from_ssh_session` | Whitespace-padded host passed `trim().is_empty()` but `remote_host` stored untrimmed → later dial would see `"  host  "` | Trim once; store trimmed host; fail closed on trim-empty | `padded_host_is_trimmed_on_open`, `blank_host_fails_closed` (`""` / spaces / tabs) |
| DIALOG-02 | P2 | `dialog::tests` | `start_transfer_uses_queue_single_flight` ran one job — did not pin concurrent double `start_transfer` | `double_start_transfer_stays_single_flight` (`peak_in_flight == 1`); rename single-job test | that test |
| DIALOG-03 | P2 | `dialog::tests` | Mid-op cancel covered; cancel-while-queued via `start_transfer` not pinned at dialog API | `cancel_queued_start_transfer_skips_then_next_completes` | that test |
| DIALOG-04 | P3 | `dialog::tests` | Port-`0` SOCKS through `open_with_fake` not pinned (transport covered; dialog open path thin) | `tunnel_zero_port_socks_fails_closed` | that test |
| DIALOG-05 | P3 | `11-sftp.md` / README | Dialog glue notes needed trim / concurrent / ledger link | Doc bullets + ledger + README row | docs review |

### Simplify delta (post-adversarial)

| ID | Sev | Location | Change | Verification |
|---|---|---|---|---|
| S-01 | — | `dialog::tests` | Drop redundant `!is_direct()` after `socks5().expect`; drop vacuous Debug `credential`/`payload` substring asserts | `cargo test -p wormhole-sftp --lib dialog::` |

Test-only simplify → no adversarial re-loop (no production code delta).

---

## Rejected candidates

| Candidate | Reason |
|---|---|
| Fail closed on SSH `port == 0` | Dial concern; C# open gate is Connected status, not port sanity |
| Mirror C# `_showInProgress` single-dialog mutex here | UI/`FileTransferDialogService` concern; glue opens state only |
| `#[derive(Debug)]` on `ConnectedSshContext` | Hand-written Debug is an explicit credential-free field whitelist |
| Extract shared cancel helpers with `serialize_queue` | Dialog vs queue surfaces; duplication pins the public API |
| Reject zero-width / exotic Unicode “blank” hosts | Speculative; `trim` matches documented blank rule |
| Live russh / dual-pane / conflict UI | Documented non-goals |
| Soften tunnel-without-SOCKS to Direct | Would violate SFTP/SSH leak-prevention (already covered by transport) |
| Require backend `is_connected` at open | Caller supplies ready backend; Fake/live wiring is separate |

---

## Adversarial clean passes (2 required)

Reset after each fix batch. Production code unchanged by S-01.

### Clean pass 1 — order: security → contract → boundaries → concurrency → test resistance → integration

- No credential fields on glue; `Debug` of context/state/errors omit password/secret/token/`hunter2`.
- `None` / disconnected / trim-empty → `SshSessionRequired`; Connected → Direct or SOCKS; tunnel sans SOCKS / `:0` fail closed; host trimmed on success.
- Concurrent `start_transfer` serializes; mid-op and mid-queue cancel leave gate free for next Completes.
- Docs / feature-matrix Lab row / C# `CanOpenFileTransfer` aligned; no secrets on open path.
- **Accepted findings:** none.

### Clean pass 2 — order: integration → concurrency → boundaries → security → contract → state → operability → tests

- Exports in `lib.rs`; `11-sftp.md` ledger link; SOCKS select before session wrap (fail cheap).
- Double start + cancel-queued pins on dialog API; queue/session invariants unchanged.
- Blank hosts `""` / whitespace / tabs; padded host normalized; SOCKS none vs some vs `:0`.
- Transport stored route-only; title/host never treated as secrets in Debug contract tests.
- Open does not dial; `start_transfer` does not reimplement cancel semantics.
- **Accepted findings:** none.

`adversarial_clean_passes = 2`.

---

## Iterative-review-simplify (3 clean cycles)

Each cycle: Code Reuse → Code Efficiency → Code Quality and Bugs (+ simplify discipline).

| Cycle | Themes | Outcome |
|---|---|---|
| 1 (fix) | Quality (redundant socks `!is_direct` + vacuous Debug asserts) | S-01 applied → counter reset |
| 1 (clean) | Reuse (keep thin `open_with_fake` / `start_transfer` delegate); efficiency (select before session); quality (hand Debug whitelist) | Clean |
| 2 | Reject `_showInProgress` / port-0 SSH / shared cancel helpers / derive Debug | Clean |
| 3 | Docs/matrix parity; fail-closed precedence (SSH before SOCKS); no further validated churn | Clean |

`simplify_clean_passes = 3`.

---

## Regression tests added/updated

- `blank_host_fails_closed` — `""`, spaces, tabs/newlines
- `padded_host_is_trimmed_on_open`
- `tunnel_zero_port_socks_fails_closed`
- `start_transfer_completes_single_job` (renamed; honest single-job pin)
- `double_start_transfer_stays_single_flight`
- `cancel_queued_start_transfer_skips_then_next_completes`
- Existing: none/disconnected/Direct/SOCKS/TunnelSocksRequired/Debug/mid-op cancel

---

## Final verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-sftp
```

Results: lib 27 passed; `serialize_queue` 12 passed; doc-tests 0.

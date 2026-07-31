# Adversarial ledger — RDP CredSSP wipe ↔ connect lifecycle glue

Scope: `rust/crates/wormhole-surface-win/src/rdp/credssp_connect_glue.rs` (Fake connect-attempt
lifecycle; wipe on success / fail / cancel / Drop; Debug redaction); docs touch in
`docs/migration/05-rdp-spike.md` (+ README index). Reuses
`WipePasswordOnDrop` / `validate_configure_inputs` from `rdp/configure.rs`.

Out of scope: live OCX / `mstscax`; OLE / CredSSP configure core rewrite; pane-layout /
`session_surface` rewrites; tunnels churn; C# mutation.

Baseline (before review edits): `cargo test -p wormhole-surface-win --features rdp` green
(157 unit tests; glue already present from impl `1a605439-5d53-4009-a83e-86ff3fa4f813`).

Design SoT: `docs/migration/05-rdp-spike.md`, prior
[adversarial-ledger-rdp-credssp.md](adversarial-ledger-rdp-credssp.md).

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| WIPE-001 | P2 | `run` / `attempt_connect` docs | Soft CredSSP miss still Fake-Connects without the same explicit ack as `RdpOcx::configure_and_connect` | Callers could treat Ok as “safe NLA” | **Fixed** — docs on `run` / `attempt_connect` + spike notes; test asserts `connect_count == 1` on soft miss |
| WIPE-002 | P2 | Fake CredSSP soft miss | `enable_cred_ssp=false` + soft_miss under-pinned (CRED-005 parity) | Soft miss could reintroduce NLA-risk noise if branch regresses | **Fixed** — `requested_off_cred_ssp_ignores_soft_miss` |
| WIPE-003 | P2 | validation wipe | Oversized / NUL password validation wipe + Debug non-echo unpinned | Hostile password bytes only covered for empty server | **Fixed** — `oversized_and_nul_password_validation_still_wipes` |
| WIPE-004 | P3 | no-password path | Connect with `password: None` (put_count 0) unpinned | Session may dial without ClearTextPassword | **Fixed** — `no_password_connect_wipes_none_and_skips_put` |
| WIPE-005 | P3 | cancel vs bare Drop | Docs equated Drop-without-`run` with cancel; `cancel_count` only bumps on explicit `cancel` | Misleading Fake counter / contract | **Fixed** — API/docs clarify; `bare_drop_wipes_without_bumping_cancel_count` |
| WIPE-006 | — | `mem::forget(attempt)` | Password never wiped | Same as any Drop-based cleanup | **Rejected** — intentional misuse |
| WIPE-007 | — | Refuse Connect on soft miss | Would diverge from lab `configure_and_connect` | Spike intentionally documents inspect-report | **Rejected** — document, do not change Fake Connect |
| WIPE-008 | — | COM `BSTR` SecureZero | Platform residual after put | Prior CRED-007 | **Rejected** — out of Fake glue scope |
| WIPE-009 | — | Sticky Fake fail / soft_miss scripts | Script flags persist until cleared / new Fake | Test Fake convention | **Rejected** — soft_miss setter documents sticky |

## Fixes applied

- `rdp/credssp_connect_glue.rs` — soft-miss / cancel-vs-abandon docs; CRED-005 Fake parity test;
  oversize/NUL validation wipe tests; no-password put skip; bare-Drop cancel_count pin;
  `with_fake` → `Default`; drop weak post-wipe Debug assert branch
- `docs/migration/05-rdp-spike.md` — soft-miss still Fake-Connects; bare Drop vs `cancel_count`

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 (initial) | Contract → boundary → state → concurrency → security → integration → perf → tests | WIPE-001…005 | Fixed; counter reset |
| Adv-1 | Reverse: tests-as-oracles → secrets/Debug → soft CredSSP → cancel/Drop → OCX parity | Doc cancel/abandon inconsistency (folded into WIPE-005) | Fixed; counter reset |
| Adv-2 | Security/privacy + lifecycle + `configure_and_connect` parity | None | Clean (1/2) |
| Adv-3 | Boundary inputs + test resistance + integration drift (no pane-layout touch) | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-fix | `with_fake` duplicated empty Fake vs `Default` | — | Weak post-wipe Debug `\|\|` assert | **Fixed** | Reset |
| Sim-1 | `WipePasswordOnDrop` / `validate_configure_inputs` shared; no new wipe helper | Fake-only; no I/O | Wipe on all exits intact; duplicate assert removed | None | Clean (1/3) |
| Sim-2 | SoftPut/OCX core left alone (in scope) | Count saturating_add fine | Soft-miss docs match lab helper | None | Clean (2/3) |
| Sim-3 | Public exports in `rdp/mod.rs` sufficient | Unit tests no COM | Errors/Debug omit secrets; OLE/GWLP unchanged | None | Clean (3/3) |

### Adversarial re-loop (required after simplify edits)

| Cycle | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-R1 | Delta: `with_fake` → `Default`; Debug assert trim; wipe contracts unchanged | None | Clean (1/2) |
| Adv-R2 | Reverse: soft miss / cancel_count / oversize-NUL / no-password oracles | None | Clean (2/2) |

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-surface-win --features rdp
cargo check -p wormhole-surface-win --features rdp
```

Result: **pass** — 161 unit tests with `--features rdp` (12 in `credssp_connect_glue`); `cargo check` green.

## Residual notes

- Soft CredSSP miss still Fake-Connects; session layer must use `ConfigureReport::has_cred_ssp_risk()`.
- COM `BSTR` for `ClearTextPassword` is not SecureZero’d (prior CRED-007; live OCX path).
- No live OCX / HardwarePass in this glue.

# Adversarial ledger — RDP display/redirect Fake configure glue

Scope: `rust/crates/wormhole-surface-win/src/rdp/display_redirect_glue.rs` (+ `rdp/mod.rs` exports), `docs/migration/05-rdp-spike.md` display/redirect notes  
Out of scope: CredSSP wipe rewrite; live OCX / `mstscax` DriveCollection walk; audio / performance / gateway Configure  
Baseline: `cargo test -p wormhole-surface-win --features rdp` green (display_redirect + full crate)  
Design SoT: C# `RdpHostForm.Configure` display + common redirects; `RdpDesktopSizeResolver.Resolve`; `RdpDriveList.ParseLetters` / `ApplyDriveRedirection` least-privilege catch

## Findings

| ID | Sev | Location | Issue | Evidence | Disposition |
|---|---|---|---|---|---|
| DR-001 | P2 | `try_put_drives` / `DisplayRedirectReport` | Least-privilege DriveCollection soft-miss re-put master=`false`, but report soft_applied reflected the *initial* `true` put only — no `redirect_drives_master` effective flag | Attack focus vs C# catch path; callers could treat Letters intent as enabled | **Fixed** — return final master put; `redirect_drives_master` from `last_applied == "true"`; regression asserts |
| DR-002 | P2 | tests | Hostile over-`MAX_DESKTOP_AXIS` only pinned for fixed `WxH`; full-content surface/fallback paths unpinned | `resolve` + `validate_desktop_axes` before puts | **Fixed** — `hostile_full_content_surface_or_fallback_over_max_fail_closed` |
| DR-003 | P2 | `try_put_drives` | Custom letters + `RedirectDrives` soft-miss still applied `DriveCollection` filter (filter without master) | Fake state / future OLE hazard vs C# master-before-collection | **Fixed** — skip collection when master soft-skipped; `redirect_drives_master_soft_miss_skips_drive_collection` |
| DR-004 | P3 | tests / resolve | FitToWindow one-axis-zero fallback, lowercase `c;d`, `" all "` sentinel parity weakly pinned | C# `ParseLetters` / `Resolve` | **Fixed** — resolve + parse asserts |
| DR-005 | P3 | `FakeRdpPropertySurface` docs | Claimed “unknown names soft-skip”; code Applies unless scripted miss | Doc/contract drift | **Fixed** — doc matches soft_miss scripting |
| DR-006 | P3 | `05-rdp-spike.md` | Drive master effective flag / master soft-miss skip not in table | Spike SoT lag | **Fixed** — table + `redirect_drives_master` note |
| DR-007 | — | Merge `try_put_bool` / `try_put_collection` | Duplication taste | Clear as-is | **Rejected** — micro-DRY |
| DR-008 | — | Drop unused `From<windows::core::Error>` | Dead conversion | Parity with CredSSP glue Error shape | **Rejected** — keep sister-glue pattern |
| DR-009 | — | Make `RedirectDrives` loud like C# | C# master not TrySetOptional | Fake catalog intentionally Soft | **Rejected** — Fake TrySet design |
| DR-010 | — | CredSSP / wipe rewrite | User gate | Out of scope | **Rejected** |

## Fixes applied

- `rdp/display_redirect_glue.rs` — final master put + `redirect_drives_master`; skip DriveCollection when master soft-misses; Fake doc fix; attack-focus regressions (over-max full-content, FitToWindow / parse, master soft-miss)
- `docs/migration/05-rdp-spike.md` — display/redirect table + effective master note
- `docs/migration/README.md` — ledger index row

## Gate record

### Adversarial loop

| Cycle | Strategy | Accepted findings | Result |
|---|---|---|---|
| Adv-0 | Contract → boundary → state → concurrency → security → integration → perf → tests | DR-001…004 | Fixed; counter reset |
| Adv-1 | Same lanes on fixed tree; Fake docs | DR-005…006 | Fixed; counter reset |
| Adv-2a | Contract→…→tests (post DR-006) | None | Clean (1/2) |
| Adv-2b | Reverse: tests-as-oracles → Fake master/collection → C# `ApplyDriveRedirection` / `ParseLetters` → resolve clamp → no OCX/CredSSP → DR-007…010 hold | None | Clean (2/2) |

### Iterative-review-simplify (after adversarial clean)

| Cycle | Reuse | Efficiency | Quality/Bugs | Accepted | Result |
|---|---|---|---|---|---|
| Sim-1 | Reject try_put bool/collection merge (DR-007) | No hot-path I/O; Fake `Vec` only | Effective master + least-privilege pins intact | None | Clean (1/3) |
| Sim-2 | Exports via `rdp/mod.rs` only; spike table matches code | Soft catalog attempt pin only on Letters profile (DriveCollection conditional) | Soft-miss skip collection; no CredSSP touch | None | Clean (2/3) |
| Sim-3 | `normalise_color_depth` / `MAX_DESKTOP_AXIS` reuse from configure | Reject From-impl churn (DR-008) | DR-009…010 remain rejected | None | Clean (3/3) |

No simplify edits → no adversarial re-loop required.

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-surface-win --features rdp
```

Result: **pass** — display_redirect unit tests (14) + full crate with `--features rdp` (176).

## Residual

- Live OCX apply of display/redirect Fake puts remains deferred (`05-rdp-spike.md`).
- Per-letter `DriveCollection` Fake value is a sorted letter string stand-in, not a live `DriveByIndex` walk.
- CredSSP wipe ↔ connect Fake glue stays in [adversarial-ledger-rdp-credssp-wipe.md](adversarial-ledger-rdp-credssp-wipe.md); this ledger does not rewrite it.

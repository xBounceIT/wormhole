# Adversarial ledger — OS idle sampling (`os_idle` / `GetLastInputInfo`)

**Scope:** `rust/crates/wormhole-secrets-win/src/os_idle.rs` (new) + registration
+ re-exports in `lib.rs`; doc-only line in `idle_lock.rs` pointing at the new module.

**Out of scope:** WinRT Hello consent; suspend-gap estimation
(`SuspendedTimerGap` stays host responsibility); wiring the sampler into a live
timer/host loop; GPUI/WinUI lock overlay.

**Compared against:** C# idle detector in `Services/Security/` + `Helpers/Win32Interop.cs`
(`GetLastInputInfo` + `unchecked((uint)GetTickCount64())` mod-2³² arithmetic);
`wormhole-secrets-win::idle_lock::AppIdleLockGlue` fail-closed table.

**Authority:** full adversarial-review-fix (reviewer subagent; parent re-verified)  
**Baseline:** secrets-win **225** tests  
**Final:** secrets-win **234** tests; `cargo clippy` zero hits in scope

**Attack focus:** mod-2³² wrap + epoch mapping (pure helpers extracted so CI
exercises them cross-platform), `GetProcAddress` fn-pointer cast soundness
(`isize as u64` value-level, no transmute), cbSize, failure paths fail-closed
(Err → lock when armed), boundary `>=` vs `>`, clock-skew interactions, Debug/Display
redaction, no-assert presence check only for the real API.

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (cycles 5–6 after fixes) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-secrets-win` | **pass** (234) |
| `cargo check -p wormhole-secrets-win` | **pass** |
| `cargo clippy -p wormhole-secrets-win --all-targets` | zero hits in `os_idle.rs` |
| `git diff --check` (scoped) | **pass** |

---

## Accepted findings and fixes

| ID | Sev | Finding | Fix |
|---|---|---|---|
| F1 | P2 | Mod-2³² wrap math + epoch mapping inlined in `#[cfg(windows)]` code CI never exercises | Extracted pure `boot_elapsed_ms` / `last_input_on_clock` helpers + 6 regression tests |
| F2 | P2 | `std::mem::transmute` between fn-pointer types in `GetProcAddress` resolution | Value-level `isize as u64` cast on return register; Safety doc rewritten |
| F3 | P3 | Clock-skew table row + "fail-closed requires armed policy + stale app leg" ordering unpinned | 2 integration tests |
| F4 | P3 | `FakeInputIdleSampler` doc claimed shared fake timeline; epoch is standalone | Doc corrected |
| D4 | P3 | Compose doc said legs must "exceed" timeout; pinned boundary is `>=` | Wording fixed |
| F5 | P3 | `SystemIdleLockClock` import would warn on unsupported non-Windows build | `#[cfg(windows)]`-gated import |
| F6 | P3 | 3 clippy warnings in scope | `c"GetTickCount64"` + `.cast::<u8>()`, `?` on proc, `if let Ok` |
| F7 | P3 | `TickSourceUnavailable` / `UnsupportedPlatform` Display+Debug redaction unpinned | Variant-exact test |

## Regression tests added (9)

`boot_elapsed_ms_matches_csharp_unchecked_arithmetic`, `boot_elapsed_ms_wrap_is_equivalent_to_u32_truncation`,
`last_input_on_clock_places_elapsed_on_clock_timeline`, `last_input_on_clock_zero_elapsed_keeps_now`,
`last_input_on_clock_saturates_when_elapsed_exceeds_epoch`, `last_input_on_clock_accepts_max_masked_elapsed_without_overflow`,
`should_lock_os_idle_clock_skew_disables_os_leg`, `should_lock_os_idle_sample_error_still_requires_stale_app_leg`,
`idle_sample_error_display_covers_all_variants_without_payload`.

### Rejected candidates

49.7-day wrap + `i32::MAX`-minute timeout corner (exact C# `unchecked` parity,
documented); Disabled/already-locked-vs-sample ordering (unobservable — sampling is
pure); `SetLastError(0)`/`GetLastError()` reliability (`GetLastError` never
self-clears).

---

## Test command

```powershell
cd rust
cargo test -p wormhole-secrets-win os_idle
cargo test -p wormhole-secrets-win
cargo clippy -p wormhole-secrets-win --all-targets
```

**Counts:** os_idle **29** tests; full secrets-win **234**.
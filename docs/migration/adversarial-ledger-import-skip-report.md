# Adversarial ledger — Import soft-skip UI report glue (`skip_report`)

**Scope:** `ImportSkipReport` / `report_unsupported_skips` / `format_skip_summary` / `FakeImportSkipReporter` in `rust/crates/wormhole-import/src/skip_report.rs`; docs `12-import.md`; related unit tests.  
**Authority:** full adversarial-review-fix (edit in scope; **no** apply-path rewrite / CredMgr / GPUI).  
**Attack focus:** password leakage, empty plan, unicode names, reason truncation, Fake `Debug`, colon-in-name sample parse, `+N more` semantics.  
**Baseline (pre-fix):** `cargo test -p wormhole-import` green (53 lib + 6 integration).

---

## Accepted findings and fixes

| ID | Sev | Location | Invariant / evidence | Fix | Verification |
|---|---|---|---|---|---|
| SR-01 | P2 | `entry_from_sample` | `split_once(": ")` mis-parsed names containing `: ` (e.g. `lab: prod: HTTP` → name=`lab`) | `rsplit_once(": ")` keeps trailing protocol | `colon_in_connection_name_*` + `xml_colon_and_unicode_*` |
| SR-02 | P2 | tests / unicode | Unicode display names unpinned on report/summary path | Round-trip unit + XML plan→report | `unicode_names_*` / `xml_colon_and_unicode_*` |
| SR-03 | P2 | `format_skip_summary` | Count-only skips (`total>0`, empty samples) emitted misleading `(+N more)` | Append `+N more` only when samples were listed | `count_only_skips_omit_plus_more_*` |
| SR-04 | P2 | Fake / password | Fake path + Fake `Debug` under-pinned vs `PlannedNode.password_plaintext` | Assert Fake report/`Debug` omit secret; Fake `Debug` never echoes names/reasons | `report_never_includes_*` / `fake_reporter_forces_*` |
| SR-05 | P3 | reason / summary | Full `UNSUPPORTED_PROTOCOL_REASON` must not be truncated | Pin full reason in summary | `reason_is_never_truncated_in_summary` |
| SR-06 | P3 | malformed sample | Sample without `: ` delimiter untested | Whole string → name, empty protocol | `malformed_sample_without_delimiter_*` |
| SR-07 | P3 | `force` docs | Comment claimed clear-via-`None`; API is `clear_forced` | Corrected rustdoc on `force` / `clear_forced` | doc review |
| SR-08 | P3 | `12-import.md` | Sample parse / Fake counts-only / reason / `+N more` understated | Soft-skip report table updated | doc review |

### Simplify delta (post-adversarial)

| ID | Sev | Location | Change |
|---|---|---|---|
| S-01 | P3 | `UnsupportedProtocolSkip` / `ImportSkipReport` | Replaced redundant manual `Debug` with `#[derive(Debug)]` (structs have no secret fields; Fake stays counts-only) |

---

## Rejected candidates

| Candidate | Reason |
|---|---|
| Truncate long names/reasons in InfoBar text | Docs require full reason; sample cap (≤5) already bounds volume |
| Reconcile hand-crafted `total_skipped=0` with non-empty `entries` | Contract: empty summary / `is_empty` keyed on `total_skipped` |
| Add `Default` on `ImportPlan` for test helper | Out of skip-report surface (`mremoteng`) |
| Mutex lock helper on Fake | Four call sites; stub noise > value |
| Rewrite `apply` / CredMgr for skips | Explicitly out of scope |
| Map HTTP/HTTPS/Serial into planned nodes so they are not skipped | Explicit non-goal (SSH/RDP/VNC-only) |
| Soften Fake `Debug` to include entry names | Attack lane requires counts-only |

---

## Adversarial clean passes (2 required)

Reset after each fix batch and after simplify implementation deltas.

### Clean pass 1 — order: security → boundaries → contract → concurrency → tests

- Never reads `password_plaintext`; report/`Debug` have no credential fields; Fake `Debug` counts-only.
- Empty skips, unicode, colon-in-name, malformed delimiter, count-only `+N more`, full reason covered.
- C# `name: protocol` sample parity via `rsplit_once`; no apply/CredMgr/GPUI claims.
- Fake mutex poison recovery; `report_calls` atomic — fine for headless stub.
- Attack lanes pinned in unit tests.
- **Accepted findings:** none.

### Clean pass 2 — order: integration → test resistance → state → operability → security

- XML → `plan_nodes` → `report_unsupported_skips` round-trip (incl. unicode/`:` names); apply path untouched.
- Fake force/clear/fall-through; password assertions on both direct and Fake paths.
- Forced report lifecycle does not retain plan secrets.
- Summary operability: pluralization, overflow `+N more`, reason never truncated.
- Password-leakage lane clean after `derive(Debug)` (still no secret fields).
- **Accepted findings:** none.

`adversarial_clean_passes = 2` (after post-simplify re-loop on S-01).

---

## Iterative-review-simplify (3 clean cycles)

Each cycle: Code Reuse → Code Efficiency → Code Quality and Bugs (+ simplify discipline).

| Cycle | Themes | Outcome |
|---|---|---|
| 1 | Reuse (manual `Debug` ≡ derive for non-secret structs); efficiency (≤5 samples — no micro-opts); quality (Fake stays custom `Debug`) | Applied S-01 → adversarial re-looped to 2 clean |
| 2 | No Fake lock helper; no `ImportPlan::Default` scope creep; reason/`+N more` comments accurate | Clean |
| 3 | Docs table matches rsplit / Fake counts-only / full reason; apply/CredMgr untouched | Clean |

`simplify_clean_passes = 3`.

---

## Regression tests added/updated

- `colon_in_connection_name_keeps_trailing_protocol`
- `unicode_names_round_trip_in_report_and_summary`
- `count_only_skips_omit_plus_more_when_no_samples`
- `reason_is_never_truncated_in_summary`
- `malformed_sample_without_delimiter_keeps_whole_as_name`
- `xml_colon_and_unicode_names_plan_into_report`
- Strengthened `report_never_includes_decrypted_passwords` (Fake path)
- Strengthened `fake_reporter_forces_canned_report` (no name/reason in Fake `Debug`)
- Extended `fake_reporter_falls_through_to_plan` (force / `clear_forced`)

---

## Final verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-import
```

Results: **65 passed** (59 lib + 6 integration).

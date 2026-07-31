# Adversarial ledger — Import plan → SQLite apply stub

**Scope:** `ConnectionRepository::insert_many` (transactional parent-before-child, FK/PK rollback); `apply_import_plan` / `planned_to_connection_node` in `wormhole-import` (`storage` feature); soft-skip never written; passwords / CredMgr out of band; docs `12-import.md` / `03-storage.md`; related tests.  
**Authority:** full adversarial-review-fix (edit in scope; no HardwarePass / cutover claims).  
**Attack focus:** partial batch / FK failure atomicity, soft-skip leakage into DB, password fields in mapped nodes, parent/child order, empty plan, duplicate ids, hostile XML→plan→apply paths, Debug secret exposure.  
**Baseline (pre-fix):** `cargo test -p wormhole-import` + `cargo test -p wormhole-storage` green.

---

## Accepted findings and fixes

| ID | Sev | Location | Invariant / evidence | Fix | Verification |
|---|---|---|---|---|---|
| IA-01 | P2 | `insert_many` | Duplicate PK mid-batch must roll back prior rows | Kept one transaction; added regression | `insert_many_rolls_back_on_duplicate_primary_key` |
| IA-02 | P2 | `insert_many` | Child-before-parent (parent later in slice) must fail FK and leave DB empty | Same tx + regression | `insert_many_rejects_child_before_parent_and_rolls_back` |
| IA-03 | P2 | `insert_many` | Collision with pre-existing Id must not leave partial batch | Regression keeps only pre-seeded row | `insert_many_rolls_back_when_id_collides_with_preexisting_row` |
| IA-04 | P2 | `apply` mapping | Hand-crafted `Http`/`Https`/`Serial` on `PlannedNode` could reach SQLite | `reject_gap_protocol` in `planned_to_connection_node` → `InvalidData` before any write | `planned_rejects_gap_protocols_*` + `apply_refuses_handcrafted_http_before_any_write` |
| IA-05 | P2 | apply / tests | SSH/RDP-only round-trip; VNC + Serial soft-skip unpinned on apply path | Extended XML→plan→apply (unit + integration) | `mini_xml_plan_apply_round_trip_ssh_rdp_vnc_skips_gaps` / `…_ssh_rdp_vnc` |
| IA-06 | P2 | password mapping | Password drop incompletely pinned (`use_inline_password` / Debug / CredMgr) | Stronger map + apply asserts; `CredentialProfiles` count = 0 | `planned_to_connection_drops_password_*` / `apply_ignores_password_plaintext_in_sqlite` |
| IA-07 | P3 | RDP domain | Folder `protocol = None` + domain → `rdp_domain` untested | Unit pin | `planned_folder_unset_protocol_keeps_domain_on_rdp_domain` |
| IA-08 | P3 | docs | Soft-skip / atomicity / password out-of-band understated on apply stub | `12-import.md` apply table + `03-storage.md` `insert_many` note | doc review |

### Simplify delta (post-adversarial)

| ID | Sev | Location | Change |
|---|---|---|---|
| S-01 | P3 | `apply` password test | Replaced fragile `group_concat` SQL scan with `list_all` field / Debug asserts + `CredentialProfiles` / `UseInlinePassword` checks |

---

## Rejected candidates

| Candidate | Reason |
|---|---|
| Filter gap protocols in `apply_connection_nodes` | Escape hatch for already-mapped domain nodes; Wormhole HTTP/HTTPS/Serial are valid outside import |
| Soft-delete / skip gap nodes mid-plan instead of `InvalidData` | Fail-closed matches soft-skip contract (gap protocols must never be written) |
| Reject `Guid::nil` on import insert | C# / storage write ledger parity — empty Guid allowed |
| Walk / rewrite child-before-parent automatically | Callers (DFS `plan_nodes`) own order; wrong order correctly fails FK |
| Deduplicate unit vs integration mini-XML fixtures | Crate-boundary value; both pin apply surface |
| `{other:?}` → `{other}` in refuse message | Micro-churn; Display == Debug labels for `ProtocolType` |
| Soften hostile XML at apply | Parse still fail-closed; apply never sees DOCTYPE / `..` / oversized |

---

## Adversarial clean passes (2 required)

Reset after each fix batch. Independent attack order on the second clean pass.

### Clean pass 1 — order: security → boundaries → contract → concurrency → tests

- Passwords ignored; `credential_id` / `use_inline_password` unset; `CredentialProfiles` empty; mapped/`ApplyImportResult` Debug do not echo plaintext.
- Gap protocols rejected before write; empty plan noop; duplicate PK / child-before-parent / orphan FK / preexisting collision roll back.
- `planned_to_connection_node` → `Result`; `insert_many` one transaction; soft-skips only in `skipped` counts.
- Sync repository API; busy timeout on concurrent opens (pre-existing).
- VNC + HTTP/Serial soft-skip, CredMgr out-of-band, DOCTYPE never reaches apply — pinned.
- **Accepted findings:** none.

### Clean pass 2 — order: integration → test resistance → state → operability → security

- C# `CommitAsync` node-insert half (DFS + single tx); CredMgr / `CredentialProfiles` still stubbed — docs accurate, no cutover claim.
- Storage vs import layers both pin atomicity; hand-crafted HTTP blocked at map and apply.
- Partial batch never durable; empty slice no-op.
- Errors are `InvalidData` / `Storage` without secret material.
- Soft-skip leakage and Debug exposure lanes clean.
- **Accepted findings:** none.

`adversarial_clean_passes = 2` (after CredMgr pin; S-01 was test-only, no implementation delta).

---

## Iterative-review-simplify (3 clean cycles)

Each cycle: Code Reuse → Code Efficiency → Code Quality and Bugs (+ simplify discipline).

| Cycle | Themes | Outcome |
|---|---|---|
| 1 | Reuse (keep map/apply layer tests); efficiency (validate-all-then-insert retained); quality (password assert clarity) | Applied S-01 → reset |
| 2 | No further duplication worth extracting; `reject_gap_protocol` single-use; insert path unchanged | Clean |
| 3 | Docs apply/atomicity notes match code; no overclaim of CredMgr/HTTP import; hostile XML tests untouched | Clean |
| 4 | Re-check after doc/ledger — no validated code changes | Clean |

`simplify_clean_passes = 3` (consecutive after S-01).

---

## Regression tests added/updated

- `wormhole-storage`: `insert_many_rolls_back_on_duplicate_primary_key`, `insert_many_rejects_child_before_parent_and_rolls_back`, `insert_many_rolls_back_when_id_collides_with_preexisting_row`
- `wormhole-import` apply units: gap reject, handcrafted HTTP, VNC+soft-skip round-trip, password/CredMgr pin, folder domain, DOCTYPE→no apply
- `tests/apply_round_trip.rs`: SSH/RDP/VNC + HTTPS/Serial soft-skip DB round-trip

---

## Final verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-import
cargo test -p wormhole-storage
```

**Result:** wormhole-import **52** passed (46 lib + 1 apply integration + 5 sample); wormhole-storage lib + integration green (including new `insert_many` regressions). No HardwarePass / cutover claims.

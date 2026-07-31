# Adversarial ledger — CredentialProfiles metadata CRUD

**Scope:**
- `rust/crates/wormhole-storage/src/repos/credential.rs`
- `rust/crates/wormhole-storage/src/credential_glue.rs`
- `models::CredentialProfile`, crate exports in `lib.rs`
- Temp-DB / Fake CredMgr tests in `tests/storage_tests.rs`
- Docs: [`03-storage.md`](03-storage.md), [`04-secrets.md`](04-secrets.md)

**Out of scope:** Live CredMgr / DPAPI production backends; credentials page GPUI;
Bitwarden CLI session; virtual Bitwarden picker rows; C# ViewModel UI; password
bodies in SQLite (forbidden).

**Authority:** full adversarial-review-fix (edit in scope)  
**Compared against:** C# `CredentialRepository` + `CredentialsViewModel` create/rename/delete
ordering + `NormalizeBitwardenFieldPath`  
**Baseline:** `cargo test -p wormhole-storage --test storage_tests credential_profile` — 11 green  
**Final:** **14** credential_* integration tests; full `cargo test -p wormhole-storage` green
(24 lib + 54 integration; 1 ignored fixture generator)

---

## Gate summary

| Gate | Result |
|---|---|
| Adversarial clean passes | **2** consecutive (independent attack order; post-simplify re-run also clean) |
| Iterative-review-simplify clean passes | **3** consecutive |
| `cargo test -p wormhole-storage` | **pass** (24 unit + 54 integration; 1 ignored) |

---

## Accepted findings and fixes

| ID | Sev | Location | Invariant | Evidence | Fix | Verification |
|---|---|---|---|---|---|---|
| CM-01 | P2 | `credential.rs` `normalize_bitwarden_field_path` | Non-blank Bitwarden paths must trim (C# `NormalizeBitwardenFieldPath`) | Prior path returned `Some(s)` without `trim()`; `"  login.custom  "` would persist with spaces | Trim non-blank; blank/None → `login.password` | `credential_profile_normalize_blank_bitwarden_field_path` (create + update) |
| CM-02 | P2 | `insert` + PK | Duplicate `Id` must fail closed | Untested PRIMARY KEY path (tunnel ledger had this) | No code change (SQLite PK); regression | `credential_profile_duplicate_id_insert_rejected` |
| CM-03 | P2 | `map_credential_profile` | Unknown `Protocol` / `SecretProvider` must fail closed on read | Only unknown `Kind` asserted | Extend fail-closed coverage | `credential_profile_rejects_unknown_protocol_and_provider_on_read` |
| CM-04 | P2 | `delete_credential_profile` | Secret cleanup errors must not resurrect metadata | Glue ignores cleanup `Err`; untested | No code change (documented best-effort); regression | `credential_profile_secret_cleanup_errors_do_not_resurrect_row` |
| CM-05 | P3 | `update` rustdoc + `03-storage.md` | Contract docs must state field-path trim + gateway fail-open | `update` docs omitted path trim; table omitted `RdpGatewayCredentialId` | Document trim + both node FK columns | Doc review |

---

## Rejected candidates

| ID | Severity | Reason |
|---|---|---|
| REJ-01 | — | Fail `update`/`delete` when 0 rows affected — C# `ExecuteAsync` same silent no-op |
| REJ-02 | — | Repo-layer in-use delete refusal — no FK; C# check lives in ViewModel; document fail-open |
| REJ-03 | — | Case-insensitive unique names — SQLite `UX_CredentialProfiles_Name` BINARY; C# UI `NameExists` is separate |
| REJ-04 | — | Share `parse_guid_col` / `require_nonblank_*` with `connection.rs` / `tunnel_config.rs` — churn across write path |
| REJ-05 | — | Zero-width / exotic Unicode “blank” names — speculative; `str::trim` covers White_Space |
| REJ-06 | — | Extra fail-open test for `RdpGatewayCredentialId` — same DELETE path already pinned via `CredentialId` |
| REJ-07 | — | Persist virtual Bitwarden / `IsReadOnly` — not SQLite columns; UI concern |
| REJ-08 | — | Wire live CredMgr in storage crate — secrets stay in `wormhole-secrets-win`; glue takes trait |
| REJ-09 | — | Surface secret-cleanup errors to callers — intentional ignore; metadata is source of truth (C# row-first) |

---

## Adversarial cycles

| Pass | Strategy | Accepted | Result |
|---|---|---|---|
| Adv-1 | Contract → boundaries → security → test resistance | CM-01…CM-04 | Fixed; reset |
| Adv-2 | Security → concurrency → integration → docs | CM-05 | Fixed; reset |
| Adv-3 | State/atomicity → reverse security → Fake vs glue | None | Clean (1/2) |
| Adv-4 | Integration drift → performance → tests-as-oracles | None | Clean (2/2) |
| Post-simplify Adv | `normalize`→`String` + UNIX_EPOCH placeholder delta | None | Clean (2/2) |

---

## Simplify passes (iterative-review-simplify)

| Cycle | Reuse | Efficiency | Quality | Disposition |
|---|---|---|---|---|
| 1 | `normalize` always-`Some` → return `String` | `as_deref` avoids `Option` clone on update | Glue `created_at` placeholder → `UNIX_EPOCH` (insert stamps) | **Fixed** → reset (+ adv re-run) |
| 2 | Shared helpers stable; no cross-repo extract | One-conn-per-op; rename 3-hop intentional | Fail-open / Debug / Fake adapter intact | Clean (1/3) |
| 3 | No missed local helpers | No hot-path I/O | Param binding / metadata-only columns | Clean (2/3) |
| 4 | Same | Same | Diff hygiene / ledger | Clean (3/3) |

Simplify cycle 1 changed code → post-simplify adversarial re-run completed clean; Sim-2…4 clean with no further edits.

---

## Attack lane outcomes (summary)

| Lane | Outcome |
|---|---|
| No password bodies in SQLite | `pragma_table_info` + raw row scan vs Fake CredMgr body |
| Blank / whitespace names | Fail-closed `InvalidArgument` on create/rename/update |
| Bitwarden field path | Blank/None → `login.password`; non-blank trimmed |
| Unique name / duplicate Id | UNIQUE index + PK; SQLite errors surfaced |
| Unknown Kind/Protocol/Provider | Fail-closed on `list_all` / `get_by_id` |
| In-use delete | Documented fail-open; node `CredentialId` leftover pinned |
| Delete + secret cleanup | Row first; cleanup errors ignored; metadata stays gone |
| SQL injection via name | Bound params; hostile name round-trips |
| Debug / Memory stub | Ids/counts only; never secret bodies |

---

## Verification

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cd rust
cargo test -p wormhole-storage
```

**Result:** 24 lib + 54 integration passed; 1 ignored fixture generator.

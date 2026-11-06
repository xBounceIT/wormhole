# Dependency update adversarial review

Scope: the complete uncommitted dependency update and its compatibility adapters.
The starting patch and status are recorded in `obj/dependency-review/`.
No unrelated user changes were found or reset.

## Finding ledger

| ID | Severity | Location | Evidence and impact | Disposition / verification |
| --- | --- | --- | --- | --- |
| AR-01 | P1 | `electron/main.ts`, `ssh:paste-clipboard` | Hold the asynchronous clipboard read, lock the real AuthSession, then resolve the read: one SSH input is still sent. The auth lock deliberately bypasses ordinary queued operations; holding that queue cannot protect this await. Go's input handler also retains the active terminal and trusts validated native input. | Fixed. Capture the auth epoch before reading and reuse `requireAuthorizationEpoch` immediately before encoding/sending. Production-handler tests cover lock, lock/unlock, clipboard failure/limits, and serialized input; V8 block coverage is 100%. |
| AR-02 | P2 | `scripts/verify-renderer-assets.mjs`, `afterPack` | electron-builder renames the Windows EXE to `productFilename.exe` but does not rename `electron_wer.dll`. Invoking the registered hook with a valid ASAR leaves the original helper and no matching `Wormhole_wer.dll`. The Inno path already performs the rename; the exposed builder path loses Electron 45 WER crash capture. | Fixed. Reuse the existing rename helper in the Windows hook. Custom Unicode names, repeated runs, legacy runtimes, errors, and non-Windows paths pass; hook/helper line, branch, and function coverage is 100%. |
| AR-03 | P2 | `electron/main.ts`, initial AR-01 fix | The initial split authorization/read/commit fix released the queue during a read. A deferred paste followed by Enter and a second paste sends the latter inputs first: the regression fails with 3 writes where only the earlier write was expected. The renderer does not serialize keyboard events behind native paste. | Fixed. Preserve the existing serialized input queue across the local clipboard read, with AR-01's epoch check at completion. A production-handler regression asserts paste/Enter/paste order and subsequent queue progress. |
| SR-01 | P3 | `tests/auth-session.test.ts`, `tests/terminal-clipboard.test.ts` | The revised minimal AR-01 fix no longer uses the split authorized-operation helper; its old mock and extracted implementation remained in the harness. | Fixed. Remove the unused mock and extract only the real epoch helpers. Both clipboard regressions pass and handler coverage remains 100%. |

## Rejected candidates

- New SMB tag decoder panics on short input: rejected. `fillReparseTag` checks
  `IsInvalid` before access; the newly changed directory decoder also guards its
  104-byte header. Protocol-negative tests cover truncated responses.
- WER staging must roll back the already patched EXE on helper failure: rejected.
  The staging command fails and no installer is published; rerunning staging is
  supported. A transaction across disposable build files is not required.
- Removed SDK v1 dependency tests hide a currently installed vulnerable package:
  rejected. Those packages are absent from the current lock graph, and version
  checks remain active for installed copies. Reintroduction must restore the
  applicable integration checks; installed package audits remain required.
- Replace tested gVisor with an untagged master revision: rejected. This is an
  explicit compatibility replacement shared with the refreshed WireGuard module,
  not an accidental missed stable update.
- Native capability fixture substitutes a reduced interface: no current defect.
  The actual shim was also compiled against the pinned SDK on x64 and arm64.
- A clipboard read could target a reconnected terminal under the old ID: rejected
  for the supported UI flow. Reconnect assigns a fresh backend session token;
  Go rejects input for absent sessions. This does not replace the auth epoch check.
- Restoring maximum sidebar width could bypass a viewport clamp: rejected after
  a new native regression test pins an unpinned 600px preference in the narrower
  test viewport and verifies that the panel stays outside unoccluded native content.
- Introduce a new per-session queue to release the global auth queue during local
  clipboard reads: rejected as unnecessary scope and ordering risk. Preserve the
  existing FIFO contract; the independent lock invalidates the read's epoch.

## Review gates

Initial adversarial cycle reviewed contract/boundaries, state/atomicity,
concurrency/lifecycle, security/privacy, integration drift, performance/operability,
and test resistance before fixes. Baseline focused suites: 69 passed, 5 skipped
because the legacy CLI dependencies were removed; WER helper coverage 100%.

AR-01 and AR-02 failed against the starting implementation. AR-03 failed against
the initial AR-01 fix. All pass on the final implementation. No accepted finding
remains open or blocked. AR-03 invalidated the earlier clean counters; the cycles
below were repeated after that fix. SR-01 changes test plumbing only.

## Completed review cycles

| Gate / cycle | Reading order and evidence | Result |
| --- | --- | --- |
| Adversarial 1 | Sources to callers: clipboard auth epoch and FIFO queue, independent lock, renderer keyboard/paste dispatch, backend input; Windows hooks, lock graph, native TLS factory, SMB decoder/modes and failure tests. Rechecked all eight attack lanes. | No findings; clean count 1. |
| Adversarial 2 | Sinks to sources: native input and EXE/helper output; reconnect tokens, stale/failed reads, queue rejection recovery, negative assertions/coverage, maximum panel clamp, platform hooks, protocol buffers and dependency provenance. Rechecked all eight lanes independently. | No findings; clean count 2. |
| Simplify 1 | Reuse: existing serializer, epoch validator, rename and coverage helpers; obsolete test plumbing removed before restarting the count. Efficiency: preserve FIFO without another queue or backend read. Quality: epoch checked after the await and immediately before the synchronous send. | No further findings in all three passes; clean count 1. |
| Simplify 2 | Reuse: both packager hooks and native compatibility adapters. Efficiency: one rename, no non-Windows I/O, bounded compositor retries. Quality: Unicode names, repeated staging/errors, renderer identity, sidebar constraints and cache privacy. | No findings in all three passes; clean count 2. |
| Simplify 3 | Reuse: final diff, real helpers and test harnesses. Efficiency: queue recovery, native lifecycle and bounded tests. Quality: mutation resistance, security negatives, dependency provenance/platform matrix and stable-version exceptions. | No findings in all three passes; clean count 3. |

The installed simplify workflow was executed locally. Its cleanup changed tests
only, so it introduced no new implementation adversarial reset requirement. A generic new test
harness, a filesystem transaction over disposable staging files, and making every
packaging hook asynchronous were rejected as unnecessary churn or contract changes.

The final npm inventory identified oxfmt 0.77.0, which was also updated and passed
the format gate. Only the intentionally compatible Node 24 type definitions remain
behind the Node 26 `latest` tag; other native/Go compatibility pins are documented
in the dependency refresh report.

## Final verification

- Focused auth/clipboard/packaging tests: 55 passed. The ordering reproduction
  fails before AR-03's fix; the final source-extracted handlers have 100% V8
  block coverage. The simplified harness's two targeted clipboard tests also pass.
- `npm run test:electron`: passed. Node reports 1,132 tests, 1,126 passed and
  six expected skips; all 30 .NET tests and all backend/sidecar Go suites pass.
  Five skips cover removed CLI dependencies, and one covers POSIX execute bits
  on Windows. No assertions were weakened to achieve these results.
- `npm run build`: passed, including the real OpenVPN3 sidecar and host x64
  backend/sidecars. The dependency refresh also verified Windows arm64 builds
  and portable Linux amd64/arm64 compilation, as recorded in its report.
- `npm run test:coverage`: passed. Loaded TypeScript modules: 95.02% lines,
  92.84% branches, 94.96% functions. Go: 83.83% statements (21,215/25,308).
  WER helper/hook: 100% lines, branches and functions; native sidebar: 98.57%
  V8 blocks. Upstream vendor-code and process-entrypoint exclusions follow the
  project's documented tooling and focused instrumentation.
- `npm run typecheck`, `npm run lint`, `npm run format:check`: passed, with
  additional targeted lint/format checks for `tests/auth-session.test.ts`.
  oxfmt 0.77.0 passes without source reformatting. Oxlint reports 29 React
  warnings in existing UI code; none are suppressed.
- `npm audit`: zero vulnerabilities after the final formatter update.
  Backend govulncheck: no vulnerable symbols or imported packages; the known
  unused OpenPGP module advisory remains, with its fix unreleased as a stable
  x/crypto version. The refresh report records the remaining module/native audits.
- Final `npm outdated`: only Node 24 types versus Node 26's latest tag, retained
  for runtime/CI compatibility. Other intentional native and Go pins are documented.
- `git diff --check`: passed. Reviewed final status/diff for accidental files,
  debug logging, secrets, skipped coverage and unrelated edits. These results
  describe verification before committing and publishing the pull request.

Native macOS builds and real VPN-provider/login interoperability remain checks
for their native CI/integration environments. No accepted finding is blocked.
Evidence logs are retained under `obj/dependency-review/` (ignored build output).

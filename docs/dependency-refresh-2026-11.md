# Dependency refresh: 2026-11-06

Registry metadata was checked on 2026-11-06. npm dependencies, overrides, Go module
requirements, NuGet packages, native sources, and pinned CI tools were reviewed.
The manifests and lockfiles record the complete versions.

## Main updates

| Dependency | Previous | Updated |
| --- | --- | --- |
| Electron | 43.8.1 | 45.2.3 |
| React / React DOM | 19.2.8 | 19.3.1 |
| Vite / React plugin | 8.3.4 / 6.0.5 | 8.3.6 / 6.2.1 |
| electron-builder / extension APIs | 26.15.3 / 4.9.0 | 26.18.0 / 4.10.0 |
| Go x/net | 0.54.0 in backend | 0.62.0 throughout consuming modules |
| Go x/crypto / x/sys / x/text | 0.52.0 / 0.47.0 / 0.37.0 in backend | 0.58.0 / 0.49.0 / 0.43.0 |
| MCP Go SDK / SQLite | 1.7.0 / 1.56.0 | 1.8.0 / 1.61.1 |
| WireGuard | ecfc5a8d5446 | b3bc704ef0ee |
| SMB fork upstream | 0c5d69b69701 | 95be04a983b8 |
| HTTP cache fork upstream | 4.2.0 | 4.3.0 |
| OpenVPN3 / mbedTLS | 3.9 / 3.6.6 | 3.11.8 / 3.6.7 LTS |
| .NET Test SDK / VS xUnit runner | 18.5.1 / 2.8.2 | 18.11.0 / 4.0.1 |
| LLVM-MinGW ARM64 cross compiler | 20260602 | 20261104 |
| oxfmt | 0.72.0 | 0.77.0 |

Other UI and development packages were updated to their stable npm `latest` tags.
Every non-replaced Go requirement was checked against its module's latest release;
modules without release tags retain upstream pseudo-versions. Local replacements
remain explicit. The vcpkg registry is pinned to the 2026-11-06 snapshot
`054bd01bec7f31492ec9ac063740cc984a0fe59e`. Updated GitHub Actions remain pinned by SHA.

## Compatibility decisions

- Keep Node types on the latest Node 24 release, matching CI and Electron 45's
  embedded Node 24. Node 26 types would expose APIs unavailable to these runtimes.
- Keep gVisor at WireGuard's tested `39ed1f5ac29c` replacement. The latest WireGuard
  module still selects this netstack; newer untagged revisions are outside this
  integration's tested netstack contract. Go's existing 1.26.10 security floor is retained.
- Keep FreeRDP 3.33.0, already the latest stable release, paired with SDL 3.4.18.
  The existing native contract documents unavailable SDL events with 3.4.20.
- Use mbedTLS 3.6.7 LTS. OpenVPN3 still uses deprecated 3.x APIs; migrating to
  mbedTLS 4.2 requires a separate API migration. Preserve DATA_V2 negotiation and
  all remaining required certificate, CBC, and key-export compatibility patches.
- Preserve the braces/deepmerge security forks and rimraf callback adapter; their
  upstream releases are unchanged. Rebase the HTTP cache fork onto 4.3.0 while
  retaining stronger stale-reuse restrictions and linear header parsing.
- Allow only the reviewed, development-only `@opentelemetry/sdk-trace-base@2.12.0`
  deprecation: current react-doctor/Sentry require its v2 API. The replacement
  `@opentelemetry/sdk-trace@3.1.0` is not a compatible package substitution. The
  packaging test rejects any other deprecated dependency or a changed exception.
- shadcn now uses the split MCP v2 server package. Tests for removed SDK v1,
  Express, Hono, and IP parser dependencies skip when those packages are absent;
  version checks and regression tests remain active for every installed copy.

## Adaptations and validation

Electron clipboard reads are awaited, including rejection and empty-input tests.
The authorization epoch is rechecked after the read, rejecting text obtained
before a lock even if the workspace was subsequently unlocked. Native paste,
keyboard input, and successive pastes retain the existing FIFO order. The real
IPC handlers measure 100% V8 block coverage.
The removed extension `license` option was dropped. Windows executable staging also
renames `electron_wer.dll` to `Wormhole_wer.dll`; direct and installer-command
regressions measure 100% line, branch, and function coverage of the helper. The
electron-builder hook also uses this helper; the hook measures 100% line, branch,
and function coverage across Windows, macOS and Linux contracts.
The sidebar ignores transient constraint-resize notifications while restoring its
saved pinned width; its native integration measures 98.57% V8 block coverage.
Glob/minimatch regression
tests now expect explicit rejection of pattern amplification, preserving ordinary
packaging matching. Hidden-window screenshot tests retry compositor frames before
applying their unchanged physical-pixel assertions, and commit hit-test regions
before sending hover input.

OpenVPN3 links the vendored TLS target directly and implements the new factory
capability. GCC/gcov measures 100% coverage of that capability. V8 LCOV measures
100% of the six executable lines added to the HTTP cache fork. Unchanged upstream
vendor code and dependency declarations are excluded from changed application-code
coverage. CMake configuration is outside V8/Go instrumentation and is checked by
real OpenVPN3 builds on Windows x64 and arm64. Process entrypoints retain the
project's IPC/CLI integration coverage rather than being counted as imported
Node unit modules.

The complete coverage gate measured TypeScript at 95.02% lines, 92.84% branches,
and 94.96% functions, and Go at 83.83% statements (21,215/25,308). Windows x64 and
arm64 backend, VPN sidecar, and .NET adapter builds passed; PE machine types were
checked for all sixteen binaries. The portable backend and five Go VPN sidecars
also cross-compiled for Linux amd64 and arm64. All 30 .NET adapter tests passed.
Typecheck, formatter, and .NET formatting gates pass. Updated oxlint exits zero
and reports 29 React diagnostics in existing UI code; these are not suppressed.
The final `npm run test:electron` passes in full, including the refreshed native
packaging/extension tests, backend, SMB contracts, credential reader, every VPN
sidecar, and the vendored IPsec engine. Focused upstream SMB decoder/reparse tests
also pass. Host development artifacts are restored to x64 after ARM64 checks.

`npm audit` and the NuGet audit report no vulnerabilities. govulncheck reports no
affected code or imported packages in the scanned Go modules. Its module-only
[OpenPGP advisory](https://pkg.go.dev/vuln/GO-2026-5932) remains in stable x/crypto
0.58.0; OpenPGP is not imported. The reported fix is an unreleased pseudo-version.

Native macOS builds and real VPN-provider/login interoperability require their
respective native CI and integration environments; cross-compilation does not
establish those runtime behaviors.

The [adversarial review](dependency-adversarial-review-2026-11.md) records the
findings, regression reproductions, rejected candidates and repeated review gates.

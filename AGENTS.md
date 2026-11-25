<!-- Canonical agent guide. CLAUDE.md links to this file. -->

# Wormhole

Electron desktop application for Windows, macOS, and Linux.

## Architecture

- `src/`: React and TypeScript UI. Access the application through the preload
  bridge; keep filesystem, network, credentials, and domain logic out of React.
- `electron/`: thin main/preload layer for window lifecycle, isolated Chromium
  surfaces, and validated IPC. Delegate backend behavior to Go.
- `tools/`: Go owns persistence, versioned SQLite migrations, authentication,
  secrets, profiles and inheritance, protocols, sessions, VPNs, imports, and
  updates. Keep shared code portable and OS-specific behavior in native adapters.
- `tools/wormhole-rdp-host/`: Windows C# adapter for the mstscax surface only;
  keep it isolated, secret-free, and free of backend logic.

## Invariants

- Keep secrets in Go-owned protected stores or pass them through stdin. Never
  expose passwords, tokens, private keys, tunnel payloads, or auth cookies in
  logs, command-line arguments, renderer state, or unencrypted files.
- Validate and bound IPC/process messages and terminal scrollback. Reserve
  stdout for protocol data and stderr for diagnostics.
- Keep web sessions in isolated Chromium profiles, with authentication secrets
  in their owning native flow.
- VPN failures must fail closed, never fall back to direct connections.
  Acquire and release session tunnel leases deterministically.
- Preserve equivalent behavior across supported platforms and Windows x64/arm64
  packaging. Use the existing Electron release scripts; no MSIX or alternate shell.
- Preserve existing user changes and keep edits within the requested scope.

## Visual changelog

- For each change, consider whether it introduces a user-visible feature or a
  workflow change worth explaining in the visual changelog. If it does, ask the
  user whether to include it unless they already gave direction.
- Keep `src/changelog/latest-release.ts` focused on one upcoming stable major
  or minor release. When preparing that release, use its intended `X.Y.0` tag
  version, replace the previous release, and keep each approved change to one slide.
- Give each slide a title, a short subtitle, and an image, GIF, or video bundled
  with the renderer. Use demo data in captures. Supply alt text for images, a
  still image for reduced motion with GIFs, and captions for videos with speech.

## Working approach

Use your judgment to choose the approach, tools, and depth of analysis appropriate
for the task. Make reasonable assumptions for routine decisions and ask when
missing information materially affects the outcome.

Code changes require automated tests for critical behavior, error paths, and
regressions. Use the project's coverage reports to identify gaps and document
justified exclusions. Avoid tests written only to inflate coverage.

Choose checks based on the affected code and risk, respecting existing CI gates.
Report what was verified and any remaining limitations.

## Commands

- Setup / development: `npm install`, `npm run dev`.
- Build: `npm run build`; packaging variants are in `package.json` and `scripts/`.
- Full test suite: `npm run test:electron`.
- Static checks: `npm run typecheck`, `npm run lint`, `npm run format:check`.
- Backend iteration: run `go test ./...` from `tools/wormhole-backend/`.

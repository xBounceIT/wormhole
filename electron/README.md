# Wormhole Electron migration shell

This directory contains the Electron main process. The React renderer lives in
`src/` so the new shell can sit beside the existing WinUI 3 implementation while
protocol providers are migrated incrementally.

From the repository root:

```powershell
npm install
npm run dev
```

The renderer uses Vite 8, React, TypeScript 7, Shadcn/Radix components, Oxlint,
and Oxfmt. `npm run build` creates the static renderer in `dist/` and
the Electron process bundle in `dist-electron/`.

The initial content is intentionally a migration preview: connection and
session data are local mock state, while the shell shape mirrors the current
WinUI layout (title bar, update strip, connection tree, footer navigation,
session tabs, and protocol surface).

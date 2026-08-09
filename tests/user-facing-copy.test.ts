import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import path from 'node:path';

const repoRoot = path.resolve(import.meta.dirname, '..');
const runtimeSources = [
  'package.json',
  'src/App.tsx',
  'src/main.tsx',
  'src/rdp-state.ts',
  'src/components/RdpSurface.tsx',
  'src/components/VncSurface.tsx',
  'electron/main.ts',
  'electron/rdp.ts',
  'electron/serial.ts',
  'tools/wormhole-backend/bitwarden_extension_installer.go',
  'tools/wormhole-backend/credential_secret_darwin_nocgo.go',
  'tools/wormhole-backend/credentials.go',
  'tools/wormhole-backend/dpapi_windows.go',
  'tools/wormhole-backend/main.go',
  'tools/wormhole-backend/rdp.go',
  'tools/wormhole-backend/vnc.go',
  'tools/wormhole-backend/workspace_migrations.go',
];

const forbiddenCopy = [
  /Electron build/i,
  /Electron Go backend/i,
  /native backend/i,
  /(?:RDP|VNC|SSH|MCP|serial) backend/i,
  /native (?:SSH|RDP|VNC|SFTP|VPN|serial|workspace|credential|remote desktop|web browser) bridge/i,
  /native bootstrap/i,
  /native update service/i,
  /native encrypted store/i,
  /protected native store/i,
  /native parser/i,
  /Wormhole for WinUI3/i,
  /WinUI-compatible/i,
  /dedicated WebView2 profile/i,
  /Windows ActiveX surface/i,
  /FreeRDP surface/i,
  /requires Node\.js\s*\/\s*npx/i,
  /in-process userspace/i,
  /Electron safe-storage/i,
  /Electron cannot/i,
  /compatible with Electron/i,
  /cgo-enabled Wormhole backend/i,
  /Windows native RDP host/i,
  /native RDP host/i,
  /FreeRDP is not installed/i,
];

function withoutCommentLines(source: string): string {
  let inBlockComment = false;
  return source
    .split(/\r?\n/)
    .map((line) => {
      const trimmed = line.trimStart();
      if (inBlockComment) {
        if (trimmed.includes('*/')) inBlockComment = false;
        return '';
      }
      if (trimmed.startsWith('//')) return '';
      if (trimmed.startsWith('/*') || trimmed.startsWith('{/*')) {
        if (!trimmed.includes('*/')) inBlockComment = true;
        return '';
      }
      return line;
    })
    .join('\n');
}

test('user-facing copy does not disclose the application stack', async () => {
  for (const relativePath of runtimeSources) {
    const source = withoutCommentLines(await readFile(path.join(repoRoot, relativePath), 'utf8'));
    for (const pattern of forbiddenCopy) {
      assert.doesNotMatch(
        source,
        pattern,
        `${relativePath} contains stack-specific copy matched by ${pattern}`,
      );
    }
  }
});

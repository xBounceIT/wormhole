import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

if (process.platform !== 'darwin') throw Error('Build the Touch ID helper on macOS.');

const root = fileURLToPath(new URL('../', import.meta.url));
const source = path.join(root, 'tools', 'wormhole-touch-id');
const contents = path.join(
  root,
  'dist-electron',
  'wormhole-touch-id',
  'Wormhole Vault Touch ID.app',
  'Contents',
);
const binary = path.join(contents, 'MacOS', 'WormholeVaultTouchID');
mkdirSync(path.dirname(binary), { recursive: true });
execFileSync(
  '/usr/bin/xcrun',
  [
    '--sdk',
    'macosx',
    'clang',
    '-arch',
    'arm64',
    '-arch',
    'x86_64',
    '-mmacosx-version-min=12.0',
    '-fobjc-arc',
    '-Wall',
    '-Wextra',
    '-Werror',
    '-framework',
    'Foundation',
    '-framework',
    'Security',
    '-framework',
    'LocalAuthentication',
    path.join(source, 'main.m'),
    '-o',
    binary,
  ],
  { stdio: 'inherit' },
);
execFileSync('/usr/bin/xcrun', ['lipo', '-verify_arch', 'arm64', 'x86_64', binary], {
  stdio: 'inherit',
});
copyFileSync(path.join(source, 'Info.plist'), path.join(contents, 'Info.plist'));

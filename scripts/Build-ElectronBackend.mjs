import { mkdirSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptRoot = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.dirname(scriptRoot);
const sourceDir = path.join(repoRoot, 'tools', 'wormhole-backend');
const stagingDir = path.join(repoRoot, 'dist-electron');
const architecture = readArchitecture(process.argv.slice(2));
const goos = process.platform === 'win32' ? 'windows' : process.platform;
const goarch = architecture === 'arm64' ? 'arm64' : 'amd64';
const suffix = goos === 'windows' ? '.exe' : '';
const binaryPath = path.join(stagingDir, `wormhole-backend-${architecture}${suffix}`);

mkdirSync(stagingDir, { recursive: true });
rmSync(binaryPath, { force: true });

console.log(`BUILD wormhole-backend (${goos}/${architecture})`);
const result = spawnSync('go', ['build', '-trimpath', '-ldflags', '-s -w', '-o', binaryPath, '.'], {
  cwd: sourceDir,
  env: {
    ...process.env,
    CGO_ENABLED: '0',
    GOARCH: goarch,
    GOOS: goos,
  },
  stdio: 'inherit',
  windowsHide: true,
});

if (result.error) {
  throw new Error(`Could not start Go: ${result.error.message}`);
}
if (result.status !== 0) {
  process.exit(result.status ?? 1);
}

console.log(`OK    ${binaryPath}`);

function readArchitecture(args) {
  const value = args.find((arg) => arg === '--arch' || arg.startsWith('--arch='));
  const architectureValue = value?.startsWith('--arch=')
    ? value.slice('--arch='.length)
    : args[args.indexOf('--arch') + 1];
  if (value && !architectureValue) {
    throw new Error('Missing backend architecture. Use --arch=x64 or --arch=arm64.');
  }
  if (architectureValue === 'x64' || architectureValue === 'arm64') return architectureValue;
  if (architectureValue) {
    throw new Error(`Unsupported backend architecture '${architectureValue}'. Use x64 or arm64.`);
  }
  return process.arch === 'arm64' ? 'arm64' : 'x64';
}

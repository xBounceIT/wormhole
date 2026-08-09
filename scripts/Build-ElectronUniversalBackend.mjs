import { chmodSync, copyFileSync, existsSync, mkdirSync, renameSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptRoot = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.dirname(scriptRoot);
const backendScript = path.join(scriptRoot, 'Build-ElectronBackend.mjs');
const stagingDir = path.join(repoRoot, 'dist-electron');
const temporaryDir = path.join(repoRoot, 'obj', 'electron-universal-backend');
const sidecarNames = [
  'wormhole-wgproxy',
  'wormhole-ovpnproxy',
  'wormhole-fortiproxy',
  'wormhole-ciscoproxy',
];

if (process.platform !== 'darwin') {
  throw new Error('The universal Electron backend must be built natively on macOS.');
}
const sdkRoot = resolveMacOsSdk();

assertWorkspacePath(temporaryDir);
rmSync(temporaryDir, { recursive: true, force: true });
mkdirSync(temporaryDir, { recursive: true });

try {
  buildArchitecture('x64');
  for (const name of sidecarNames) {
    const source = path.join(stagingDir, name);
    assertFileExists(source);
    copyFileSync(source, path.join(temporaryDir, `${name}-x64`));
  }

  buildArchitecture('arm64');
  mergeUniversalBinary(
    path.join(stagingDir, 'wormhole-backend-x64'),
    path.join(stagingDir, 'wormhole-backend-arm64'),
    path.join(stagingDir, 'wormhole-backend-universal'),
  );
  rmSync(path.join(stagingDir, 'wormhole-backend-x64'), { force: true });
  rmSync(path.join(stagingDir, 'wormhole-backend-arm64'), { force: true });

  for (const name of sidecarNames) {
    const x64Path = path.join(temporaryDir, `${name}-x64`);
    const arm64Path = path.join(stagingDir, name);
    const universalPath = path.join(temporaryDir, name);
    assertFileExists(arm64Path);
    mergeUniversalBinary(x64Path, arm64Path, universalPath);
    rmSync(arm64Path, { force: true });
    renameSync(universalPath, arm64Path);
    console.log(`OK    ${arm64Path} (universal x64 + arm64)`);
  }
} finally {
  rmSync(temporaryDir, { recursive: true, force: true });
}

function buildArchitecture(architecture) {
  run(process.execPath, [backendScript, '--arch', architecture]);
}

function mergeUniversalBinary(x64Path, arm64Path, outputPath) {
  assertFileExists(x64Path);
  assertFileExists(arm64Path);
  rmSync(outputPath, { force: true });
  run('lipo', ['-create', x64Path, arm64Path, '-output', outputPath]);
  run('lipo', [outputPath, '-verify_arch', 'x86_64', 'arm64']);
  chmodSync(outputPath, 0o755);
  console.log(`OK    ${outputPath} (universal x64 + arm64)`);
}

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    env: { ...process.env, SDKROOT: sdkRoot },
    stdio: 'inherit',
  });
  if (result.error) throw new Error(`Could not start ${command}: ${result.error.message}`);
  if (result.status !== 0) throw new Error(`${command} failed with exit ${result.status ?? 1}.`);
}

function resolveMacOsSdk() {
  const result = spawnSync('xcrun', ['--sdk', 'macosx', '--show-sdk-path'], {
    encoding: 'utf8',
  });
  if (result.error) throw new Error(`Could not start xcrun: ${result.error.message}`);
  if (result.status !== 0 || !result.stdout.trim()) {
    throw new Error('Could not resolve the installed macOS SDK.');
  }
  return result.stdout.trim();
}

function assertFileExists(filePath) {
  if (!existsSync(filePath)) throw new Error(`Expected build output is missing: ${filePath}`);
}

function assertWorkspacePath(candidate) {
  const relative = path.relative(repoRoot, path.resolve(candidate));
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error(`Refusing to modify a path outside the repository: ${candidate}`);
  }
}

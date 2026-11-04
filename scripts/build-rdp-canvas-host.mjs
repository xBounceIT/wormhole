import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Reuses FreeRDP's existing build trees. This does not download or install
// FreeRDP: dependency provisioning stays with the existing packaging workflow.
export function buildRdpCanvasHost({ repoRoot, platform = process.platform, spawn = spawnSync }) {
  if (platform !== 'darwin') return;
  const source = path.join(repoRoot, 'tools', 'wormhole-freerdp-host');
  const output = path.join(repoRoot, 'dist-electron', 'wormhole-freerdp-host');
  const run = (args, command = 'cmake') => {
    const result = spawn(command, args, { cwd: repoRoot, stdio: 'inherit' });
    if (result.error) throw result.error;
    if (result.status !== 0) throw new Error(`RDP canvas build failed: ${command}`);
  };
  const slices = [];
  for (const architecture of ['x64', 'arm64']) {
    const build = path.join(repoRoot, 'obj', 'macos-freerdp', `${architecture}-osx`);
    if (!existsSync(path.join(build, 'CMakeCache.txt'))) {
      throw new Error('Build the macOS FreeRDP runtime before building the RDP canvas adapter.');
    }
    run([
      '-S',
      path.join(repoRoot, 'obj', 'freerdp-source'),
      '-B',
      build,
      `-DCMAKE_PROJECT_FreeRDP_INCLUDE=${path.join(source, 'register.cmake')}`,
      `-DWORMHOLE_RDP_SURFACE_SOURCE=${source}`,
    ]);
    run(['--build', build, '--target', 'wormhole-freerdp-host', '--parallel', '4']);
    slices.push(path.join(build, 'wormhole-surface', 'wormhole-freerdp-host'));
  }
  mkdirSync(path.dirname(output), { recursive: true });
  run(['-create', ...slices, '-output', output], 'lipo');
  run([output, '-verify_arch', 'x86_64', 'arm64'], 'lipo');
  run(['--force', '--sign', '-', output], 'codesign');
  return output;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  buildRdpCanvasHost({ repoRoot: fileURLToPath(new URL('..', import.meta.url)) });
}

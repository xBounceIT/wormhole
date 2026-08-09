import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
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
// The macOS credential implementation calls Keychain through Security.framework. It must be
// built natively with the Apple SDK; the Windows and Linux backends remain pure Go.
const cgoEnabled = goos === 'darwin' ? '1' : '0';

mkdirSync(stagingDir, { recursive: true });
rmSync(binaryPath, { force: true });

console.log(`BUILD wormhole-backend (${goos}/${architecture})`);
const result = spawnSync('go', ['build', '-trimpath', '-ldflags', '-s -w', '-o', binaryPath, '.'], {
  cwd: sourceDir,
  env: {
    ...process.env,
    CGO_ENABLED: cgoEnabled,
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

// The VPN implementations are independent Go sidecars. Build their portable variants beside
// the native backend so Linux/macOS development builds can exercise WireGuard, Fortinet, and
// Cisco too. On Windows, wormhole-ovpnproxy must NOT be replaced by the portable mock-only
// build: the real OpenVPN3-linked binary produced by scripts/Fetch-OvpnProxy.ps1 (staged under
// obj\ovpnproxy\<arch>) is reused when present so a plain `npm run build` can never silently
// regress OpenVPN/WatchGuard/Stormshield tunnels to the "binding not linked" stub.
for (const name of ['wormhole-wgproxy', 'wormhole-ovpnproxy', 'wormhole-fortiproxy', 'wormhole-ciscoproxy']) {
  const source = path.join(repoRoot, 'tools', name);
  const output = path.join(stagingDir, `${name}${suffix}`);
  rmSync(output, { force: true });
  if (goos === 'windows' && name === 'wormhole-ovpnproxy') {
    const realSource = path.join(repoRoot, 'obj', 'ovpnproxy', architecture, 'wormhole-ovpnproxy.exe');
    if (existsSync(realSource) && !isMockOnlyOvpnProxy(realSource)) {
      copyFileSync(realSource, output);
      console.log(`OK    ${output} (real OpenVPN3 build from obj\\ovpnproxy\\${architecture})`);
      continue;
    }
    if (existsSync(realSource)) {
      console.warn(
        `wormhole-ovpnproxy.exe under obj\\ovpnproxy\\${architecture} is the development-only mock stub; building the portable fallback. ` +
        'Run scripts\\Fetch-OvpnProxy.ps1 -Arch ' + architecture + ' -RequireReal before packaging.',
      );
    }
  }
  console.log(`BUILD ${name} (${goos}/${architecture})`);
  const sidecar = spawnSync('go', ['build', '-trimpath', '-ldflags', '-s -w', '-o', output, '.'], {
    cwd: source,
    env: {
      ...process.env,
      CGO_ENABLED: '0',
      GOARCH: goarch,
      GOOS: goos,
    },
    stdio: 'inherit',
    windowsHide: true,
  });
  if (sidecar.error) throw new Error(`Could not start ${name}: ${sidecar.error.message}`);
  if (sidecar.status !== 0) process.exit(sidecar.status ?? 1);
  console.log(`OK    ${output}`);
}

function isMockOnlyOvpnProxy(path) {
  try {
    const bytes = readFileSync(path);
    return bytes.includes(Buffer.from('binding not linked', 'ascii'));
  } catch {
    return true;
  }
}

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

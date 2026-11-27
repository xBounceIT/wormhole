import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { closeSync, existsSync } from 'node:fs';
import { copyFile, glob, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { coerce, prerelease, satisfies, valid } from 'semver';
import { parse } from 'yaml';
import { backendGoToolchain } from '../scripts/backend-go-toolchain.mjs';
import {
  touchIDBundleIdentifier,
  touchIDEntitlements,
} from '../scripts/sign-macos-with-touch-id.mjs';

const require = createRequire(import.meta.url);
const { convertIcon } = require('app-builder-lib/out/util/iconConverter.js');

const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
const packageLock = JSON.parse(
  await readFile(new URL('../package-lock.json', import.meta.url), 'utf8'),
);
const releaseWorkflow = await readFile(
  new URL('../.github/workflows/release.yml', import.meta.url),
  'utf8',
);
const ciWorkflow = await readFile(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8');
const releaseConfig = parse(releaseWorkflow);
const releaseJobs = releaseConfig.jobs;
const windowsOvpnSetup = parse(
  await readFile(
    new URL('../.github/actions/setup-windows-ovpn/action.yml', import.meta.url),
    'utf8',
  ),
);
const linuxIconSizes = [16, 24, 32, 48, 64, 96, 128, 256, 512, 1024];
const projectDir = fileURLToPath(new URL('..', import.meta.url));
const macIcon = await readFile(new URL('../Assets/Wormhole.icns', import.meta.url));
const bash =
  process.platform === 'win32'
    ? resolve(
        execFileSync('git', ['--exec-path'], { encoding: 'utf8' }).trim(),
        '../../../bin/bash.exe',
      )
    : 'bash';

test('Windows installer retires only the legacy Wormhole LocalDumps defaults', async () => {
  const installer = await readFile(
    new URL('../installer/Wormhole.Electron.iss', import.meta.url),
    'utf8',
  );
  const registry = /^\[Registry\]\r?\n([^[]*)/m.exec(installer)?.[1] ?? '';
  assert.doesNotMatch(registry, /LocalDumps/i);
  assert.match(installer, /LocalDumps\\\{#MyAppExeName\}/);
  const [, guards, removal] =
    /procedure RemoveLegacyLocalDumps;([\s\S]*?)(RegDeleteValue[\s\S]*?)\r?\nend;/.exec(
      installer,
    ) ?? [];
  assert.ok(guards && removal);
  assert.match(guards, /GetArrayLength\(Names\) <> 3 then Exit/);
  assert.match(guards, /GetArrayLength\(Subkeys\) <> 0 then Exit/);
  assert.match(guards, /CompareText\(Folder, '%LOCALAPPDATA%\\Wormhole\\crashdumps'\) <> 0/);
  assert.match(guards, /\(Count <> 10\) or \(DumpType <> 1\) then Exit/);
  assert.deepEqual(
    [...removal.matchAll(/RegDeleteValue\(HKLM, LegacyLocalDumps, '([^']+)'\)/g)].map(
      ([, value]) => value,
    ),
    ['DumpFolder', 'DumpCount', 'DumpType'],
  );
  assert.match(removal, /RegDeleteKeyIfEmpty\(HKLM, LegacyLocalDumps\)/);
  assert.doesNotMatch(removal, /RegDeleteKeyIncludingSubkeys/);
  assert.match(installer, /if CurStep = ssPostInstall then\s+begin\s+RemoveLegacyLocalDumps;/);
});

test('Windows installer scopes WER exclusion to its own executable and preserves existing entries', async () => {
  const installer = await readFile(
    new URL('../installer/Wormhole.Electron.iss', import.meta.url),
    'utf8',
  );
  assert.match(installer, /^#define MyAppExeName\s+"Wormhole\.exe"/m);
  const provision = installer.slice(
    installer.indexOf('procedure InstallWerExclusion;'),
    installer.indexOf('procedure RemoveOwnedWerExclusion;'),
  );
  assert.match(provision, /RegValueExists\(HKLM64, WerExclusions, '\{#MyAppExeName\}'\) then Exit/);
  assert.match(
    provision,
    /RegWriteDWordValue\(HKLM64, InstallerState, WerExclusionOwner, 1\)[\s\S]+RegWriteDWordValue\(HKLM64, WerExclusions, '\{#MyAppExeName\}', 1\)/,
  );
  const removal = installer.slice(
    installer.indexOf('procedure RemoveOwnedWerExclusion;'),
    installer.indexOf('procedure CurStepChanged'),
  );
  assert.match(removal, /if Owner <> 1 then Exit/);
  assert.match(
    removal,
    /\(Value = 1\) then[\s\S]+RegDeleteValue\(HKLM64, WerExclusions, '\{#MyAppExeName\}'\)/,
  );
  assert.doesNotMatch(removal, /RegDeleteKey\w*\(HKLM64, WerExclusions\)/);
  assert.match(installer, /RemoveLegacyLocalDumps;\s+InstallWerExclusion;/);
  assert.match(installer, /if CurUninstallStep = usPostUninstall then RemoveOwnedWerExclusion/);
});

test('Touch ID uses a nested app and a release profile for its own application identity', () => {
  const team = 'ABCDEFG123';
  const now = new Date('2026-01-02').getTime();
  const applicationID = `${team}.${touchIDBundleIdentifier}`;
  const profile = {
    TeamIdentifier: [team],
    ExpirationDate: new Date('2026-06-01'),
    Entitlements: { 'com.apple.application-identifier': applicationID },
  };
  assert.deepEqual(touchIDEntitlements(profile, team, now), {
    'com.apple.application-identifier': applicationID,
    'com.apple.developer.team-identifier': team,
  });
  for (const invalid of [
    { ...profile, TeamIdentifier: 'xABCDEFG123x' },
    { ...profile, TeamIdentifier: ['ZZZZZZZ000'] },
    { ...profile, ExpirationDate: new Date('2026-01-01') },
    { ...profile, Entitlements: { 'com.apple.application-identifier': `${team}.*` } },
    {
      ...profile,
      Entitlements: { ...profile.Entitlements, 'com.apple.security.get-task-allow': true },
    },
  ])
    assert.throws(() => touchIDEntitlements(invalid, team, now), /authorize/);
  assert.throws(() => touchIDEntitlements(profile, 'bad-team', now), /authorize/);
  assert.equal(packageJson.build.mac.sign, './scripts/sign-macos-with-touch-id.mjs');
  assert.ok(
    packageJson.build.mac.extraFiles.some(({ to }) => to === 'Helpers/Wormhole Vault Touch ID.app'),
  );
  assert.match(releaseWorkflow, /npm run build:touch-id:macos/);
  assert.match(ciWorkflow, /Build the universal Touch ID helper and reject a direct caller/);
});

function readPngDimensions(data) {
  const pngSignature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  assert.deepEqual(data.subarray(0, pngSignature.length), pngSignature);
  assert.equal(data.subarray(12, 16).toString('ascii'), 'IHDR');
  return { width: data.readUInt32BE(16), height: data.readUInt32BE(20) };
}

test(
  'Windows setup replaces a running helper only in the selected installation',
  {
    skip: process.platform !== 'win32',
  },
  async (context) => {
    const compiler = join(process.env['ProgramFiles(x86)'], 'Inno Setup 6', 'ISCC.exe');
    if (!existsSync(compiler)) return context.skip('Inno Setup 6 is required');
    const directory = await mkdtemp(join(tmpdir(), 'wormhole-setup-lock-'));
    const relativeHelper = join('resources', 'app', 'dist-electron', 'wormhole-wgproxy.exe');
    const target = join(directory, 'installed');
    const children = [];
    const waitForExit = async (child) => {
      if (child.exitCode === null && child.signalCode === null) {
        await once(child, 'exit', { signal: AbortSignal.timeout(10_000) });
      }
    };
    const startFixture = async (image, code, args = []) => {
      await mkdir(dirname(image), { recursive: true });
      await copyFile(process.execPath, image);
      const child = spawn(image, ['-e', code, ...args], {
        windowsHide: true,
        stdio: 'ignore',
      });
      children.push(child);
      await once(child, 'spawn');
      return child;
    };
    try {
      // Use the shipping Setup, Files and Code sections. Isolate the identity and
      // omit shortcuts, uninstall registration, WER registry writes and app launches.
      const policy = await readFile(join(projectDir, 'installer', 'Wormhole.Electron.iss'), 'utf8');
      const script = policy
        .replace(/^AppId=.*$/m, 'AppId=WormholeIsolatedSetupTest')
        .replace(
          /^SetupIconFile=.*$/m,
          'PrivilegesRequired=lowest\nUninstallable=no\nUsePreviousAppDir=no',
        )
        .replace(/^\[Icons\][\s\S]*?(?=^\[Code\])/m, '');
      const payload = join(directory, 'payload');
      await mkdir(join(payload, 'resources', 'app', 'dist-electron'), { recursive: true });
      await writeFile(join(payload, relativeHelper), 'new version');
      await writeFile(join(payload, 'Wormhole.exe'), 'new app');
      const fixture = join(directory, 'setup.iss');
      await writeFile(fixture, script);
      const arch = process.arch === 'arm64' ? 'arm64' : 'x64';
      execFileSync(
        compiler,
        [
          '/Q',
          '/DMyAppVersion=1.0.0',
          '/DAppArchitecture=' + arch,
          '/DPublishDir=' + payload,
          '/O' + directory,
          '/Fupgrade',
          fixture,
        ],
        { windowsHide: true },
      );
      const log = join(directory, 'install.log');
      const runUpgrade = async (extraArgs = []) => {
        const install = spawn(
          join(directory, 'upgrade.exe'),
          [
            '/VERYSILENT',
            '/SUPPRESSMSGBOXES',
            '/NORESTART',
            '/DIR=' + target,
            '/LOG=' + log,
            ...extraArgs,
          ],
          { windowsHide: true, stdio: 'ignore', timeout: 120_000 },
        );
        const [code] = await once(install, 'exit');
        if (code !== 0) assert.fail(await readFile(log, 'utf8'));
      };
      const worker = 'setTimeout(() => {}, 180000)';
      const orphan = await startFixture(join(target, relativeHelper), worker);
      const other = await startFixture(join(directory, 'other', relativeHelper), worker);
      const flushed = join(directory, 'session-saved');
      await startFixture(
        join(target, 'Wormhole.exe'),
        `
          const fs = require('node:fs');
          const timer = setInterval(() => {
            if (!fs.existsSync(process.argv[1])) return;
            clearInterval(timer);
            setTimeout(() => fs.writeFileSync(process.argv[2], 'saved'), 1500);
          }, 50);
        `,
        [log, flushed],
      );
      await runUpgrade(['/RESTARTAPP']);
      assert.equal(await readFile(flushed, 'utf8'), 'saved');
      await waitForExit(orphan);
      assert.equal((await stat(join(target, relativeHelper))).size, 'new version'.length);
      assert.equal(await readFile(join(target, relativeHelper), 'utf8'), 'new version');

      // A standalone setup must also replace an abandoned Electron process.
      const abandonedApp = await startFixture(join(target, 'Wormhole.exe'), worker);
      await runUpgrade();
      await waitForExit(abandonedApp);
      assert.equal((await stat(join(target, 'Wormhole.exe'))).size, 'new app'.length);
      assert.equal(
        other.exitCode ?? other.signalCode,
        null,
        'The other installation must keep running',
      );
    } finally {
      await Promise.all(
        children.map(async (child) => {
          if (!child.pid || child.exitCode !== null || child.signalCode !== null) return;
          child.kill();
          await waitForExit(child);
        }),
      );
      await rm(directory, { recursive: true, force: true, maxRetries: 5 });
    }
  },
);

function readIcnsChunks(icon) {
  assert.equal(icon.subarray(0, 4).toString('ascii'), 'icns');
  assert.equal(icon.readUInt32BE(4), icon.length);

  const chunks = new Map();
  let offset = 8;
  while (offset < icon.length) {
    assert.ok(offset + 8 <= icon.length, 'ICNS chunk header is truncated');
    const type = icon.subarray(offset, offset + 4).toString('ascii');
    const size = icon.readUInt32BE(offset + 4);
    assert.ok(size >= 8, `ICNS chunk ${type} has an invalid size`);
    assert.ok(offset + size <= icon.length, `ICNS chunk ${type} is truncated`);
    assert.ok(!chunks.has(type), `ICNS chunk ${type} is duplicated`);
    chunks.set(type, icon.subarray(offset + 8, offset + size));
    offset += size;
  }

  assert.equal(offset, icon.length);
  return chunks;
}

test('dependency lock excludes the Nano ID zero-size generator vulnerability', () => {
  const nanoIdPackages = Object.entries(packageLock.packages)
    .filter(
      ([location]) =>
        location === 'node_modules/nanoid' || location.endsWith('/node_modules/nanoid'),
    )
    .map(([, metadata]) => metadata);

  for (const { version } of nanoIdPackages) {
    assert.ok(
      valid(version) !== null &&
        prerelease(version) === null &&
        !satisfies(version, '<3.3.18 || >=4.0.0 <5.1.6'),
      `nanoid ${version} is vulnerable`,
    );
  }
});

test('dependency lock rejects deprecated packages outside the reviewed Sentry development dependency', () => {
  const deprecated = Object.entries(packageLock.packages)
    .filter(([location, metadata]) => {
      if (!metadata.deprecated) return false;
      // Sentry 10 still requires the v2 API; its v3 replacement is not compatible.
      // This is development-only through react-doctor, and must be reviewed on update.
      if (
        location === 'node_modules/@opentelemetry/sdk-trace-base' &&
        metadata.version === '2.12.0'
      ) {
        assert.equal(metadata.dev, true);
        assert.ok(
          packageLock.packages['node_modules/@sentry/node'].dependencies[
            '@opentelemetry/sdk-trace-base'
          ],
        );
        return false;
      }
      return true;
    })
    .map(([location]) => location);
  assert.deepEqual(deprecated, []);
});

test('Electron downloader initializes the overridden proxy agent', () => {
  const proxy = 'http://127.0.0.1:9';
  const activeProxy = execFileSync(
    process.execPath,
    [
      '-e',
      'const { createRequire } = require("node:module"); ' +
        'createRequire(require.resolve("app-builder-lib"))("@electron/get").initializeProxy(); ' +
        'process.stdout.write(global.GLOBAL_AGENT?.HTTP_PROXY ?? "");',
    ],
    { cwd: projectDir, env: { ...process.env, GLOBAL_AGENT_HTTP_PROXY: proxy }, encoding: 'utf8' },
  );

  assert.equal(activeProxy, proxy);
});

test('Squirrel temporary directory cleanup works with overridden rimraf', () => {
  const temp = require('temp').track();
  const directory = temp.mkdirSync('wormhole-installer-');

  try {
    assert.ok(existsSync(directory));
  } finally {
    temp.cleanupSync();
  }

  assert.equal(existsSync(directory), false);
});

test('Squirrel asynchronous cleanup retains the legacy rimraf callback contract', async () => {
  const temp = require('temp').track();
  const directory = temp.mkdirSync('wormhole-installer-');
  const file = temp.openSync('wormhole-installer-');
  closeSync(file.fd);

  try {
    assert.deepEqual(await temp.cleanup(), { files: 1, dirs: 1 });
    assert.equal(existsSync(directory), false);
    assert.equal(existsSync(file.path), false);
  } finally {
    await Promise.all([
      rm(directory, { recursive: true, force: true }),
      rm(file.path, { force: true }),
    ]);
  }
});

test('legacy rimraf callback supports omitted options and reports deletion errors', async () => {
  const rimraf = require('rimraf');
  const directory = await mkdtemp(join(tmpdir(), 'wormhole-rimraf-'));

  await new Promise((resolve, reject) => {
    rimraf(directory, (error) => (error ? reject(error) : resolve()));
  });
  assert.equal(existsSync(directory), false);

  await assert.rejects(
    new Promise((resolve, reject) => {
      rimraf(42, { maxBusyTries: 6 }, (error) => (error ? reject(error) : resolve()));
    }),
    TypeError,
  );
});

test('electron-builder produces portable and installable Linux packages', () => {
  assert.equal(packageJson.build.artifactName, 'Wormhole-${version}-${os}-${arch}-setup.${ext}');
  assert.equal(packageJson.build.linux.artifactName, 'Wormhole-${version}-${os}-${arch}.${ext}');
  assert.equal(packageJson.build.appImage.artifactName, 'Wormhole-${version}-${arch}.${ext}');
  assert.equal(packageJson.build.toolsets.appimage, '1.0.3');
  assert.equal(packageJson.build.artifactBuildCompleted, './scripts/appimage-update-info.mjs');
  assert.deepEqual(packageJson.build.linux.target, ['AppImage', 'deb', 'rpm']);
  assert.equal(packageJson.build.linux.icon, 'Assets/LinuxIcons');
  assert.ok(packageJson.build.files.includes('!Assets/LinuxIcons/**/*'));
  assert.equal(packageJson.desktopName, 'com.xbounceit.wormhole.desktop');
  assert.equal(packageJson.build.linux.syncDesktopName, true);
  assert.equal(packageJson.build.deb.packageName, 'wormhole');
  assert.equal(packageJson.build.rpm.packageName, 'wormhole');
});

test('Linux packages provide freedesktop icons at standard menu sizes', async () => {
  const canonicalIcon = await readFile(new URL('../Assets/Wormhole.png', import.meta.url));

  for (const size of linuxIconSizes) {
    const icon = await readFile(
      new URL(`../Assets/LinuxIcons/${size}x${size}.png`, import.meta.url),
    );
    assert.deepEqual(readPngDimensions(icon), { width: size, height: size });
    if (size === 1024) assert.deepEqual(icon, canonicalIcon);
  }
});

test('electron-builder resolves every reviewed Linux icon asset', async () => {
  const resolved = await convertIcon({
    sources: [packageJson.build.linux.icon],
    fallbackSources: [],
    roots: [projectDir],
    format: 'set',
    outDir: fileURLToPath(new URL('../release/.icon-test', import.meta.url)),
  });

  assert.equal(resolved.isFallback, false);
  assert.deepEqual(
    resolved.icons.map(({ file, size }) => ({
      file: relative(projectDir, file).replaceAll('\\', '/'),
      size,
    })),
    linuxIconSizes.map((size) => ({ file: `Assets/LinuxIcons/${size}x${size}.png`, size })),
  );
});

test('electron-builder produces the supported macOS installer', () => {
  assert.equal(packageJson.build.mac.target, 'dmg');
  assert.equal(packageJson.build.mac.icon, 'Assets/Wormhole.icns');
  const chunks = readIcnsChunks(macIcon);
  for (const [type, size] of [
    ['ic07', 128],
    ['ic08', 256],
    ['ic09', 512],
    ['ic10', 1024],
    ['ic11', 32],
    ['ic12', 64],
    ['ic13', 256],
    ['ic14', 512],
  ]) {
    assert.ok(chunks.has(type), `macOS icon must include ${type}`);
    assert.deepEqual(readPngDimensions(chunks.get(type)), { width: size, height: size }, type);
  }
});

test('macOS small icons use decodable ARGB instead of PNG chunks that Finder renders as noise', () => {
  // https://github.com/electron-userland/electron-builder-binaries/blob/master/packages/icons/CHANGELOG.md
  // Asset-only fix: validate the committed binary and its original pixels; no runtime code changes.
  const chunks = readIcnsChunks(macIcon);
  for (const type of ['icp4', 'icp5', 'icp6']) {
    assert.ok(!chunks.has(type), `${type} is unsafe for small Finder/DMG icons`);
  }
  // SHA-256 of the original small PNGs decoded into straight A,R,G,B planes.
  for (const [type, size, pixelHash] of [
    ['ic04', 16, '17310795e8ee51de6bbd1ec169614f8de71a48682ac624090e2a11805292f628'],
    ['ic05', 32, '0c9e0b4998201587627e18a59272b645c7018aab0f007235f431c8f612997f0a'],
  ]) {
    const data = chunks.get(type);
    assert.ok(data, `macOS icon must include ${type}`);
    assert.equal(data.toString('ascii', 0, 4), 'ARGB');
    let offset = 4;
    const planes = [];
    for (let channel = 0; channel < 4; channel++) {
      const plane = [];
      while (plane.length < size * size) {
        assert.ok(offset < data.length, `${type} has a truncated channel`);
        const control = data[offset++];
        const count = control < 128 ? control + 1 : control - 125;
        assert.ok(plane.length + count <= size * size, `${type} channel overflows`);
        assert.ok(offset + (control < 128 ? count : 1) <= data.length);
        if (control < 128) {
          plane.push(...data.subarray(offset, offset + count));
          offset += count;
        } else {
          plane.push(...Array(count).fill(data[offset++]));
        }
      }
      planes.push(Buffer.from(plane));
    }
    assert.equal(offset, data.length, `${type} has trailing channel data`);
    assert.equal(
      createHash('sha256').update(Buffer.concat(planes)).digest('hex'),
      pixelHash,
      `${type} must preserve the original colors and alpha`,
    );
  }
});

test('the desktop window uses an icon format supported by the current platform', async () => {
  const electronMain = await readFile(new URL('../electron/main.ts', import.meta.url), 'utf8');
  assert.match(
    electronMain,
    /const applicationIconPath = path\.join\([^;]*process\.platform === 'win32' \? 'Wormhole\.ico' : 'Wormhole\.png'/,
  );
  assert.match(
    electronMain,
    /const window = createApplicationWindow\(\{[^;]*icon: applicationIconPath/,
  );
});

test('native Go binaries are shipped outside the Electron asar archive', () => {
  assert.equal(packageJson.build.asar, true);
  const filters = packageJson.build.extraResources.flatMap((resource) => resource.filter ?? []);
  for (const pattern of [
    'wormhole-backend-*',
    'wormhole-wgproxy*',
    'wormhole-ovpnproxy*',
    'wormhole-fortiproxy*',
    'wormhole-ciscoproxy*',
    'wormhole-sshproxy*',
  ]) {
    assert.ok(filters.includes(pattern), `${pattern} is missing from extraResources`);
  }
});

test('packaged backend resolution uses the universal binary only on macOS', async () => {
  const electronMain = await readFile(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const backendPathBody = electronMain.match(
    /^function backendPath\(\): string \{([\s\S]*?)^\}/m,
  )?.[1];
  assert.ok(backendPathBody, 'backendPath function is missing');
  const resolveBackendPath = new Function(
    'process',
    'findBundledExecutable',
    'recordDiagnostic',
    backendPathBody,
  );

  for (const platform of ['darwin', 'win32', 'linux']) {
    for (const arch of ['x64', 'arm64']) {
      const resolve = (files) =>
        resolveBackendPath(
          { platform, arch },
          (name) => (files.includes(name) ? `/resources/${name}` : undefined),
          () => {},
        );
      const nativeName = `wormhole-backend-${arch}${platform === 'win32' ? '.exe' : ''}`;
      assert.equal(
        resolve([nativeName, 'wormhole-backend-universal']),
        `/resources/${nativeName}`,
        `${platform}/${arch} must prefer its architecture-specific binary`,
      );
      if (platform === 'darwin') {
        assert.equal(
          resolve(['wormhole-backend-universal']),
          '/resources/wormhole-backend-universal',
        );
      } else {
        assert.throws(() => resolve(['wormhole-backend-universal']), /component is missing/);
      }
      assert.throws(() => resolve([]), /component is missing/);
    }
  }
});

test('universal backend builds verify both architectures and set executable permissions', async () => {
  const script = await readFile(
    new URL('../scripts/Build-ElectronUniversalBackend.mjs', import.meta.url),
    'utf8',
  );
  const mergeBody = script.match(/^function mergeUniversalBinary\([^\n]+\) \{([\s\S]*?)^\}/m)?.[1];
  assert.ok(mergeBody, 'universal binary merge function is missing');
  const commands = [];
  const merge = new Function(
    'x64Path',
    'arm64Path',
    'outputPath',
    'assertFileExists',
    'rmSync',
    'run',
    'chmodSync',
    'console',
    mergeBody,
  );
  merge(
    'backend-x64',
    'backend-arm64',
    'backend-universal',
    () => {},
    () => {},
    (command, args) => commands.push([command, ...args]),
    (file, mode) => commands.push(['chmod', file, mode]),
    { log() {} },
  );
  assert.deepEqual(commands, [
    ['lipo', '-create', 'backend-x64', 'backend-arm64', '-output', 'backend-universal'],
    ['lipo', 'backend-universal', '-verify_arch', 'x86_64', 'arm64'],
    ['chmod', 'backend-universal', 0o755],
  ]);
});

test('release Go toolchains satisfy every native module requirement', async () => {
  // Workflow configuration is outside Node/Go coverage; check it against the actual modules.
  const modules = [];
  for await (const modulePath of glob(['tools/**/go.mod', 'vendor/**/go.mod'], {
    cwd: projectDir,
  })) {
    const source = await readFile(join(projectDir, modulePath), 'utf8');
    const version = source.match(/^go (\d+\.\d+(?:\.\d+)?)\s*$/m)?.[1];
    assert.ok(version, `${modulePath} must declare its Go version`);
    modules.push({ modulePath, version: coerce(version).version });
  }
  assert.ok(modules.length > 0, 'native Go modules are missing');

  for (const [job, nativeBuildName] of [
    [releaseJobs.build, 'Build real VPN sidecars'],
    [releaseJobs.packages, 'Build native Go components'],
  ]) {
    const setups = job.steps.filter((step) => step.uses?.startsWith('actions/setup-go@'));
    assert.equal(setups.length, 1, `${job.name} must install exactly one Go toolchain`);
    const [setup] = setups;
    assert.equal(setup.if, undefined, `${job.name} must install Go for every architecture`);
    const nativeBuildIndex = job.steps.findIndex((step) => step.name === nativeBuildName);
    assert.ok(
      nativeBuildIndex > job.steps.indexOf(setup),
      `${job.name} must install Go before ${nativeBuildName}`,
    );
    assert.equal(setup.with['go-version-file'], 'tools/wormhole-backend/go.mod');
    assert.equal(setup.with['go-version'], undefined);
    const source = await readFile(join(projectDir, setup.with['go-version-file']), 'utf8');
    const configuredVersion = coerce(source.match(/^go (\S+)/m)?.[1]).version;
    for (const { modulePath, version } of modules) {
      assert.ok(
        satisfies(configuredVersion, `>=${version}`),
        `${job.name} installs Go ${configuredVersion}, but ${modulePath} requires ${version}`,
      );
    }
  }
});

test('Windows OpenVPN setup checks out the manifest baseline independently of the runner registry', async () => {
  // Workflow configuration is outside Node/Go coverage. Validate the actual action and execute
  // its bootstrap below, including a stale runner registry and a failed bootstrap.
  const manifest = JSON.parse(
    await readFile(
      new URL('../tools/wormhole-ovpnproxy/ovpn_shim/vcpkg.json', import.meta.url),
      'utf8',
    ),
  );
  const [checkout, bootstrap, x64, arm64] = windowsOvpnSetup.runs.steps;
  assert.equal(windowsOvpnSetup.runs.using, 'composite');
  assert.equal(windowsOvpnSetup.inputs.architecture.required, true);
  assert.ok(checkout.uses.startsWith('actions/checkout@'));
  assert.equal(checkout.if, undefined);
  assert.equal(checkout.with.repository, 'microsoft/vcpkg');
  assert.match(checkout.with.ref, /^[a-f0-9]{40}$/);
  assert.equal(checkout.with.ref, manifest['builtin-baseline']);
  assert.equal(checkout.with['fetch-depth'], 0);
  assert.equal(checkout.with['persist-credentials'], false);
  assert.equal(checkout.with.path, 'obj/windows-vcpkg');
  assert.equal(bootstrap.if, undefined);
  assert.equal(bootstrap.shell, 'pwsh');
  assert.ok(bootstrap.run.includes(checkout.with.path));
  assert.equal(x64.if, "inputs.architecture == 'x64'");
  assert.match(x64.run, /choco install mingw/);
  assert.equal(arm64.if, "inputs.architecture == 'arm64'");
  assert.match(arm64.run, /WORMHOLE_OVPN_CMAKE_GENERATOR=Ninja/);
  assert.match(arm64.run, /SHA-256 mismatch/);
  assert.ok(!JSON.stringify(windowsOvpnSetup).includes('VCPKG_INSTALLATION_ROOT'));
  assert.ok(!releaseWorkflow.includes('VCPKG_INSTALLATION_ROOT'));
});

test('Windows release and CI use the same OpenVPN setup before real builds on both architectures', () => {
  const ci = parse(ciWorkflow).jobs['windows-openvpn'];
  for (const [job, nativeBuildName] of [
    [releaseJobs.build, 'Build real VPN sidecars'],
    [ci, 'Build and verify real OpenVPN sidecar'],
  ]) {
    assert.match(job['runs-on'], /^windows-/);
    assert.deepEqual([...job.strategy.matrix.platform].sort(), ['arm64', 'x64']);
    assert.equal(job.strategy['fail-fast'], false);
    const setups = job.steps.filter((step) => step.uses === './.github/actions/setup-windows-ovpn');
    assert.equal(setups.length, 1);
    const [setup] = setups;
    assert.equal(setup.if, undefined);
    assert.equal(setup.with.architecture, '${{ matrix.platform }}');
    const checkoutIndex = job.steps.findIndex((step) => step.uses?.startsWith('actions/checkout@'));
    const setupIndex = job.steps.indexOf(setup);
    const buildIndex = job.steps.findIndex((step) => step.name === nativeBuildName);
    assert.ok(checkoutIndex >= 0 && setupIndex > checkoutIndex && buildIndex > setupIndex);
    assert.equal(job.steps[checkoutIndex].with.submodules, 'recursive');
    assert.match(job.steps[buildIndex].run, /-RequireReal(?:Ovpn)?\b/);
    assert.equal(job.steps[buildIndex].env.PLATFORM, '${{ matrix.platform }}');
  }
  assert.match(ci.steps.at(-1).run, /Fetch-OvpnProxy\.ps1/);
});

for (const exitCode of [0, 17]) {
  test(
    `Windows OpenVPN bootstrap uses the pinned checkout and handles exit ${exitCode}`,
    { skip: process.platform !== 'win32' },
    async () => {
      const workDir = await mkdtemp(join(tmpdir(), 'wormhole ovpn setup-'));
      const vcpkgRoot = join(workDir, 'obj', 'windows-vcpkg');
      const envFile = join(workDir, 'github-env');
      const script = join(workDir, 'bootstrap.ps1');
      try {
        await mkdir(vcpkgRoot, { recursive: true });
        await writeFile(
          join(vcpkgRoot, 'bootstrap-vcpkg.bat'),
          '@echo off\r\n> "%GITHUB_WORKSPACE%\\bootstrap-arguments.txt" echo %*\r\n' +
            'exit /b %WORMHOLE_TEST_BOOTSTRAP_EXIT%\r\n',
        );
        await writeFile(envFile, 'EXISTING=value\n');
        await writeFile(script, windowsOvpnSetup.runs.steps[1].run);
        const result = spawnSync('pwsh', ['-NoProfile', '-File', script], {
          encoding: 'utf8',
          windowsHide: true,
          env: {
            ...process.env,
            GITHUB_WORKSPACE: workDir,
            GITHUB_ENV: envFile,
            VCPKG_ROOT: join(workDir, 'stale-runner-vcpkg'),
            VCPKG_INSTALLATION_ROOT: join(workDir, 'stale-runner-vcpkg'),
            WORMHOLE_TEST_BOOTSTRAP_EXIT: String(exitCode),
          },
        });
        assert.ifError(result.error);
        assert.equal(
          (await readFile(join(workDir, 'bootstrap-arguments.txt'), 'utf8')).trim(),
          '-disableMetrics',
        );
        const publishedEnv = (await readFile(envFile, 'utf8')).replaceAll('\r\n', '\n');
        if (exitCode === 0) {
          assert.equal(result.status, 0, result.stderr);
          assert.equal(publishedEnv, `EXISTING=value\nVCPKG_ROOT=${vcpkgRoot}\n`);
        } else {
          assert.notEqual(result.status, 0);
          assert.match(result.stderr, /vcpkg bootstrap failed with exit 17/);
          assert.equal(publishedEnv, 'EXISTING=value\n');
        }
      } finally {
        await rm(workDir, { recursive: true, force: true });
      }
    },
  );

  test(
    `Windows OpenVPN setup handles MinGW installation exit ${exitCode}`,
    { skip: process.platform !== 'win32' },
    async () => {
      const workDir = await mkdtemp(join(tmpdir(), 'wormhole mingw setup-'));
      try {
        const script = join(workDir, 'install.ps1');
        await writeFile(
          join(workDir, 'choco.cmd'),
          `@echo off\r\n> "%GITHUB_WORKSPACE%\\choco-arguments.txt" echo %*\r\nexit /b ${exitCode}\r\n`,
        );
        await writeFile(script, windowsOvpnSetup.runs.steps[2].run);
        const result = spawnSync('pwsh', ['-NoProfile', '-File', script], {
          encoding: 'utf8',
          windowsHide: true,
          env: {
            ...process.env,
            GITHUB_WORKSPACE: workDir,
            PATH: `${workDir};${process.env.PATH}`,
          },
        });
        assert.ifError(result.error);
        assert.equal(
          (await readFile(join(workDir, 'choco-arguments.txt'), 'utf8')).trim(),
          'install mingw -y --no-progress',
        );
        if (exitCode === 0) {
          assert.equal(result.status, 0, result.stderr);
        } else {
          assert.notEqual(result.status, 0);
          assert.match(result.stderr, /MinGW installation failed with exit 17/);
        }
      } finally {
        await rm(workDir, { recursive: true, force: true });
      }
    },
  );
}

test('release matrices build and upload every supported platform and package format', () => {
  assert.match(releaseJobs.build['runs-on'], /^windows-/);
  assert.equal(releaseJobs.packages['runs-on'], '${{ matrix.runner }}');
  assert.deepEqual([...releaseJobs.build.strategy.matrix.platform].sort(), ['arm64', 'x64']);
  const targets = releaseJobs.packages.strategy.matrix.include.map(
    ({ builder_platform, builder_arch, backend_arch, runner, artifacts, updater_artifact }) => ({
      target: `${builder_platform}/${builder_arch}/${backend_arch}`,
      runnerPlatform: runner.split('-')[0],
      artifacts: artifacts.trim().split(/\s+/).sort(),
      updater: updater_artifact,
    }),
  );
  assert.deepEqual(
    targets.sort((a, b) => a.target.localeCompare(b.target)),
    [
      {
        target: 'linux/arm64/arm64',
        runnerPlatform: 'ubuntu',
        artifacts: [
          'release/*.AppImage',
          'release/*.AppImage.zsync',
          'release/*.deb',
          'release/*.rpm',
        ],
        updater: 'release/Wormhole-*-arm64.AppImage',
      },
      {
        target: 'linux/x64/x64',
        runnerPlatform: 'ubuntu',
        artifacts: [
          'release/*.AppImage',
          'release/*.AppImage.zsync',
          'release/*.deb',
          'release/*.rpm',
        ],
        updater: 'release/Wormhole-*-x86_64.AppImage',
      },
      {
        target: 'mac/universal/universal',
        runnerPlatform: 'macos',
        artifacts: ['release/Wormhole-*-mac-universal-setup.dmg'],
        updater: 'release/Wormhole-*-mac-universal-setup.dmg',
      },
    ],
  );
});

test('release verifies the Linux package outputs and their installed desktop assets', () => {
  const verify = releaseJobs.packages.steps.find((step) =>
    step.run?.includes('dpkg-deb --extract'),
  );
  assert.ok(verify, 'Linux package validation is missing');
  assert.equal(verify.if, "matrix.builder_platform == 'linux'");
  assert.equal(verify.env.LC_ALL, 'C');
  for (const suffix of [
    'x86_64.AppImage',
    'amd64.deb',
    'x86_64.rpm',
    'arm64.AppImage',
    'arm64.deb',
    'aarch64.rpm',
  ]) {
    assert.ok(
      verify.run.includes(
        `release/Wormhole-*-${suffix.endsWith('.AppImage') ? '' : 'linux-'}${suffix}`,
      ),
      `${suffix} must be verified`,
    );
  }
  assert.match(verify.run, /if \[\[ \$\{#matches\[@\]\} -ne 1 \]\]; then[\s\S]*?exit 1/);
  assert.match(verify.run, /usr\/share\/icons\/hicolor\/\$size\/apps\/wormhole\.png/);
  assert.match(verify.run, /PNG image data, \$icon_width x \$icon_height,/);
  assert.match(verify.run, /cmp -s "Assets\/LinuxIcons\/\$size\.png" "\$icon_path"/);
  assert.match(verify.run, /grep -Fxq 'Icon=wormhole' "\$desktop_entry"/);
  assert.match(verify.run, /readelf --program-headers "\$appimage"/);
  assert.match(verify.run, /readelf --dynamic "\$appimage"/);
  assert.match(verify.run, /readelf --string-dump=\.upd_info "\$appimage"/);
  assert.match(verify.run, /sha1sum "\$appimage"/);
  assert.match(verify.run, /grep -aFxq "SHA-1: \$appimage_sha1" "\$appimage\.zsync"/);
  const tooling = releaseJobs.packages.steps.find((step) => step.run?.includes('--yes zsync'));
  assert.equal(tooling?.if, "matrix.builder_platform == 'linux'");
});

function releaseBash() {
  return process.platform === 'win32'
    ? resolve(
        execFileSync('git', ['--exec-path'], { encoding: 'utf8' }).trim(),
        '../../../bin/bash.exe',
      )
    : 'bash';
}

test('release AppImage validation accepts static PIE and rejects external dependencies and inspection errors', async () => {
  // Workflow Bash is outside the Node/Go coverage tooling. Execute its actual validation
  // with both architectures, covering static PIE, external dependencies and command failures.
  const verify = releaseJobs.packages.steps.find((step) =>
    step.run?.includes('dpkg-deb --extract'),
  );
  const source = verify.run.slice(
    verify.run.indexOf('appimages=('),
    verify.run.indexOf('deb_packages=('),
  );
  const script = `set -euo pipefail
shopt -s nullglob
readelf() {
  if [[ "$1" == '--program-headers' ]]; then
    printf '%s\\n' "$MOCK_PROGRAM_HEADERS"
    return "$MOCK_PROGRAM_STATUS"
  fi
  if [[ "$1" == '--dynamic' ]]; then
    printf '%s\\n' "$MOCK_DYNAMIC_ENTRIES"
    return "$MOCK_DYNAMIC_STATUS"
  fi
  printf '%s\\n' "gh-releases-zsync|xBounceIT|wormhole|latest|Wormhole-*-$MOCK_ARCH.AppImage.zsync"
  return "$MOCK_SECTION_STATUS"
}
${source}`;
  const bash = releaseBash();
  const directory = await mkdtemp(join(tmpdir(), 'wormhole-release-appimage-'));
  const content = Buffer.from('AppImage fixture');
  const sha1 = createHash('sha1').update(content).digest('hex');
  try {
    await mkdir(join(directory, 'release'));
    for (const arch of ['x86_64', 'arm64']) {
      const image = join(directory, 'release', `Wormhole-2.1.0-${arch}.AppImage`);
      await writeFile(image, content);
      for (const {
        headers = 'LOAD',
        programStatus = '0',
        dynamicEntries = 'There is no dynamic section in this file.',
        dynamicStatus = '0',
        sectionStatus = '0',
        sidecar = `SHA-1: ${sha1}\n`,
        success,
      } of [
        { success: true },
        {
          headers: 'LOAD\nDYNAMIC',
          dynamicEntries: '0x0000000000000007 (RELA) 0x1200\n0x0000000000000000 (NULL) 0x0',
          success: true,
        },
        { programStatus: '9', success: false },
        { headers: '  INTERP 0x000040 0x0000000000000040', success: false },
        {
          headers: 'LOAD\nDYNAMIC',
          dynamicEntries: '0x0000000000000001 (NEEDED) Shared library: [libfuse.so.2]',
          success: false,
        },
        { dynamicStatus: '9', success: false },
        { sectionStatus: '9', success: false },
        { sidecar: 'SHA-1: wrong\n', success: false },
        { sidecar: '', success: false },
      ]) {
        await writeFile(`${image}.zsync`, sidecar);
        const result = spawnSync(bash, ['-c', script], {
          cwd: directory,
          env: {
            ...process.env,
            LC_ALL: verify.env.LC_ALL,
            MOCK_PROGRAM_HEADERS: headers,
            MOCK_PROGRAM_STATUS: programStatus,
            MOCK_DYNAMIC_ENTRIES: dynamicEntries,
            MOCK_DYNAMIC_STATUS: dynamicStatus,
            MOCK_ARCH: arch,
            MOCK_SECTION_STATUS: sectionStatus,
          },
          encoding: 'utf8',
        });
        assert.ifError(result.error);
        assert.equal(
          result.status === 0,
          success,
          `${arch}/${headers}/${programStatus}/${dynamicStatus}/${sectionStatus}: ${result.stderr}`,
        );
      }
      await rm(image);
      await rm(`${image}.zsync`);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('macOS release prepares private notarization credentials and verifies only accepted disk images', async () => {
  const steps = releaseJobs.packages.steps;
  const prepare = steps
    .find((step) => step.id === 'mac-notary')
    .run.replace('/usr/bin/expect', 'mock_expect');
  const notarize = steps
    .find((step) => step.name === 'Notarize and verify the signed macOS disk image')
    .run.replaceAll('/usr/bin/xcrun', 'mock_xcrun');
  const mock = `
    export GITHUB_WORKSPACE="$PWD"
    mock_expect() { [[ "$#" -eq 0 ]] && cat >/dev/null; }
    mock_xcrun() {
      printf '%s %s\n' "$1" "$2" >> calls.txt
      if [[ "$1" == notarytool ]]; then
        [[ "$4" == --keychain-profile && "$5" == 'release profile' && "$6" == --keychain ]] || return 1
        printf '{"status":"%s"}\n' "$MOCK_NOTARY_STATUS"
      fi
    }
    go() { printf 'verify %s\n' "$*" >> calls.txt; }
  `;
  const directory = await mkdtemp(join(tmpdir(), 'wormhole-macos-notarization-'));
  const bash = releaseBash();
  const run = (script, env = {}) => {
    const result = spawnSync(bash, ['-s'], {
      cwd: directory,
      encoding: 'utf8',
      input: `${mock}\n${script}`,
      env: {
        ...process.env,
        GITHUB_OUTPUT: 'outputs.txt',
        GITHUB_RUN_ID: '10',
        GITHUB_RUN_ATTEMPT: '4',
        MACOS_PUBLISHER: 'AB7CDEFGH9',
        NOTARY_PROFILE: '',
        NOTARY_KEYCHAIN: './test.keychain-db',
        APPLE_ID: '',
        APPLE_APP_SPECIFIC_PASSWORD: '',
        APPLE_KEYCHAIN_PROFILE: 'release profile',
        APPLE_KEYCHAIN: './test.keychain-db',
        MOCK_NOTARY_STATUS: 'Accepted',
        ...env,
      },
    });
    assert.ifError(result.error);
    return result;
  };
  try {
    await mkdir(join(directory, 'release'));
    await writeFile(
      join(directory, 'release', 'Wormhole-9.8.7-mac-universal-setup.dmg'),
      'disk image fixture',
    );
    await writeFile(join(directory, 'test.keychain-db'), 'keychain fixture');
    assert.equal(run(prepare, { NOTARY_PROFILE: 'existing profile' }).status, 0);
    assert.match(
      await readFile(join(directory, 'outputs.txt'), 'utf8'),
      /^profile=existing profile$/m,
    );
    assert.equal(run(prepare, { NOTARY_PROFILE: 'profile\noutput=invalid' }).status, 1);
    assert.equal(run(prepare).status, 1);
    const credentials = run(prepare, {
      APPLE_ID: 'fixture@example.invalid',
      APPLE_APP_SPECIFIC_PASSWORD: 'mock-password',
    });
    assert.equal(credentials.status, 0, credentials.stderr);
    assert.doesNotMatch(credentials.stdout + credentials.stderr, /mock-password/);
    assert.match(
      await readFile(join(directory, 'outputs.txt'), 'utf8'),
      /^profile=wormhole-release-10-4$/m,
    );
    assert.equal(run(notarize, { MOCK_NOTARY_STATUS: 'Invalid' }).status, 1);
    const calls = join(directory, 'calls.txt');
    assert.equal((await readFile(calls, 'utf8')).trim(), 'notarytool submit');
    await writeFile(calls, '');
    const accepted = run(notarize);
    assert.equal(accepted.status, 0, accepted.stderr);
    assert.match(
      await readFile(calls, 'utf8'),
      /^notarytool submit\r?\nstapler staple\r?\nstapler validate\r?\nverify -C tools\/wormhole-backend run .\/cmd\/verify-update-publisher AB7CDEFGH9 /,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('release packages generate and upload the installer checksums required by the updater', () => {
  const checksum = releaseJobs.packages.steps.find((step) => step.run?.includes('Get-FileHash'));
  assert.ok(checksum, 'installer checksum generation is missing');
  assert.match(checksum.run, /Get-ChildItem "\$\{\{ matrix\.updater_artifact \}\}" -File/);
  assert.match(checksum.run, /if \(\$installers\.Count -ne 1\)\s*\{\s*throw /);
  assert.match(checksum.run, /Get-FileHash -Algorithm SHA256 -LiteralPath \$_\.FullName/);
  assert.match(
    checksum.run,
    /"\$hash  \$\(\$_\.Name\)" \| Set-Content -LiteralPath "\$\(\$_\.FullName\)\.sha256" -Encoding ascii/,
  );
  const uploadSteps = releaseJobs.packages.steps.filter(
    (step) =>
      step.uses?.startsWith('actions/upload-artifact@') &&
      step.with.name === 'wormhole-${{ matrix.platform }}',
  );
  assert.equal(uploadSteps.length, 1, 'expected one release package upload step');
  const paths = uploadSteps[0].with.path.split(/\r?\n/).map((line) => line.trim());
  assert.ok(paths.includes('${{ matrix.artifacts }}'), 'release installers must be uploaded');
  assert.ok(
    paths.includes('${{ matrix.updater_artifact }}.sha256'),
    'each updater installer must be uploaded with its SHA-256 sidecar',
  );
});

test('release resolves the version from a stable tag regardless of the checked-in version', async () => {
  assert.deepEqual(releaseConfig.on.push.tags, ['v*']);
  assert.equal(releaseConfig.on.workflow_dispatch, null);
  assert.equal(releaseJobs.checks.if, "github.ref_type == 'tag' && !github.event.deleted");
  const tagCheck = releaseJobs.checks.steps.find((step) => step.id === 'release');
  assert.equal(tagCheck?.env.RELEASE_TAG, '${{ github.ref_name }}');
  assert.equal(tagCheck.shell, 'bash');
  const otherVersion = packageJson.version === '8.12.34' ? '9.12.34' : '8.12.34';
  const workDir = await mkdtemp(join(tmpdir(), 'wormhole-release-version-'));
  const output = join(workDir, 'github-output');
  try {
    for (const [tag, version] of [
      [`v${otherVersion}`, otherVersion],
      [`v${packageJson.version}`, packageJson.version],
      ['v0.0.0', '0.0.0'],
      ['v65535.65535.65535', '65535.65535.65535'],
      ['', null],
      ['8.12.34', null],
      ['v8.12', null],
      ['v08.12.34', null],
      ['v٨.12.34', null],
      ['v8.12.34-rc.1', null],
      ['v65536.12.34', null],
      ['v8.65536.34', null],
      ['v8.12.65536', null],
      ['v18446744073709551616.12.34', null],
      ['v8.12.34\nversion=9.9.9', null],
    ]) {
      await writeFile(output, '');
      const result = spawnSync(bash, ['-e', '-c', tagCheck.run], {
        cwd: workDir,
        encoding: 'utf8',
        env: { ...process.env, ...tagCheck.env, RELEASE_TAG: tag, GITHUB_OUTPUT: output },
      });
      assert.ifError(result.error);
      assert.equal(result.status, version === null ? 1 : 0, `${tag}: ${result.stderr}`);
      assert.equal(
        await readFile(output, 'utf8'),
        version === null ? '' : `tag=${tag}\nversion=${version}\n`,
      );
      if (version === null) assert.match(result.stderr, /Release tag must have the form vX\.Y\.Z/);
    }
  } finally {
    await rm(workDir, { recursive: true, force: true });
  }
});

test('all release builds use the tagged commit and embed the resolved version', () => {
  const { checks, build, packages } = releaseJobs;
  assert.deepEqual(checks.outputs, {
    tag: '${{ steps.release.outputs.tag }}',
    version: '${{ steps.release.outputs.version }}',
    'update-manifest-public-key': '${{ steps.update-key.outputs.public-key }}',
    'windows-publisher-spki': '${{ steps.update-key.outputs.windows-publisher-spki }}',
    'macos-publisher-team': '${{ steps.update-key.outputs.macos-publisher-team }}',
  });
  const checkout = (job) => job.steps.find((step) => step.uses?.startsWith('actions/checkout@'));
  for (const job of [build, packages]) {
    assert.equal(job.needs, 'checks');
    assert.equal(checkout(job).with?.ref, undefined);
  }

  const version = '${{ needs.checks.outputs.version }}';
  const installer = build.steps.find((step) => step.run?.includes('Build-ElectronInstaller.ps1'));
  assert.equal(installer?.env.VERSION, version);
  assert.match(installer.run, /-AppVersion \$env:VERSION/);
  const zip = build.steps.find((step) => step.run?.includes('Compress-Archive'));
  assert.equal(zip?.env.VERSION, version);
  assert.match(zip.run, /Wormhole-\$env:VERSION-win-\$env:PLATFORM\.zip/);
  const packageBuild = packages.steps.find((step) => step.run?.startsWith('npm run package --'));
  assert.equal(packageBuild?.env.RELEASE_VERSION, version);
  assert.ok(packageBuild.run.includes('--config.extraMetadata.version="$RELEASE_VERSION"'));
});

test('electron-builder writes the release version into the packaged app manifest', async (t) => {
  const { extractFile } = await import('@electron/asar');
  const workDir = await mkdtemp(join(tmpdir(), 'wormhole-release-asar-'));
  t.after(() => rm(workDir, { recursive: true, force: true }));
  const manifestPath = join(workDir, 'package.json');
  const manifest = {
    name: 'wormhole-release-fixture',
    version: '1.0.0',
    description: 'Release version fixture',
    author: 'Wormhole',
    main: 'index.js',
    build: {
      electronVersion: require('electron/package.json').version,
      electronDist: 'runtime',
      npmRebuild: false,
      files: ['index.js'],
    },
  };
  await mkdir(join(workDir, 'runtime'));
  await writeFile(join(workDir, 'runtime', 'electron'), 'Electron runtime fixture');
  await writeFile(join(workDir, 'index.js'), 'module.exports = {};\n');
  await writeFile(manifestPath, JSON.stringify(manifest));

  const version = '8.12.34';
  execFileSync(
    process.execPath,
    [
      require.resolve('electron-builder/cli.js'),
      '--linux',
      '--x64',
      '--dir',
      '--publish',
      'never',
      `--config.extraMetadata.version=${version}`,
    ],
    { cwd: workDir, timeout: 30_000 },
  );

  const archive = join(workDir, 'dist', 'linux-unpacked', 'resources', 'app.asar');
  assert.equal(JSON.parse(extractFile(archive, 'package.json')).version, version);
  assert.equal(JSON.parse(await readFile(manifestPath, 'utf8')).version, manifest.version);
});

test('backend builds pin the release key and reject malformed keys before replacing the binary', async () => {
  const source = await readFile(
    new URL('../scripts/Build-ElectronBackend.mjs', import.meta.url),
    'utf8',
  );
  const start = source.indexOf('const cgoEnabled');
  const end = source.indexOf('// The VPN implementations', start);
  assert.ok(start >= 0 && end > start);
  const build = new Function(
    'backendGoToolchain',
    'goos',
    'process',
    'stage',
    'spawnSync',
    `
    const goarch = 'amd64', architecture = 'x64';
    const stagingDir = 'dist-electron', binaryPath = 'backend.exe', sourceDir = 'source';
    const mkdirSync = stage, rmSync = stage, console = { log() {} };
    ${source.slice(start, end)}
  `,
  ).bind(null, backendGoToolchain);
  const pin = 'f2'.repeat(32);
  const publisher = '3d'.repeat(32);
  for (const [key, spki, ldflags] of [
    ['', '', '-s -w'],
    [pin, '', `-s -w -X main.updateManifestPublicKeyHex=${pin}`],
    [
      pin,
      publisher,
      `-s -w -X main.updateManifestPublicKeyHex=${pin} -X main.updateWindowsPublisherSPKI=${publisher}`,
    ],
  ]) {
    const mutations = [];
    const spawns = [];
    build(
      'windows',
      { env: { WORMHOLE_UPDATE_MANIFEST_PUBLIC_KEY: key, WORMHOLE_WINDOWS_PUBLISHER_SPKI: spki } },
      (...args) => mutations.push(args),
      (...args) => {
        spawns.push(args);
        return { status: 0 };
      },
    );
    assert.equal(mutations.length, 2);
    assert.equal(spawns.length, 1);
    assert.equal(spawns[0][0], 'go');
    assert.equal(spawns[0][2].env.GOTOOLCHAIN, backendGoToolchain());
    assert.equal(spawns[0][1][spawns[0][1].indexOf('-ldflags') + 1], ldflags);
  }
  for (const key of [
    pin.toUpperCase(),
    '0'.repeat(64),
    pin + '\n',
    'x'.repeat(64),
    pin.slice(0, -1),
  ]) {
    assert.throws(
      () =>
        build(
          'windows',
          { env: { WORMHOLE_UPDATE_MANIFEST_PUBLIC_KEY: key } },
          assert.fail,
          assert.fail,
        ),
      /Invalid WORMHOLE_UPDATE_MANIFEST_PUBLIC_KEY/,
    );
  }
  for (const [key, spki] of [
    ['', publisher],
    [pin, publisher.toUpperCase()],
    [pin, '0'.repeat(64)],
    [pin, publisher + '\n'],
    [pin, 'z'.repeat(64)],
  ]) {
    assert.throws(
      () =>
        build(
          'windows',
          {
            env: {
              WORMHOLE_UPDATE_MANIFEST_PUBLIC_KEY: key,
              WORMHOLE_WINDOWS_PUBLISHER_SPKI: spki,
            },
          },
          assert.fail,
          assert.fail,
        ),
      /Invalid WORMHOLE_WINDOWS_PUBLISHER_SPKI/,
    );
  }
  const team = 'AB7CDEFGH9';
  build(
    'darwin',
    { env: { WORMHOLE_UPDATE_MANIFEST_PUBLIC_KEY: pin, WORMHOLE_MACOS_PUBLISHER_TEAM_ID: team } },
    () => {},
    (_command, args) => {
      assert.equal(
        args[args.indexOf('-ldflags') + 1],
        `-s -w -X main.updateManifestPublicKeyHex=${pin} -X main.updateDarwinPublisherTeamID=${team}`,
      );
      return { status: 0 };
    },
  );
  for (const [key, value] of [
    ['', team],
    [pin, team.toLowerCase()],
    [pin, '0000000000'],
    [pin, `${team}\n`],
    [pin, `A" or true`],
  ]) {
    assert.throws(
      () =>
        build(
          'darwin',
          {
            env: {
              WORMHOLE_UPDATE_MANIFEST_PUBLIC_KEY: key,
              WORMHOLE_MACOS_PUBLISHER_TEAM_ID: value,
            },
          },
          assert.fail,
          assert.fail,
        ),
      /Invalid WORMHOLE_MACOS_PUBLISHER_TEAM_ID/,
    );
  }
});

test('release publication waits for every build and publishes the downloaded assets', () => {
  assert.equal(releaseConfig.permissions.contents, 'read');
  assert.match(packageJson.scripts.package, /--publish never(?:\s|$)/);
  assert.equal(releaseConfig.concurrency.group, 'release-${{ github.ref_name }}');
  assert.equal(releaseConfig.concurrency['cancel-in-progress'], false);
  assert.equal(releaseJobs.build.needs, 'checks');
  assert.equal(releaseJobs.packages.needs, 'checks');
  const pin = '${{ needs.checks.outputs.update-manifest-public-key }}';
  assert.equal(
    releaseJobs.checks.outputs['update-manifest-public-key'],
    '${{ steps.update-key.outputs.public-key }}',
  );
  const pinCheck = releaseJobs.checks.steps.find((step) => step.id === 'update-key');
  assert.equal(pinCheck.env.PUBLIC_KEY, '${{ vars.WORMHOLE_UPDATE_MANIFEST_PUBLIC_KEY }}');
  assert.equal(pinCheck.env.WINDOWS_PUBLISHER, '${{ vars.WORMHOLE_WINDOWS_PUBLISHER_SPKI }}');
  assert.equal(pinCheck.env.MACOS_PUBLISHER, '${{ vars.WORMHOLE_MACOS_PUBLISHER_TEAM_ID }}');
  assert.match(pinCheck.run, /exit 1[\s\S]+GITHUB_OUTPUT/);
  for (const [job, name] of [
    [releaseJobs.build, 'Build Go backend for ${{ matrix.platform }}'],
    [releaseJobs.packages, 'Build native Go components'],
    [releaseJobs.packages, 'Build universal macOS Go components'],
  ]) {
    assert.equal(
      job.steps.find((step) => step.name === name)?.env.WORMHOLE_UPDATE_MANIFEST_PUBLIC_KEY,
      pin,
    );
  }
  const windowsPublisher = '${{ needs.checks.outputs.windows-publisher-spki }}';
  assert.equal(
    releaseJobs.checks.outputs['windows-publisher-spki'],
    '${{ steps.update-key.outputs.windows-publisher-spki }}',
  );
  const windowsBackend = releaseJobs.build.steps.find((step) =>
    step.name?.startsWith('Build Go backend for'),
  );
  assert.equal(windowsBackend.env.WORMHOLE_WINDOWS_PUBLISHER_SPKI, windowsPublisher);
  const finalize = releaseJobs['windows-installers'];
  assert.deepEqual(finalize.needs, ['checks', 'build']);
  assert.deepEqual(finalize.strategy.matrix.platform, releaseJobs.build.strategy.matrix.platform);
  const steps = finalize.steps;
  const verifyPublisher = steps.find((step) => step.name === 'Verify Windows installer publisher');
  assert.equal(verifyPublisher?.env.WINDOWS_PUBLISHER, windowsPublisher);
  assert.match(
    verifyPublisher.run,
    /go run \.\/cmd\/verify-update-publisher \$env:WINDOWS_PUBLISHER \$env:INSTALLER/,
  );
  assert.ok(
    steps.indexOf(verifyPublisher) >
      steps.findIndex((step) => step.name === 'Sign Windows installer'),
  );
  assert.ok(
    steps.indexOf(verifyPublisher) <
      steps.findIndex((step) => step.name === 'Generate SHA-256 sidecar'),
  );
  const macPublisher = '${{ needs.checks.outputs.macos-publisher-team }}';
  assert.equal(
    releaseJobs.checks.outputs['macos-publisher-team'],
    '${{ steps.update-key.outputs.macos-publisher-team }}',
  );
  const macSteps = releaseJobs.packages.steps;
  const macBackend = macSteps.find((step) => step.name === 'Build universal macOS Go components');
  const macPackaging = macSteps.find((step) => step.name === 'Build macOS packages');
  const macCredentials = macSteps.find((step) => step.id === 'mac-notary');
  const macNotary = macSteps.find(
    (step) => step.name === 'Notarize and verify the signed macOS disk image',
  );
  assert.equal(macBackend.env.WORMHOLE_MACOS_PUBLISHER_TEAM_ID, macPublisher);
  assert.equal(macPackaging.env.MACOS_PUBLISHER, macPublisher);
  assert.equal(macNotary.env.MACOS_PUBLISHER, macPublisher);
  assert.equal(macCredentials?.env.NOTARY_PROFILE, '${{ vars.WORMHOLE_MACOS_NOTARY_PROFILE }}');
  assert.equal(macPackaging.env.APPLE_KEYCHAIN_PROFILE, '${{ steps.mac-notary.outputs.profile }}');
  assert.equal(macNotary.env.APPLE_KEYCHAIN_PROFILE, '${{ steps.mac-notary.outputs.profile }}');
  assert.equal(macNotary.env.APPLE_KEYCHAIN, '${{ steps.mac-notary.outputs.keychain }}');
  assert.match(
    macCredentials.run,
    /log_user 0[\s\S]+unset env\(APPLE_APP_SPECIFIC_PASSWORD\)[\s\S]+spawn -noecho[^\n]+notarytool store-credentials[\s\S]+send -- "\$password\\r"/,
  );
  assert.doesNotMatch(macCredentials.run, /notarytool store-credentials[^\n]+--password/);
  assert.match(
    macPackaging.run,
    /unset APPLE_ID APPLE_APP_SPECIFIC_PASSWORD[\s\S]*--config\.dmg\.sign=true/,
  );
  assert.match(
    macNotary.run,
    /credentials=\(--keychain-profile[^\n]+[\s\S]+notarytool submit[^\n]+--wait[\s\S]+status !== "Accepted"[\s\S]+stapler staple[\s\S]+stapler validate[\s\S]+go -C tools\/wormhole-backend run .\/cmd\/verify-update-publisher/,
  );
  assert.ok(macSteps.indexOf(macNotary) > macSteps.indexOf(macPackaging));
  assert.ok(
    macSteps.indexOf(macNotary) <
      macSteps.findIndex((step) => step.name === 'Generate installer SHA-256 sidecar'),
  );
  const sign = releaseJobs.sign;
  assert.deepEqual([...sign.needs].sort(), ['checks', 'packages', 'windows-installers']);
  assert.equal(sign.permissions, undefined);
  const signStep = sign.steps.find((step) => step.env?.WORMHOLE_UPDATE_MANIFEST_SEED);
  assert.equal(signStep.env.PUBLIC_KEY, pin);
  assert.match(
    signStep.run,
    /printf[^\n]+WORMHOLE_UPDATE_MANIFEST_SEED[^\n]+\|\n\s+env -u WORMHOLE_UPDATE_MANIFEST_SEED/,
  );
  assert.deepEqual(sign.steps.at(-1).with.path.trim().split(/\r?\n/), [
    'dist/Wormhole-UpdateManifest-v1.json',
    'dist/Wormhole-UpdateManifest-v2.json',
  ]);

  const release = releaseJobs.release;
  assert.deepEqual(release.needs, ['checks', 'sign']);
  assert.equal(release.permissions.contents, 'write');
  const download = release.steps.find((step) =>
    step.uses?.startsWith('actions/download-artifact@'),
  );
  assert.equal(download?.with.path, 'dist');
  assert.equal(download.with['merge-multiple'], true);
  const publish = release.steps.find((step) => step.run?.includes('gh release create'));
  assert.ok(publish, 'release publication step is missing');
  assert.equal(publish.env.RELEASE_TAG, '${{ needs.checks.outputs.tag }}');
  assert.equal(publish.env.RELEASE_COMMIT, '${{ github.sha }}');
  assert.match(publish.run, /gh release create[\s\S]*?dist\/\*/);
  assert.match(publish.run, /test -s dist\/Wormhole-UpdateManifest-v1\.json/);
  assert.match(publish.run, /test -s dist\/Wormhole-UpdateManifest-v2\.json/);
  assert.match(publish.run, /gh release create[\s\S]*?--draft[\s\S]*?dist\/\*/);
  assert.match(publish.run, /for asset in dist\/\*/);
  assert.match(
    publish.run,
    /\[\[ "\$is_draft" == "true" \]\]\n\s+gh release upload "\$RELEASE_TAG" dist\/\*/,
  );
  assert.match(publish.run, /gh release edit[\s\S]*?--draft=false/);
});

test('publication keeps packages in a draft until the tag still resolves to the build commit', async (t) => {
  const publish = releaseJobs.release.steps.find((step) => step.run?.includes('gh release create'));
  const workDir = await mkdtemp(join(tmpdir(), 'wormhole-release-publish-'));
  t.after(() => rm(workDir, { recursive: true, force: true }));
  await mkdir(join(workDir, 'dist'));
  const assets = [
    'Wormhole-8.12.34.AppImage',
    ...['darwin-universal', 'linux-arm64', 'linux-x64', 'windows-arm64', 'windows-x64'].map(
      (target) => 'Wormhole-InstallationProof-v1-' + target + '.json',
    ),
    'Wormhole-UpdateManifest-v1.json',
    'Wormhole-UpdateManifest-v2.json',
  ];
  await Promise.all(assets.map((asset) => writeFile(join(workDir, 'dist', asset), 'fixture')));
  const uploadFiles = assets.map((asset) => 'dist/' + asset).join(' ');

  const commit = 'a'.repeat(40);
  const movedCommit = 'b'.repeat(40);
  const resolveTag =
    'api repos/example/wormhole/commits/refs/tags/v8.12.34 --header Accept: application/vnd.github.sha';
  const view = 'release view v8.12.34 --repo example/wormhole --json isDraft,assets';
  const create =
    'release create v8.12.34 --repo example/wormhole --verify-tag --draft --generate-notes ' +
    uploadFiles;
  const upload = 'release upload v8.12.34 ' + uploadFiles + ' --repo example/wormhole --clobber';
  const edit = 'release edit v8.12.34 --repo example/wormhole --verify-tag --draft=false';

  const fakeCli = `
gh() {
  printf '%s\\n' "$*" >> commands
  case "$1 $2" in
    'release view')
      [[ "$RESUME_DRAFT" == yes ]] || return 1
      printf '%s\\n' '{"isDraft":true,"assets":[{"name":"Wormhole-8.12.34.AppImage"}]}'
      ;;
    'release create'|'release upload') touch uploaded ;;
    'release edit') return 0 ;;
    'api '*)
      local remote_commit="$TAG_BEFORE_UPLOAD"
      if [[ -f uploaded ]]; then remote_commit="$TAG_AFTER_UPLOAD"; fi
      if [[ -z "$remote_commit" ]]; then
        echo "Tag reference could not be resolved." >&2
        return 1
      fi
      printf '%s\\n' "$remote_commit"
      ;;
    *) return 2 ;;
  esac
}
jq() {
  case "$2" in
    '.isDraft') echo true ;;
    '.assets[].name') echo Wormhole-8.12.34.AppImage ;;
    *) return 2 ;;
  esac
}
`;
  for (const { before, after, resumeDraft, expected, error } of [
    { before: commit, after: commit, expected: [resolveTag, view, create, resolveTag, edit] },
    {
      before: commit,
      after: commit,
      resumeDraft: true,
      expected: [resolveTag, view, upload, resolveTag, edit],
    },
    { before: movedCommit, expected: [resolveTag], error: /no longer points/ },
    { before: '', expected: [resolveTag], error: /could not be resolved/ },
    {
      before: commit,
      after: movedCommit,
      expected: [resolveTag, view, create, resolveTag],
      error: /no longer points/,
    },
    {
      before: commit,
      after: '',
      expected: [resolveTag, view, create, resolveTag],
      error: /could not be resolved/,
    },
  ]) {
    await rm(join(workDir, 'uploaded'), { force: true });
    await writeFile(join(workDir, 'commands'), '');
    const result = spawnSync(bash, ['-c', fakeCli + publish.run], {
      cwd: workDir,
      encoding: 'utf8',
      env: {
        ...process.env,
        RELEASE_TAG: 'v8.12.34',
        RELEASE_COMMIT: commit,
        REPOSITORY: 'example/wormhole',
        TAG_BEFORE_UPLOAD: before,
        TAG_AFTER_UPLOAD: after ?? '',
        RESUME_DRAFT: resumeDraft ? 'yes' : 'no',
      },
    });
    assert.ifError(result.error);
    assert.equal(result.status, error ? 1 : 0, result.stderr);
    if (error) assert.match(result.stderr, error);
    assert.equal(await readFile(join(workDir, 'commands'), 'utf8'), expected.join('\n') + '\n');
  }
});

test('only finalized Windows installers reach release signing and publication', () => {
  const build = releaseJobs.build.steps;
  const steps = releaseJobs['windows-installers'].steps;
  const input = build.find((step) => step.name === 'Upload installer for finalization');
  const download = steps.find((step) => step.name === 'Download Windows installer');
  const output = steps.at(-1);
  assert.equal(download.with.name, input.with.name);
  assert.doesNotMatch(input.with.name, /^wormhole-/);
  for (const step of build.filter((s) => s.with?.name?.startsWith('wormhole-'))) {
    assert.doesNotMatch(step.with.path, /setup\.exe|sha256|\n/);
    assert.match(step.with.path, /\.zip$/);
  }
  assert.match(output.with.name, /^wormhole-/);
  assert.deepEqual(output.with.path.trim().split(/\r?\n/), [
    '${{ steps.installer.outputs.path }}',
    '${{ steps.installer.outputs.path }}.sha256',
  ]);
  const installTool = steps.find((step) => step.name === 'Download pinned Authenticode tool');
  const sign = steps.find((step) => step.name === 'Sign Windows installer');
  const verify = steps.find((step) => step.name === 'Verify Windows installer publisher');
  assert.ok(steps.indexOf(installTool) < steps.indexOf(sign));
  for (const step of [installTool, sign, verify]) {
    assert.equal(step.if, "needs.checks.outputs.windows-publisher-spki != ''");
  }
  assert.match(installTool.run, /releases\/download\/v7\.0\.1\/AzureSignTool-x64\.exe/);
  assert.match(installTool.run, /DC85A3F24BCD5978C63FCFD167A9B41313AF9116722B99B831400F05F387FCBA/);
  assert.deepEqual(
    Object.values(releaseJobs).flatMap((job) =>
      job.steps.filter((step) => step.env?.AZURE_CLIENT_SECRET),
    ),
    [sign],
  );
  assert.equal(
    sign.env.AZURE_CLIENT_SECRET,
    '${{ secrets.WORMHOLE_WINDOWS_SIGNING_CLIENT_SECRET }}',
  );
  assert.equal(verify.env.INSTALLER, sign.env.INSTALLER);
});

test(
  'Windows publisher workflow signs the selected installer and hashes the final bytes',
  {
    skip: process.platform !== 'win32',
  },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'wormhole authenticode-'));
    const steps = releaseJobs['windows-installers'].steps;
    const run = (name, overrides = {}, prefix = '') => {
      const body = steps.find((step) => step.name === name).run;
      const result = spawnSync('pwsh', ['-NoProfile', '-Command', prefix + body], {
        encoding: 'utf8',
        windowsHide: true,
        env: { ...process.env, RUNNER_TEMP: directory, ...overrides },
      });
      assert.ifError(result.error);
      return result;
    };
    try {
      const name = 'Wormhole-2.4.3-win-arm64-setup.exe';
      const staging = join(directory, 'windows-installer');
      const installer = join(staging, name);
      const output = join(directory, 'github-output');
      const selection = { RELEASE_TAG: 'v2.4.3', PLATFORM: 'arm64', GITHUB_OUTPUT: output };
      await mkdir(staging);
      assert.notEqual(run('Select installer', selection).status, 0);
      await writeFile(installer, 'unsigned');
      assert.equal(run('Select installer', selection).status, 0);
      assert.equal((await readFile(output, 'utf8')).trim(), 'path=' + installer);

      const mismatch = run(
        'Download pinned Authenticode tool',
        {},
        'function Invoke-WebRequest($Uri, $OutFile) { [IO.File]::WriteAllText($OutFile, "unexpected") }\n',
      );
      assert.notEqual(mismatch.status, 0);
      assert.match(mismatch.stderr, /Unexpected Authenticode tool digest/);

      // A native child records the actual arguments and supplies a deterministic signed-file fixture.
      await copyFile(process.execPath, join(directory, 'AzureSignTool-x64.exe'));
      const hook = join(directory, 'signer.cjs');
      await writeFile(
        hook,
        [
          "const fs = require('node:fs');",
          'fs.writeFileSync(process.env.TRACE, JSON.stringify(process.argv.slice(1)));',
          "if (process.env.FAKE_SIGN_ERROR === '1') process.exit(7);",
          "fs.appendFileSync(process.env.INSTALLER, '-signed');",
          'process.exit(0);',
        ].join('\n'),
      );
      const trace = join(directory, 'trace.json');
      const env = {
        VAULT_NAME: 'wormhole-signing',
        CERTIFICATE: 'release',
        AZURE_TENANT_ID: 'test-tenant',
        AZURE_CLIENT_ID: 'test-client',
        AZURE_CLIENT_SECRET: 'fixture-only',
        INSTALLER: installer,
        TRACE: trace,
        NODE_OPTIONS: '--require "' + hook.replaceAll('\\', '/') + '"',
      };
      for (const override of [{ AZURE_CLIENT_SECRET: '' }, { VAULT_NAME: 'other.invalid/path' }]) {
        assert.notEqual(run('Sign Windows installer', { ...env, ...override }).status, 0);
        assert.equal(existsSync(trace), false);
      }
      const failure = run('Sign Windows installer', { ...env, FAKE_SIGN_ERROR: '1' });
      assert.notEqual(failure.status, 0);
      assert.match(failure.stderr, /Windows installer signing failed/);
      assert.equal(await readFile(installer, 'utf8'), 'unsigned');
      const signed = run('Sign Windows installer', env);
      assert.equal(signed.status, 0, signed.stderr);
      const args = JSON.parse(await readFile(trace, 'utf8'));
      // Node expands argv[1] to an absolute path; the remaining arguments are untouched.
      assert.equal(args[0].split(/[\\/]/).at(-1), 'sign');
      assert.deepEqual(args.slice(1), [
        '-q',
        '-kvm',
        '-kvu',
        'https://wormhole-signing.vault.azure.net',
        '-kvc',
        'release',
        '-fd',
        'sha256',
        '-tr',
        'http://timestamp.digicert.com',
        '-td',
        'sha256',
        installer,
      ]);
      assert.equal(run('Generate SHA-256 sidecar', { INSTALLER: installer }).status, 0);
      const digest = createHash('sha256').update('unsigned-signed').digest('hex');
      assert.equal((await readFile(installer + '.sha256', 'utf8')).trim(), digest + '  ' + name);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);

test('release jobs sign installation proofs from the packaged payloads for every target', async () => {
  const findStep = (job, name) => job.steps.find((step) => step.name === name);
  const win = findStep(releaseJobs.build, 'Measure installed Windows payload');
  const linux = findStep(releaseJobs.packages, 'Measure installed Linux payload');
  const mac = findStep(releaseJobs.packages, 'Measure installed macOS payload');
  for (const measure of [win, linux, mac]) {
    assert.match(measure.run, /inventory-installation/);
    assert.doesNotMatch(JSON.stringify(measure), /WORMHOLE_UPDATE_MANIFEST_SEED/);
  }
  assert.match(win.run, /artifacts\/electron-app\/\$env:PLATFORM\/Wormhole/);
  assert.match(
    linux.run,
    /dpkg-deb --extract[\s\S]*rpm2cpio[\s\S]*cmp "\$scratch\/deb.json" "\$scratch\/rpm.json"/,
  );
  assert.match(
    mac.run,
    /hdiutil attach -readonly[\s\S]*inventory-installation[^\n]+darwin\/universal[\s\S]*\$scratch\/mount\/Wormhole\.app/,
  );
  assert.equal(
    findStep(releaseJobs.sign, 'Download installation inventories').with.pattern,
    'installation-inventory-*',
  );
  assert.equal(
    findStep(releaseJobs.release, 'Download release packages').with.pattern,
    'wormhole-*',
  );
  const publish = findStep(releaseJobs.release, 'Publish release with generated notes');
  const targets = ['darwin-universal', 'linux-arm64', 'linux-x64', 'windows-arm64', 'windows-x64'];
  assert.ok(targets.every((target) => publish.run.includes(target)));
  assert.match(publish.run, /test -s "dist\/Wormhole-InstallationProof-v1-\$name.json"/);

  const signer = `#!/usr/bin/env bash
set -euo pipefail
[[ -z "\${WORMHOLE_UPDATE_MANIFEST_SEED+x}" ]]
[[ "$(cat)" == 'test seed' ]]
if [[ "$1" == sign-system-manifest ]]; then
  [[ "$2" == v2.4.3 && "$4" == 'test pin' ]]
  printf signed-system-release > "$3/Wormhole-UpdateManifest-v2.json"
  exit 0
elif [[ "$1" != sign-installation ]]; then
  [[ "$1" == v2.4.3 && "$3" == 'test pin' ]]
  printf signed-release > "$2/Wormhole-UpdateManifest-v1.json"
  exit 0
fi
[[ "$2" == v2.4.3 && "$5" == 'test pin' && "$(cat "$4")" == "$3" ]]
printf 'signed %s' "$3"
`;
  const directory = await mkdtemp(join(tmpdir(), 'wormhole-installation-release-'));
  try {
    await mkdir(join(directory, 'dist'));
    await mkdir(join(directory, 'inventory'));
    await writeFile(join(directory, 'wormhole-sign-update-manifest'), signer, { mode: 0o755 });
    const step = findStep(releaseJobs.sign, 'Sign installer sizes and hashes');
    const execute = () =>
      spawnSync(releaseBash(), ['-s'], {
        cwd: directory,
        encoding: 'utf8',
        input: `export RUNNER_TEMP="$PWD" GITHUB_WORKSPACE="$PWD"\nchmod +x wormhole-sign-update-manifest\n${step.run}`,
        env: {
          ...process.env,
          RELEASE_TAG: 'v2.4.3',
          PUBLIC_KEY: 'test pin',
          WORMHOLE_UPDATE_MANIFEST_SEED: 'test seed',
        },
      });
    for (const target of targets) {
      await writeFile(
        join(directory, 'inventory', `installation-${target}.json`),
        target.replace('-', '/'),
      );
    }
    const valid = execute();
    assert.equal(valid.status, 0, valid.stderr || valid.error?.message);
    assert.equal(
      await readFile(join(directory, 'dist', 'Wormhole-UpdateManifest-v2.json'), 'utf8'),
      'signed-system-release',
    );
    for (const target of targets) {
      assert.equal(
        await readFile(
          join(directory, 'dist', `Wormhole-InstallationProof-v1-${target}.json`),
          'utf8',
        ),
        `signed ${target.replace('-', '/')}`,
      );
    }
    await rm(join(directory, 'inventory', 'installation-linux-x64.json'));
    const missing = execute();
    assert.notEqual(missing.status, 0, 'a missing target inventory must fail the signing job');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('workflows pin runner images and third-party action revisions', () => {
  const pinnedRunners = new Set([
    'ubuntu-24.04',
    'ubuntu-24.04-arm',
    'windows-2025',
    'windows-11-arm',
    'macos-26',
    'macos-26-intel',
  ]);
  const workflows = [
    { source: ciWorkflow, config: parse(ciWorkflow) },
    { source: releaseWorkflow, config: releaseConfig },
  ];

  for (const { source: workflow, config } of workflows) {
    for (const [name, job] of Object.entries(config.jobs)) {
      const runners =
        job['runs-on'] === '${{ matrix.runner }}'
          ? job.strategy.matrix.include.map(({ runner }) => runner)
          : [job['runs-on']];
      assert.ok(runners.length > 0, `${name} must select a runner`);
      for (const runner of runners) {
        assert.ok(pinnedRunners.has(runner), `${name} uses an unreviewed runner image: ${runner}`);
      }
    }
    const actionReferences = [...workflow.matchAll(/uses:\s+([^\s#]+)/g)].map((match) => match[1]);
    assert.ok(actionReferences.length > 0, 'workflow must use at least one action');
    for (const reference of actionReferences) {
      if (reference.startsWith('./')) continue;

      const separator = reference.lastIndexOf('@');
      assert.ok(separator > 0, `${reference} must include an immutable revision`);
      const source = reference.slice(0, separator);
      const revision = reference.slice(separator + 1);
      const expectedRevision = source.startsWith('docker://')
        ? /^sha256:[0-9a-f]{64}$/
        : /^[0-9a-f]{40}$/;
      assert.match(revision, expectedRevision, `${source} must be pinned immutably`);
    }
  }
});

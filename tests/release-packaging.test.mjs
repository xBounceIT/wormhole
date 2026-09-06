import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { relative } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { prerelease, satisfies, valid } from 'semver';
import { parse } from 'yaml';

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
const releaseJobs = parse(releaseWorkflow).jobs;
const linuxIconSizes = [16, 24, 32, 48, 64, 96, 128, 256, 512, 1024];
const projectDir = fileURLToPath(new URL('..', import.meta.url));
const macIcon = await readFile(new URL('../Assets/Wormhole.icns', import.meta.url));

function readPngDimensions(data) {
  const pngSignature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  assert.deepEqual(data.subarray(0, pngSignature.length), pngSignature);
  assert.equal(data.subarray(12, 16).toString('ascii'), 'IHDR');
  return { width: data.readUInt32BE(16), height: data.readUInt32BE(20) };
}

function readIcnsChunkTypes(icon) {
  assert.equal(icon.subarray(0, 4).toString('ascii'), 'icns');
  assert.equal(icon.readUInt32BE(4), icon.length);

  const chunkTypes = new Set();
  let offset = 8;
  while (offset < icon.length) {
    assert.ok(offset + 8 <= icon.length, 'ICNS chunk header is truncated');
    const type = icon.subarray(offset, offset + 4).toString('ascii');
    const size = icon.readUInt32BE(offset + 4);
    assert.ok(size >= 8, `ICNS chunk ${type} has an invalid size`);
    assert.ok(offset + size <= icon.length, `ICNS chunk ${type} is truncated`);
    chunkTypes.add(type);
    offset += size;
  }

  assert.equal(offset, icon.length);
  return chunkTypes;
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

test('electron-builder produces portable and installable Linux packages', () => {
  assert.equal(packageJson.build.artifactName, 'Wormhole-${version}-${os}-${arch}-setup.${ext}');
  assert.equal(packageJson.build.linux.artifactName, 'Wormhole-${version}-${os}-${arch}.${ext}');
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
  const iconChunkTypes = readIcnsChunkTypes(macIcon);
  assert.ok(iconChunkTypes.has('ic09'), 'macOS icon must include a 512px representation');
  assert.ok(iconChunkTypes.has('ic10'), 'macOS icon must include a 1024px representation');
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
  const resolveBackendPath = new Function('process', 'findBundledExecutable', backendPathBody);

  for (const platform of ['darwin', 'win32', 'linux']) {
    for (const arch of ['x64', 'arm64']) {
      const resolve = (files) =>
        resolveBackendPath({ platform, arch }, (name) =>
          files.includes(name) ? `/resources/${name}` : undefined,
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

test('release matrices build every supported platform and architecture', () => {
  assert.deepEqual([...releaseJobs.build.strategy.matrix.platform].sort(), ['arm64', 'x64']);
  const targets = releaseJobs.packages.strategy.matrix.include.map(
    ({ builder_platform, builder_arch, backend_arch }) =>
      `${builder_platform}/${builder_arch}/${backend_arch}`,
  );
  assert.deepEqual(targets.sort(), [
    'linux/arm64/arm64',
    'linux/x64/x64',
    'mac/universal/universal',
  ]);
});

test('release package uploads include installer checksums required by the updater', () => {
  const uploadSteps = releaseJobs.packages.steps.filter((step) =>
    step.uses?.startsWith('actions/upload-artifact@'),
  );
  assert.equal(uploadSteps.length, 1, 'expected one release package upload step');
  const paths = uploadSteps[0].with.path.split(/\r?\n/).map((line) => line.trim());
  assert.ok(paths.includes('${{ matrix.artifacts }}'), 'release installers must be uploaded');
  assert.ok(
    paths.includes('${{ matrix.updater_artifact }}.sha256'),
    'each updater installer must be uploaded with its SHA-256 sidecar',
  );
});

test('workflows pin third-party actions to immutable revisions', () => {
  const workflows = [ciWorkflow, releaseWorkflow];

  for (const workflow of workflows) {
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

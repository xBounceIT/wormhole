import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { relative } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { Arch, getArtifactArchName } from 'builder-util';
import { prerelease, satisfies, valid } from 'semver';

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
const electronMain = await readFile(new URL('../electron/main.ts', import.meta.url), 'utf8');
const universalBackend = await readFile(
  new URL('../scripts/Build-ElectronUniversalBackend.mjs', import.meta.url),
  'utf8',
);
const gitignore = await readFile(new URL('../.gitignore', import.meta.url), 'utf8');
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

function linuxArtifactPattern(arch, extension) {
  return packageJson.build.linux.artifactName
    .replace('${version}', '*')
    .replace('${os}', 'linux')
    .replace('${arch}', getArtifactArchName(arch, extension))
    .replace('${ext}', extension);
}

function isNanoIdVersionPatched(version) {
  return (
    valid(version) !== null &&
    prerelease(version) === null &&
    !satisfies(version, '<3.3.18 || >=4.0.0 <5.1.6')
  );
}

test('dependency lock excludes the Nano ID zero-size generator vulnerability', () => {
  assert.equal(isNanoIdVersionPatched('3.3.17'), false);
  assert.equal(isNanoIdVersionPatched('3.3.18'), true);
  assert.equal(isNanoIdVersionPatched('4.0.0'), false);
  assert.equal(isNanoIdVersionPatched('5.1.5'), false);
  assert.equal(isNanoIdVersionPatched('5.1.6'), true);
  assert.equal(isNanoIdVersionPatched('5.1.6-beta.1'), false);
  assert.equal(isNanoIdVersionPatched('invalid'), false);

  const nanoIdPackages = Object.entries(packageLock.packages)
    .filter(
      ([location]) =>
        location === 'node_modules/nanoid' || location.endsWith('/node_modules/nanoid'),
    )
    .map(([, metadata]) => metadata);

  for (const { version } of nanoIdPackages) {
    assert.ok(isNanoIdVersionPatched(version), `nanoid ${version} is vulnerable`);
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
  assert.equal(packageJson.homepage, 'https://github.com/xBounceIT/wormhole');
  assert.equal(packageJson.license, 'AGPL-3.0-only');
  assert.match(packageJson.author.email, /@/);
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
  assert.equal(packageJson.productName, 'Wormhole');
  assert.equal(packageJson.build.mac.target, 'dmg');
  assert.equal(packageJson.build.mac.icon, 'Assets/Wormhole.icns');
  const iconChunkTypes = readIcnsChunkTypes(macIcon);
  assert.ok(iconChunkTypes.has('ic09'), 'macOS icon must include a 512px representation');
  assert.ok(iconChunkTypes.has('ic10'), 'macOS icon must include a 1024px representation');
  assert.equal(packageJson.scripts.package, 'electron-builder --publish never');
});

test('the desktop window uses an icon format supported by the current platform', () => {
  assert.match(electronMain, /process\.platform === 'win32' \? 'Wormhole\.ico' : 'Wormhole\.png'/);
  assert.match(electronMain, /icon: applicationIconPath/);
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
  assert.match(electronMain, /findBundledExecutable\('wormhole-backend-universal'\)/);
  assert.match(universalBackend, /chmodSync\(outputPath, 0o755\)/);
  assert.match(
    universalBackend,
    /run\('lipo', \[outputPath, '-verify_arch', 'x86_64', 'arm64'\]\)/,
  );
});

test('release workflow builds and publishes every desktop package', () => {
  for (const expected of [
    linuxArtifactPattern(Arch.x64, 'AppImage'),
    linuxArtifactPattern(Arch.x64, 'deb'),
    linuxArtifactPattern(Arch.x64, 'rpm'),
    linuxArtifactPattern(Arch.arm64, 'AppImage'),
    linuxArtifactPattern(Arch.arm64, 'deb'),
    linuxArtifactPattern(Arch.arm64, 'rpm'),
    'Wormhole-*-mac-universal-setup.dmg',
  ]) {
    assert.match(releaseWorkflow, new RegExp(expected.replaceAll('*', '\\*').replace('.', '\\.')));
  }
  assert.match(releaseWorkflow, /gh release upload/);
  assert.match(releaseWorkflow, /gh release edit/);
  assert.match(releaseWorkflow, /Generate installer SHA-256 sidecar/);
  assert.match(releaseWorkflow, /\$installers\.Count -ne 1/);
  assert.match(releaseWorkflow, /\$\{\{ matrix\.updater_artifact \}\}\.sha256/);
  assert.equal((releaseWorkflow.match(/Verify tag matches package version/g) ?? []).length, 1);
  assert.match(releaseWorkflow, /build:\r?\n[\s\S]*?needs: checks/);
  assert.match(releaseWorkflow, /packages:\r?\n[\s\S]*?needs: checks/);
  assert.match(releaseWorkflow, /needs: \[build, packages\]/);
  assert.match(releaseWorkflow, /Verify Linux package outputs/);
  assert.match(releaseWorkflow, /if \[\[ \$\{#matches\[@\]\} -ne 1 \]\]/);
  assert.match(releaseWorkflow, /usr\/share\/icons\/hicolor\/\$size\/apps\/wormhole\.png/);
  assert.match(releaseWorkflow, /dpkg-deb --extract/);
  assert.match(releaseWorkflow, /PNG image data/);
  assert.match(releaseWorkflow, /cmp -s "Assets\/LinuxIcons\/\$size\.png"/);
  assert.doesNotMatch(releaseWorkflow, /dpkg-deb --contents/);
  assert.match(releaseWorkflow, /Icon=wormhole/);
  for (const extension of ['AppImage', 'deb', 'rpm']) {
    assert.equal(
      (releaseWorkflow.match(new RegExp(`release/\\*\\.${extension}`, 'g')) ?? []).length,
      2,
    );
  }
  assert.match(releaseWorkflow, /permissions:\r?\n\s+contents: read/);
  assert.match(releaseWorkflow, /release:\r?\n[\s\S]*?permissions:\r?\n\s+contents: write/);
  assert.match(
    releaseWorkflow,
    /group: release-\$\{\{ github\.event\.inputs\.tag \|\| github\.ref_name \}\}/,
  );
  assert.match(gitignore, /^\/release\/$/m);
  assert.doesNotMatch(gitignore, /^release\/$/m);
});

test('workflows pin current stable runner images and immutable actions', () => {
  const workflows = [ciWorkflow, releaseWorkflow];
  const combinedWorkflows = workflows.join('\n');
  const expectedRunnerImages = ['macos-26', 'ubuntu-24.04', 'windows-2025'];
  const configuredRunnerImages = [
    ...new Set(combinedWorkflows.match(/\b(?:ubuntu|windows|macos)-[\w.-]+\b/g) ?? []),
  ].sort();

  assert.deepEqual(configuredRunnerImages, expectedRunnerImages);

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

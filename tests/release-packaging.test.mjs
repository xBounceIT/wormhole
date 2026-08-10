import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { Arch, getArtifactArchName } from 'builder-util';

const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
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

function linuxArtifactPattern(arch, extension) {
  return packageJson.build.linux.artifactName
    .replace('${version}', '*')
    .replace('${os}', 'linux')
    .replace('${arch}', getArtifactArchName(arch, extension))
    .replace('${ext}', extension);
}

test('electron-builder produces portable and installable Linux packages', () => {
  assert.equal(packageJson.build.artifactName, 'Wormhole-${version}-${os}-${arch}-setup.${ext}');
  assert.equal(packageJson.build.linux.artifactName, 'Wormhole-${version}-${os}-${arch}.${ext}');
  assert.deepEqual(packageJson.build.linux.target, ['AppImage', 'deb', 'rpm']);
  assert.equal(packageJson.build.linux.icon, 'Assets/Wormhole.png');
  assert.equal(packageJson.desktopName, 'com.xbounceit.wormhole.desktop');
  assert.equal(packageJson.build.linux.syncDesktopName, true);
  assert.equal(packageJson.homepage, 'https://github.com/xBounceIT/wormhole');
  assert.equal(packageJson.license, 'AGPL-3.0-only');
  assert.match(packageJson.author.email, /@/);
  assert.equal(packageJson.build.deb.packageName, 'wormhole');
  assert.equal(packageJson.build.rpm.packageName, 'wormhole');
});

test('electron-builder produces the supported macOS installer', () => {
  assert.equal(packageJson.productName, 'Wormhole');
  assert.equal(packageJson.build.mac.target, 'dmg');
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

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

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

test('electron-builder produces the supported Linux and macOS installers', () => {
  assert.equal(packageJson.build.artifactName, 'Wormhole-${version}-${os}-${arch}-setup.${ext}');
  assert.equal(packageJson.build.linux.target, 'AppImage');
  assert.equal(packageJson.build.mac.target, 'dmg');
  assert.equal(packageJson.scripts.package, 'electron-builder --publish never');
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

test('release workflow builds and publishes every installer target', () => {
  for (const expected of [
    'Wormhole-*-linux-x86_64-setup.AppImage',
    'Wormhole-*-linux-arm64-setup.AppImage',
    'Wormhole-*-mac-universal-setup.dmg',
  ]) {
    assert.match(releaseWorkflow, new RegExp(expected.replaceAll('*', '\\*').replace('.', '\\.')));
  }
  assert.match(releaseWorkflow, /gh release upload/);
  assert.match(releaseWorkflow, /gh release edit/);
  assert.match(releaseWorkflow, /Generate installer SHA-256 sidecar/);
  assert.match(releaseWorkflow, /\$installers\.Count -ne 1/);
  assert.match(releaseWorkflow, /\$\{\{ matrix\.artifact \}\}\.sha256/);
  assert.equal((releaseWorkflow.match(/Verify tag matches package version/g) ?? []).length, 1);
  assert.match(releaseWorkflow, /build:\r?\n[\s\S]*?needs: checks/);
  assert.match(releaseWorkflow, /installers:\r?\n[\s\S]*?needs: checks/);
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

import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import * as ResEdit from 'resedit';

const execFileAsync = promisify(execFile);
const testRoot = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.dirname(testRoot);
const patchScript = path.join(repoRoot, 'scripts', 'patch-electron-exe.mjs');
const stageRuntimeDependenciesScript = path.join(
  repoRoot,
  'scripts',
  'stage-electron-runtime-dependencies.mjs',
);
const runtimeDependenciesManifest = path.join(
  repoRoot,
  'installer',
  'electron-runtime-dependencies.json',
);
const iconPath = path.join(repoRoot, 'Assets', 'Wormhole.ico');

async function collectRuntimeDependencyClosure(packageName, dependencyNames = new Set()) {
  if (dependencyNames.has(packageName)) return dependencyNames;
  dependencyNames.add(packageName);
  const packageJsonPath = path.join(
    repoRoot,
    'node_modules',
    ...packageName.split('/'),
    'package.json',
  );
  const packageJson = JSON.parse(await readFile(packageJsonPath, 'utf8'));
  for (const dependencyName of Object.keys(packageJson.dependencies ?? {})) {
    await collectRuntimeDependencyClosure(dependencyName, dependencyNames);
  }
  return dependencyNames;
}

async function createExecutableFixture(exePath, { includeVersion = true } = {}) {
  const executable = ResEdit.NtExecutable.createEmpty(false, false);
  const resources = ResEdit.NtExecutableResource.from(executable);
  const iconFile = ResEdit.Data.IconFile.from(await readFile(iconPath));
  ResEdit.Resource.IconGroupEntry.replaceIconsForResource(resources.entries, 1, 1033, [
    iconFile.icons[0].data,
  ]);

  if (includeVersion) {
    const versionInfo = ResEdit.Resource.VersionInfo.create(
      1033,
      { fileOS: 0x40004, fileType: 1 },
      [
        {
          lang: 1033,
          codepage: 1200,
          values: {
            InternalName: 'electron.exe',
            ProductName: 'Electron',
            SquirrelAwareVersion: '1',
          },
        },
      ],
    );
    versionInfo.setFileVersion('43.3.0');
    versionInfo.setProductVersion('43.3.0');
    versionInfo.outputToResourceEntries(resources.entries);
  }

  resources.outputResource(executable);
  await writeFile(exePath, Buffer.from(executable.generate()));
}

async function inspectExecutable(exePath) {
  const executable = ResEdit.NtExecutable.from(await readFile(exePath));
  const resources = ResEdit.NtExecutableResource.from(executable);
  const iconGroups = ResEdit.Resource.IconGroupEntry.fromEntries(resources.entries);
  const versionInfo = ResEdit.Resource.VersionInfo.fromEntries(resources.entries)[0];
  return { iconGroups, versionInfo };
}

async function createNeutralVersionFixture(exePath) {
  const executable = ResEdit.NtExecutable.createEmpty(false, false);
  const resources = ResEdit.NtExecutableResource.from(executable);
  const versionInfo = ResEdit.Resource.VersionInfo.create(0, {}, []);
  versionInfo.outputToResourceEntries(resources.entries);
  resources.outputResource(executable);
  await writeFile(exePath, Buffer.from(executable.generate()));
}

test('patches prerelease metadata and icons idempotently', async (context) => {
  const temporaryDirectory = await mkdtemp(path.join(tmpdir(), 'wormhole resedit Ω-'));
  context.after(() => rm(temporaryDirectory, { recursive: true, force: true }));
  const exePath = path.join(temporaryDirectory, 'Wormhole.exe');
  const version = '2.0.0-beta.1+build.7';
  await createExecutableFixture(exePath);

  await execFileAsync(process.execPath, [patchScript, exePath, version, iconPath]);

  const firstOutput = await readFile(exePath);
  const { iconGroups, versionInfo } = await inspectExecutable(exePath);
  const language = versionInfo.getAllLanguagesForStringValues()[0];
  const values = versionInfo.getStringValues(language);
  assert.equal(iconGroups.length, 1);
  assert.equal(iconGroups[0].icons.length, 7);
  assert.equal(values.ProductName, 'Wormhole');
  assert.equal(values.FileVersion, version);
  assert.equal(values.ProductVersion, version);
  assert.equal(values.InternalName, 'Wormhole.exe');
  assert.equal(values.SquirrelAwareVersion, '1');
  assert.equal(versionInfo.fixedInfo.fileVersionMS >>> 0, 2 << 16);
  assert.equal(versionInfo.fixedInfo.fileVersionLS >>> 0, 0);
  assert.equal(versionInfo.fixedInfo.productVersionMS >>> 0, 2 << 16);
  assert.equal(versionInfo.fixedInfo.productVersionLS >>> 0, 0);

  await execFileAsync(process.execPath, [patchScript, exePath, version, iconPath]);

  assert.deepEqual(await readFile(exePath), firstOutput);
  assert.deepEqual(await readdir(temporaryDirectory), ['Wormhole.exe']);
});

test('leaves the executable unchanged when required version resources are missing', async (context) => {
  const temporaryDirectory = await mkdtemp(path.join(tmpdir(), 'wormhole-resedit-test-'));
  context.after(() => rm(temporaryDirectory, { recursive: true, force: true }));
  const exePath = path.join(temporaryDirectory, 'Wormhole.exe');
  await createExecutableFixture(exePath, { includeVersion: false });
  const original = await readFile(exePath);

  await assert.rejects(
    execFileAsync(process.execPath, [patchScript, exePath, '2.0.0', iconPath]),
    /executable contains no version information/,
  );

  assert.deepEqual(await readFile(exePath), original);
  assert.deepEqual(await readdir(temporaryDirectory), ['Wormhole.exe']);
});

test('preserves version forms accepted by rcedit', async (context) => {
  const temporaryDirectory = await mkdtemp(path.join(tmpdir(), 'wormhole-resedit-test-'));
  context.after(() => rm(temporaryDirectory, { recursive: true, force: true }));
  const cases = [
    { version: '2.0.0_rc1', fileVersionLS: 0 },
    { version: '2.0.0.1.5', fileVersionLS: 1 },
  ];

  for (const [index, current] of cases.entries()) {
    const exePath = path.join(temporaryDirectory, `Wormhole-${index}.exe`);
    await createExecutableFixture(exePath);
    await execFileAsync(process.execPath, [patchScript, exePath, current.version, iconPath]);

    const { versionInfo } = await inspectExecutable(exePath);
    const language = versionInfo.getAllLanguagesForStringValues()[0];
    const values = versionInfo.getStringValues(language);
    assert.equal(values.FileVersion, current.version);
    assert.equal(values.ProductVersion, current.version);
    assert.equal(versionInfo.fixedInfo.fileVersionLS >>> 0, current.fileVersionLS);
    assert.equal(versionInfo.fixedInfo.productVersionLS >>> 0, current.fileVersionLS);
  }
});

test('preserves neutral version resources without string tables', async (context) => {
  const temporaryDirectory = await mkdtemp(path.join(tmpdir(), 'wormhole-resedit-test-'));
  context.after(() => rm(temporaryDirectory, { recursive: true, force: true }));
  const exePath = path.join(temporaryDirectory, 'Wormhole.exe');
  await createNeutralVersionFixture(exePath);

  await execFileAsync(process.execPath, [patchScript, exePath, '2.0.0', iconPath]);

  const { versionInfo } = await inspectExecutable(exePath);
  assert.equal(versionInfo.lang, 0);
  assert.deepEqual(versionInfo.getAllLanguagesForStringValues(), [{ lang: 0, codepage: 1200 }]);
  assert.equal(versionInfo.getStringValues({ lang: 0, codepage: 1200 }).ProductName, 'Wormhole');
});

test('supports 16-bit version limits and rejects larger components', async (context) => {
  const temporaryDirectory = await mkdtemp(path.join(tmpdir(), 'wormhole-resedit-test-'));
  context.after(() => rm(temporaryDirectory, { recursive: true, force: true }));
  const exePath = path.join(temporaryDirectory, 'Wormhole.exe');
  await createExecutableFixture(exePath);

  await execFileAsync(process.execPath, [
    patchScript,
    exePath,
    '65535.65535.65535.65535',
    iconPath,
  ]);
  const { versionInfo } = await inspectExecutable(exePath);
  assert.equal(versionInfo.fixedInfo.fileVersionMS >>> 0, 0xffffffff);
  assert.equal(versionInfo.fixedInfo.fileVersionLS >>> 0, 0xffffffff);

  const validOutput = await readFile(exePath);
  await assert.rejects(
    execFileAsync(process.execPath, [patchScript, exePath, '65536.0.0', iconPath]),
    /numeric version components must be between 0 and 65535/,
  );
  assert.deepEqual(await readFile(exePath), validOutput);
});

test('stages the complete Chrome extension runtime dependency closure', async (context) => {
  const declaredDependencies = JSON.parse(await readFile(runtimeDependenciesManifest, 'utf8'));
  const expectedDependencies = await collectRuntimeDependencyClosure('electron-chrome-extensions');
  assert.deepEqual([...declaredDependencies].sort(), [...expectedDependencies].sort());

  const temporaryDirectory = await mkdtemp(path.join(tmpdir(), 'wormhole-runtime-deps-'));
  context.after(() => rm(temporaryDirectory, { recursive: true, force: true }));
  const destination = path.join(temporaryDirectory, 'node_modules');
  await execFileAsync(process.execPath, [
    stageRuntimeDependenciesScript,
    runtimeDependenciesManifest,
    path.join(repoRoot, 'node_modules'),
    destination,
  ]);

  for (const dependencyName of declaredDependencies) {
    const stagedPackageJson = path.join(destination, ...dependencyName.split('/'), 'package.json');
    const packageJson = JSON.parse(await readFile(stagedPackageJson, 'utf8'));
    assert.equal(packageJson.name, dependencyName);
  }
});

test('rejects traversal before staging Electron runtime dependencies', async (context) => {
  const temporaryDirectory = await mkdtemp(path.join(tmpdir(), 'wormhole-runtime-deps-invalid-'));
  context.after(() => rm(temporaryDirectory, { recursive: true, force: true }));
  const manifest = path.join(temporaryDirectory, 'dependencies.json');
  const destination = path.join(temporaryDirectory, 'node_modules');
  await writeFile(manifest, JSON.stringify(['electron-chrome-extensions', '..']));

  await assert.rejects(
    execFileAsync(process.execPath, [
      stageRuntimeDependenciesScript,
      manifest,
      path.join(repoRoot, 'node_modules'),
      destination,
    ]),
    /Invalid Electron runtime dependency name: \.\./,
  );
  await assert.rejects(stat(destination), /ENOENT/);
});

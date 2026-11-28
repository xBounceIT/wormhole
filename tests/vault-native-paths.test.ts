import assert from 'node:assert/strict';
import test from 'node:test';
import path from 'node:path';
import { mkdtemp, mkdir, writeFile, unlink, rm, rmdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { selectVaultNativePaths } from '../electron/vault-native-paths.ts';

test('native selections preserve Windows compatibility and portable userData roots', () => {
  const userData = path.resolve('fixture-user-data');
  for (const configured of [undefined, '', '   ']) {
    const portable = selectVaultNativePaths(userData, { WORMHOLE_DATABASE: configured });
    assert.deepEqual(portable, {
      userDataPath: userData,
      databasePath: path.join(userData, 'Wormhole', 'wormhole.db'),
    });
    const windows = selectVaultNativePaths(userData, {
      LOCALAPPDATA: path.resolve('fixture-local'),
      WORMHOLE_DATABASE: configured,
    });
    assert.equal(windows.databasePath, path.resolve('fixture-local', 'Wormhole', 'wormhole.db'));
  }
  const environment = {
    WORMHOLE_DATABASE: '  relative-selected.db  ',
    LOCALAPPDATA: path.resolve('unused'),
  };
  const pinned = selectVaultNativePaths(userData, environment);
  environment.WORMHOLE_DATABASE = 'different.db';
  assert.deepEqual(pinned, {
    userDataPath: userData,
    databasePath: path.resolve('relative-selected.db'),
  });
  assert.ok(Object.isFrozen(pinned));
  assert.throws(() => {
    (pinned as any).databasePath = 'changed';
  });
  assert.equal(
    selectVaultNativePaths(userData, { WORMHOLE_DATABASE: path.join(userData, 'custom.db') })
      .databasePath,
    path.join(userData, 'custom.db'),
  );
});

test('native selection admits a complete restored pair and rejects ambiguous or partial copies', async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), 'wormhole-restored-selection-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const original = path.join(directory, 'configured.db');
  const restoredDirectory = `${original}.restored`;
  const env = { WORMHOLE_DATABASE: original };
  assert.equal(selectVaultNativePaths(directory, env).databasePath, original);
  await mkdir(restoredDirectory);
  assert.throws(() => selectVaultNativePaths(directory, env), /Restored vault selection/);
  const restored = path.join(restoredDirectory, 'wormhole.db');
  await writeFile(restored, 'ciphertext fixture');
  await writeFile(`${restored}.slots`, 'slots fixture');
  assert.equal(selectVaultNativePaths(directory, env).databasePath, restored);
  await writeFile(original, 'preserve previous database');
  assert.throws(() => selectVaultNativePaths(directory, env), /Restored vault selection/);
  await unlink(original);
  await writeFile(`${original}.slots`, 'preserve previous slots');
  assert.throws(() => selectVaultNativePaths(directory, env), /Restored vault selection/);
  await unlink(`${original}.slots`);
  await unlink(restored);
  assert.throws(() => selectVaultNativePaths(directory, env), /Restored vault selection/);
  await mkdir(`${restored}.root-rotation`);
  assert.throws(() => selectVaultNativePaths(directory, env), /Restored vault selection/);
  await rmdir(`${restored}.root-rotation`);
  await writeFile(`${restored}.root-rotation`, 'native rotation journal fixture');
  assert.equal(selectVaultNativePaths(directory, env).databasePath, restored);
});

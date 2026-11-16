import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  parseMRemoteImportInspection,
  parseMRemoteImportOptions,
  parseMRemoteImportPlan,
  parseMRemoteImportResult,
} from '../electron/mremote-import-contract.ts';

test('mRemoteNG IPC option validation rejects malformed and oversized secrets', () => {
  assert.deepEqual(
    parseMRemoteImportOptions({ password: 'secret', structureOnly: false, reuseExisting: true }),
    {
      password: 'secret',
      structureOnly: false,
      reuseExisting: true,
    },
  );
  assert.throws(() => parseMRemoteImportOptions({ password: 'x' }));
  assert.throws(() =>
    parseMRemoteImportOptions({
      password: 'x'.repeat(16 * 1024 + 1),
      structureOnly: false,
      reuseExisting: true,
    }),
  );
  assert.doesNotThrow(() =>
    parseMRemoteImportOptions({
      password: 'x'.repeat(16 * 1024),
      structureOnly: false,
      reuseExisting: true,
    }),
  );
  assert.throws(() =>
    parseMRemoteImportOptions({
      password: '🔐'.repeat(4097),
      structureOnly: false,
      reuseExisting: true,
    }),
  );
});

test('mRemoteNG IPC response validation accepts a bounded plan and rejects drift', () => {
  const plan = {
    planToken: 'a'.repeat(64),
    folders: 1,
    connections: 1,
    credentials: 1,
    credentialsReused: 2,
    sharedCredentials: 0,
    sharedCredentialConnections: 0,
    skippedUnsupported: 0,
    skippedUnsupportedSamples: [],
    warnings: [],
    droppedWarnings: 0,
    preview: [{ name: 'Root', kind: 'folder', depth: 1 }],
    previewTruncated: false,
  };
  assert.deepEqual(parseMRemoteImportPlan(plan), plan);
  assert.doesNotThrow(() =>
    parseMRemoteImportPlan({
      ...plan,
      preview: [{ name: '🔐'.repeat(256), kind: 'folder', depth: 1 }],
    }),
  );
  assert.throws(() =>
    parseMRemoteImportPlan({
      ...plan,
      preview: [{ name: '🔐'.repeat(257), kind: 'folder', depth: 1 }],
    }),
  );
  assert.throws(() =>
    parseMRemoteImportPlan({
      ...plan,
      preview: [{ ...plan.preview[0], password: 'leak', kind: 'invalid' }],
    }),
  );
  assert.throws(() => parseMRemoteImportPlan({ ...plan, warnings: Array(51).fill('warning') }));
});

test('mRemoteNG inspect and result contracts reject invalid values', () => {
  assert.equal(
    parseMRemoteImportInspection(
      {
        fileSize: 10,
        confVersion: '2.7',
        passwordRequired: true,
        fullFileEncrypted: false,
      },
      'c.xml',
    ).fileName,
    'c.xml',
  );
  assert.throws(() => parseMRemoteImportInspection({ fileSize: -1 }, 'c.xml'));
  assert.equal(
    parseMRemoteImportResult({
      foldersCreated: 1,
      connectionsCreated: 2,
      credentialsCreated: 3,
      credentialsReused: 2,
      skippedUnsupported: 0,
      warnings: [],
      droppedWarnings: 0,
    }).connectionsCreated,
    2,
  );
  assert.throws(() => parseMRemoteImportResult({ foldersCreated: -1 }));
  assert.throws(() =>
    parseMRemoteImportResult({
      foldersCreated: 1,
      connectionsCreated: 2,
      credentialsCreated: 3,
      credentialsReused: 2,
      skippedUnsupported: 0,
      warnings: [],
      droppedWarnings: 0,
      password: 'must-not-cross',
    }),
  );
});

test('mRemoteNG commit starts inside the authorization boundary and supports cooperative cancellation', () => {
  const mainSource = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const handler = mainSource.slice(
    mainSource.indexOf("ipcMain.handle('mremote-import:commit'"),
    mainSource.indexOf("ipcMain.handle('backup:export'"),
  );
  assert.match(handler, /runOwnedNativeOperation\(event\.sender, 'mremote-import'/);
  assert.match(handler, /mremote\.import\.commit/);
  assert.match(handler, /selection\.reuseExisting !== options\.reuseExisting/);
  assert.match(handler, /reuseExisting: options\.reuseExisting/);
  assert.match(handler, /mremote-import:cancel-commit/);
  assert.match(mainSource, /function runOwnedNativeOperation[\s\S]{0,1200}runAuthorizedOperation/);
  assert.match(mainSource, /cancelOperation\(operation\.id\)/);
});

test('mRemoteNG reuse options and count fields remain strict and bounded', () => {
  for (const reuseExisting of [true, false]) {
    assert.equal(
      parseMRemoteImportOptions({ password: '', structureOnly: false, reuseExisting })
        .reuseExisting,
      reuseExisting,
    );
  }
  for (const reuseExisting of [undefined, null, 'true', 0]) {
    assert.throws(() =>
      parseMRemoteImportOptions({ password: '', structureOnly: false, reuseExisting }),
    );
  }
  const plan = {
    planToken: 'a'.repeat(64),
    folders: 1,
    connections: 11,
    credentials: 5,
    credentialsReused: 2,
    sharedCredentials: 3,
    sharedCredentialConnections: 11,
    skippedUnsupported: 0,
    skippedUnsupportedSamples: [],
    warnings: [],
    droppedWarnings: 0,
    preview: [],
    previewTruncated: false,
  };
  assert.deepEqual(parseMRemoteImportPlan(plan), plan);
  for (const field of ['credentialsReused', 'sharedCredentials', 'sharedCredentialConnections']) {
    for (const value of [undefined, -1, 50_001, 0.5, '1']) {
      assert.throws(() => parseMRemoteImportPlan({ ...plan, [field]: value }));
    }
  }
  assert.throws(() => parseMRemoteImportPlan({ ...plan, password: 'leak' }));
  assert.throws(() => parseMRemoteImportPlan({ ...plan, sharedCredentials: 6 }));
  assert.throws(() => parseMRemoteImportPlan({ ...plan, sharedCredentialConnections: 12 }));
  const result = {
    foldersCreated: 1,
    connectionsCreated: 2,
    credentialsCreated: 1,
    credentialsReused: 1,
    skippedUnsupported: 0,
    warnings: [],
    droppedWarnings: 0,
  };
  assert.deepEqual(parseMRemoteImportResult(result), result);
  for (const credentialsReused of [undefined, -1, 50_001, 0.5, '1']) {
    assert.throws(() => parseMRemoteImportResult({ ...result, credentialsReused }));
  }
});

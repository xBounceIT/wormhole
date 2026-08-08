import assert from 'node:assert/strict';
import test from 'node:test';
import {
  parseMRemoteImportInspection,
  parseMRemoteImportOptions,
  parseMRemoteImportPlan,
  parseMRemoteImportResult,
} from '../electron/mremote-import-contract.ts';

test('mRemoteNG IPC option validation rejects malformed and oversized secrets', () => {
  assert.deepEqual(parseMRemoteImportOptions({ password: 'secret', structureOnly: false }), {
    password: 'secret',
    structureOnly: false,
  });
  assert.throws(() => parseMRemoteImportOptions({ password: 'x' }));
  assert.throws(() =>
    parseMRemoteImportOptions({ password: 'x'.repeat(16 * 1024 + 1), structureOnly: false }),
  );
});

test('mRemoteNG IPC response validation accepts a bounded plan and rejects drift', () => {
  const plan = {
    planToken: 'a'.repeat(64),
    folders: 1,
    connections: 1,
    credentials: 1,
    skippedUnsupported: 0,
    skippedUnsupportedSamples: [],
    warnings: [],
    droppedWarnings: 0,
    preview: [{ name: 'Root', kind: 'folder', depth: 1 }],
    previewTruncated: false,
  };
  assert.deepEqual(parseMRemoteImportPlan(plan), plan);
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
      skippedUnsupported: 0,
      warnings: [],
      droppedWarnings: 0,
      password: 'must-not-cross',
    }),
  );
});

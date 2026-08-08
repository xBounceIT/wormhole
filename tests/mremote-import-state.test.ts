import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { canAnalyzeMRemoteImport, mremoteImportProgress } from '../src/mremote-import-state.ts';

const encryptedInspection: WormholeMRemoteImportInspection = {
  fileName: 'connections.xml',
  fileSize: 128,
  confVersion: '2.7',
  passwordRequired: true,
  fullFileEncrypted: false,
};

test('password-protected analysis requires a password or explicit structure-only mode', () => {
  assert.equal(canAnalyzeMRemoteImport(encryptedInspection, 'idle', false, false), false);
  assert.equal(canAnalyzeMRemoteImport(encryptedInspection, 'idle', true, false), true);
  assert.equal(canAnalyzeMRemoteImport(encryptedInspection, 'idle', false, true), true);
  assert.equal(canAnalyzeMRemoteImport(encryptedInspection, 'analyzing', true, false), false);
});

test('full-file encryption cannot enter analysis', () => {
  assert.equal(
    canAnalyzeMRemoteImport(
      { ...encryptedInspection, fullFileEncrypted: true },
      'idle',
      true,
      false,
    ),
    false,
  );
});

test('flow progress covers selection, analysis, preview, commit, and result', () => {
  assert.deepEqual(
    [
      mremoteImportProgress('idle', false, false, false),
      mremoteImportProgress('selecting', false, false, false),
      mremoteImportProgress('idle', true, false, false),
      mremoteImportProgress('analyzing', true, false, false),
      mremoteImportProgress('idle', true, true, false),
      mremoteImportProgress('committing', true, true, false),
      mremoteImportProgress('idle', true, false, true),
    ],
    [0, 10, 20, 35, 60, 75, 100],
  );
});

test('connections menu opens the wired mRemoteNG dialog', async () => {
  const source = await readFile(new URL('../src/App.tsx', import.meta.url), 'utf8');
  assert.match(source, /DropdownMenuItem onClick=\{\(\) => setMremoteImportOpen\(true\)\}/);
  assert.match(source, /<MRemoteImportDialog/);
  assert.match(source, /onImported=\{applyWorkspaceSnapshot\}/);
});

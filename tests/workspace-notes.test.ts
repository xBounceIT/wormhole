import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  parseWorkspaceNotes,
  workspaceNodeWriteMaxRequestBytes,
  workspaceNotesMaxLength,
} from '../electron/workspace-notes.ts';

test('connection notes preserve multiline text, whitespace, Unicode and literal markup', () => {
  for (const notes of [
    '',
    '  First line\r\nSecond line\t\n',
    'Manutenzione 🛠️',
    '<script>alert(1)</script>',
  ]) {
    assert.equal(parseWorkspaceNotes(notes), notes);
  }
  assert.equal(parseWorkspaceNotes(undefined), undefined);
  const maximum = 'a'.repeat(workspaceNotesMaxLength);
  assert.equal(parseWorkspaceNotes(maximum), maximum);
  const maximumEmoji = '🛠'.repeat(workspaceNotesMaxLength / 2);
  assert.equal(parseWorkspaceNotes(maximumEmoji), maximumEmoji);
});

test('connection notes reject invalid IPC types, oversized input and null bytes', () => {
  for (const notes of [
    null,
    42,
    false,
    {},
    [],
    'a'.repeat(workspaceNotesMaxLength + 1),
    '🛠'.repeat(workspaceNotesMaxLength / 2 + 1),
    'before\0after',
  ]) {
    assert.throws(() => parseWorkspaceNotes(notes), /Connection notes are invalid/);
  }
});

test('connection notes reject unpaired UTF-16 surrogates before JSON serialization', () => {
  for (const notes of [
    '\uD800',
    '\uDC00',
    'before\uD800after',
    'before\uDC00after',
    '\uD800\uD800',
    '\uDC00\uD800',
    '\uD800\uDC00\uDC00',
    '\uD800\uD800\uDC00',
  ]) {
    assert.throws(() => parseWorkspaceNotes(notes), /Connection notes are invalid/);
  }
  for (const notes of ['\uD800\uDC00', '\uDBFF\uDFFF', 'before 🛠️ after', '\uFFFD']) {
    assert.equal(parseWorkspaceNotes(notes), notes);
    assert.equal(JSON.parse(JSON.stringify(notes)), notes);
  }
});

test('connection write limits allow maximum JSON-escaped notes while keeping process input bounded', () => {
  const notes = '\x01'.repeat(workspaceNotesMaxLength);
  assert.equal(parseWorkspaceNotes(notes), notes);
  const request = JSON.stringify({ name: 'Connection', notes, host: 'example.test' });
  assert.ok(Buffer.byteLength(request, 'utf8') > 64 * 1024);
  assert.ok(Buffer.byteLength(request, 'utf8') < workspaceNodeWriteMaxRequestBytes);
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  assert.match(
    main,
    /operation === 'workspace-node-create' \|\| operation === 'workspace-node-update'\s*\? workspaceNodeWriteMaxRequestBytes/,
  );
});

test('saved connection create and edit flows initialize, load and submit notes through validated IPC', () => {
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const section = (start: string, end: string) => {
    const first = app.indexOf(start);
    const last = app.indexOf(end, first);
    assert.ok(first >= 0 && last > first);
    return app.slice(first, last);
  };
  assert.match(
    section('function openNewConnection(', 'async function showConnectionCredentials('),
    /notes: ''/,
  );
  assert.match(
    section('function openQuickConnect(', 'function applyWorkspaceSnapshot('),
    /notes: ''/,
  );
  const editing = section('function openEditConnection(', 'function openEditFolder(');
  assert.match(editing, /setConnectionEditorMode\('saved'\)/);
  assert.match(editing, /notes: node\.notes \?\? ''/);
  assert.match(
    editing,
    /setConnectionNotesReady\(!window\.wormhole \|\| node\.persisted === false\)/,
  );
  const submission = section(
    'async function submitNewConnection(',
    'async function submitFolderDetails(',
  );
  assert.match(submission, /if \(editorBusy \|\| !connectionNotesReady\) return/);
  assert.match(
    section('async function submitNewConnection(', 'async function submitFolderDetails('),
    /notes: newConnectionForm\.notes/,
  );
  const main = readFileSync(new URL('../electron/main.ts', import.meta.url), 'utf8');
  const parsing = main.slice(
    main.indexOf('function parseWorkspaceNodeWriteRequest('),
    main.indexOf('function isWorkspaceNodeCredentialSettingsRequest('),
  );
  assert.match(parsing, /const notes = parseWorkspaceNotes\(value\.notes\)/);
  assert.match(parsing, /return \{[\s\S]*\bnotes,/);
  const reading = main.slice(
    main.indexOf("ipcMain.handle('workspace:node-notes'"),
    main.indexOf("ipcMain.handle('workspace:move-nodes'"),
  );
  assert.match(reading, /parseWorkspaceNodeRequest\(value\)/);
  assert.match(reading, /runAuthorizedOperation/);
  assert.match(reading, /'workspace-node-notes', request/);
  const preload = readFileSync(new URL('../electron/preload.cts', import.meta.url), 'utf8');
  assert.match(
    preload,
    /loadWorkspaceNodeNotes:[\s\S]*?ipcRenderer.invoke\('workspace:node-notes', request\)/,
  );
});

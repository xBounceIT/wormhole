import assert from 'node:assert/strict';
import test from 'node:test';
import {
  beginSftpTreeRequest,
  createSftpTree,
  finishSftpTreeRequest,
  invalidateSftpTree,
  revealSftpTreePath,
  sftpShortcut,
  sftpTreeAncestors,
  sftpTreeCacheLimit,
  sftpTreeRows,
  toggleSftpTreePath,
} from '../src/sftp-tree-state.ts';

test('revealing paths synchronizes trees on POSIX, drive roots and UNC shares', () => {
  assert.deepEqual(sftpTreeAncestors('remote', '/var/www/site'), [
    '/',
    '/var',
    '/var/www',
    '/var/www/site',
  ]);
  assert.deepEqual(sftpTreeAncestors('local', 'C:\\Users\\me'), [
    'C:\\',
    'C:\\Users',
    'C:\\Users\\me',
  ]);
  assert.deepEqual(sftpTreeAncestors('local', '\\\\server\\share\\folder'), [
    '\\\\server\\share',
    '\\\\server\\share\\folder',
  ]);
  assert.deepEqual(sftpTreeAncestors('local', ''), []);
  let state = revealSftpTreePath(createSftpTree('remote'), '/var/www');
  assert.deepEqual(
    sftpTreeRows(state).map((row) => row.path),
    ['/', '/var', '/var/www'],
  );
  state = toggleSftpTreePath(state, '/var');
  assert.deepEqual(
    sftpTreeRows(state).map((row) => row.path),
    ['/', '/var'],
  );
  state = toggleSftpTreePath(state, '/var');
  assert.equal(sftpTreeRows(state).at(-1)?.path, '/var/www');
});

test('tree requests have independent correlations and ignore invalidated responses', () => {
  let state = revealSftpTreePath(createSftpTree('remote'), '/var');
  state = beginSftpTreeRequest(state, '/', 'root');
  state = beginSftpTreeRequest(state, '/var', 'var');
  const entry = (name: string, isDirectory = true) => ({ name, fullPath: `/${name}`, isDirectory });
  assert.equal(finishSftpTreeRequest(state, '/', 'stale', []), state);
  state = finishSftpTreeRequest(state, '/', 'root', [
    entry('z'),
    entry('a'),
    entry('a'),
    entry('file', false),
    entry('self'),
  ]);
  assert.deepEqual(
    state.nodes['/'].children.map((child) => child.name),
    ['z', 'a', 'a', 'self'],
  );
  assert.deepEqual(
    sftpTreeRows(state).map((row) => row.path),
    ['/', '/a', '/self', '/var', '/z'],
  );
  state = finishSftpTreeRequest(state, '/var', 'var', [], 'Permission denied');
  assert.equal(state.nodes['/var'].status, 'failed');
  assert.equal(sftpTreeRows(state).find((row) => row.path === '/var')?.error, 'Permission denied');
  state = invalidateSftpTree(state);
  assert.equal(state.nodes['/'].status, 'idle');
  assert.equal(state.nodes['/'].children.length, 4);
  assert.equal(finishSftpTreeRequest(state, '/var', 'var', []), state);
  state = beginSftpTreeRequest(state, '/new', 'new');
  state = finishSftpTreeRequest(state, '/new', 'new', []);
  state = toggleSftpTreePath(state, '/new2');
  assert.equal(state.nodes['/new2'].status, 'idle');
});

test('tree caches, directory listings and expansion remain bounded during long browsing sessions', () => {
  let state = revealSftpTreePath(createSftpTree('remote'), '/');
  for (let index = 0; index < sftpTreeCacheLimit * 3; index++)
    state = revealSftpTreePath(state, `/folder-${index}`);
  assert.ok(Object.keys(state.nodes).length <= sftpTreeCacheLimit);
  assert.ok(state.expanded.length <= sftpTreeCacheLimit);
  assert.ok(state.nodes[state.path]);
  state = beginSftpTreeRequest(state, '/', 'root');
  state = finishSftpTreeRequest(
    state,
    '/',
    'root',
    Array.from({ length: 5000 }, (_, index) => ({
      fullPath: `/dir-${index}`,
      name: `dir-${index}`,
      isDirectory: true,
    })),
  );
  assert.equal(state.nodes['/'].children.length, 4096);
  assert.equal(sftpTreeRows(state).length, 4096);
  const deep = '/' + Array(300).fill('folder').join('/');
  assert.equal(sftpTreeAncestors('remote', deep).length, 256);
  assert.ok(sftpTreeRows(revealSftpTreePath(createSftpTree('remote'), deep)).length <= 256);
  assert.deepEqual(sftpTreeRows(createSftpTree('local')), []);
});

test('Commander shortcuts respect text editing, modifiers and application scope', () => {
  const expected = {
    Tab: 'switch',
    Backspace: 'up',
    F5: 'copy',
    F2: 'rename',
    F7: 'mkdir',
    Delete: 'delete',
    F4: 'edit',
  };
  for (const [key, action] of Object.entries(expected)) {
    assert.equal(sftpShortcut({ key }, false), action);
    assert.equal(sftpShortcut({ key }, true), undefined);
  }
  assert.equal(sftpShortcut({ key: 'ArrowUp', altKey: true }, false), 'up');
  assert.equal(sftpShortcut({ key: 'R', ctrlKey: true }, false), 'refresh');
  assert.equal(sftpShortcut({ key: 'r', metaKey: true }, false), 'refresh');
  assert.equal(sftpShortcut({ key: 'F5', ctrlKey: true }, false), undefined);
  assert.equal(sftpShortcut({ key: 'F5', altKey: true }, false), undefined);
  assert.equal(sftpShortcut({ key: 'F6' }, false), undefined);
  assert.equal(sftpShortcut({ key: 'Escape' }, false), undefined);
});

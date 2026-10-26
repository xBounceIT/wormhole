import assert from 'node:assert/strict';
import test from 'node:test';
import {
  beginSftpTreeRequest,
  createSftpTree,
  filterSftpTreeRows,
  finishSftpTreeRequest,
  invalidateSftpTree,
  revealSftpTreePath,
  sftpShortcut,
  sftpTreeCacheLimit,
  sftpTreeRows,
  toggleSftpTreePath,
} from '../src/sftp-tree-state.ts';
import { isSftpPathWithin } from '../src/sftp-state.ts';

test('the current directory is the tree root, without ancestor reads or sibling branches', () => {
  let state = revealSftpTreePath(createSftpTree('remote'), '/home/ubuntu');
  assert.deepEqual(Object.keys(state.nodes), ['/home/ubuntu']);
  assert.deepEqual(state.expanded, ['/home/ubuntu']);
  assert.equal(
    toggleSftpTreePath(state, '/home'),
    state,
    'Expansion cannot escape the current root',
  );
  assert.deepEqual(
    sftpTreeRows(state).map((row) => row.path),
    ['/home/ubuntu'],
  );
  state = beginSftpTreeRequest(state, '/home/ubuntu', 'current');
  state = finishSftpTreeRequest(state, '/home/ubuntu', 'current', [
    { name: '.ssh', fullPath: '/home/ubuntu/.ssh', isDirectory: true },
    { name: 'other', fullPath: '/home/other', isDirectory: true },
  ]);
  assert.deepEqual(
    sftpTreeRows(state).map((row) => row.path),
    ['/home/ubuntu', '/home/ubuntu/.ssh'],
  );
  state = toggleSftpTreePath(state, '/home/ubuntu/.ssh');
  state = revealSftpTreePath(state, '/var/www');
  assert.deepEqual(state.expanded, ['/var/www']);
  assert.deepEqual(
    sftpTreeRows(state).map((row) => row.path),
    ['/var/www'],
  );
  state = revealSftpTreePath(state, '/home/ubuntu');
  assert.deepEqual(
    sftpTreeRows(state).map((row) => row.path),
    ['/home/ubuntu', '/home/ubuntu/.ssh'],
  );
});

test('rooted trees preserve POSIX, Windows drive and UNC path semantics', () => {
  for (const [pane, path, name] of [
    ['remote', '/var/www/site', 'site'],
    ['remote', '/', '/'],
    ['remote', '///', '///'],
    ['local', 'C:\\Users\\me', 'me'],
    ['local', 'C:/', 'C:/'],
    ['local', '\\\\server\\share\\folder', 'folder'],
    ['local', '\\\\server\\share', '\\\\server\\share'],
    ['local', '/tmp/a\\b', 'a\\b'],
  ] as const) {
    let state = revealSftpTreePath(createSftpTree(pane), path);
    assert.deepEqual(
      sftpTreeRows(state).map((row) => [row.path, row.name, row.depth]),
      [[path, name, 0]],
    );
    assert.deepEqual(state.expanded, [path]);
    state = toggleSftpTreePath(state, path);
    assert.equal(sftpTreeRows(state)[0].expanded, false);
    state = toggleSftpTreePath(state, path);
    assert.equal(sftpTreeRows(state)[0].expanded, true);
    state = revealSftpTreePath(state, '');
    assert.deepEqual(state.expanded, []);
    assert.deepEqual(sftpTreeRows(state), []);
  }
  for (const [pane, root, child, expected] of [
    ['remote', '/', '/home', true],
    ['remote', '/home/ubuntu/', '/home/ubuntu/.ssh', true],
    ['remote', '/home/ubuntu', '/home/ubuntu2', false],
    ['remote', '/Home', '/home/child', false],
    ['remote', '/tmp/a\\b', '/tmp/a\\b/child', true],
    ['local', 'C:\\Users\\me', 'c:/users/ME/.ssh', true],
    ['local', 'C:\\', 'c:\\Users', true],
    ['local', '\\\\server\\share', '\\\\SERVER\\SHARE\\child', true],
    ['local', '\\\\server\\share', '\\\\server\\share2\\child', false],
    ['local', '/home/me', '/home/me2', false],
    ['local', '', '/child', false],
    ['remote', '/', '', false],
    ['local', 'relative', 'relative/child', false],
    ['remote', '/', 'C:\\folder', false],
  ] as const)
    assert.equal(isSftpPathWithin(pane, root, child), expected);
});

test('tree requests have independent correlations and ignore invalidated responses', () => {
  let state = revealSftpTreePath(createSftpTree('remote'), '/');
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
    entry('var'),
  ]);
  assert.deepEqual(
    state.nodes['/'].children.map((child) => child.name),
    ['z', 'a', 'a', 'self', 'var'],
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
  assert.equal(state.nodes['/'].children.length, 5);
  assert.equal(finishSftpTreeRequest(state, '/var', 'var', []), state);
  state = beginSftpTreeRequest(state, '/new', 'new');
  state = finishSftpTreeRequest(state, '/new', 'new', []);
  state = toggleSftpTreePath(state, '/new2');
  assert.equal(state.nodes['/new2'].status, 'idle');
});

test('tree rows retain directory modification dates without inventing ancestor metadata', () => {
  let state = revealSftpTreePath(createSftpTree('remote'), '/home/ubuntu');
  const date = '2026-10-25T10:30:00Z';
  state = beginSftpTreeRequest(state, '/home', 'home');
  state = finishSftpTreeRequest(state, '/home', 'home', [
    { name: 'ubuntu', fullPath: '/home/ubuntu', isDirectory: true, lastModifiedUtc: date },
  ]);
  assert.equal(
    sftpTreeRows(state).find((row) => row.path === '/home/ubuntu')?.lastModifiedUtc,
    date,
  );
  assert.equal(sftpTreeRows(state).find((row) => row.path === '/')?.lastModifiedUtc, undefined);
  assert.equal(sftpTreeRows(state).find((row) => row.path === '/home')?.lastModifiedUtc, undefined);
  state = invalidateSftpTree(state);
  assert.equal(sftpTreeRows(state).at(-1)?.lastModifiedUtc, date);
  state = beginSftpTreeRequest(state, '/home', 'refresh');
  state = finishSftpTreeRequest(state, '/home', 'refresh', [
    { name: 'ubuntu', fullPath: '/home/ubuntu', isDirectory: true },
  ]);
  assert.equal(sftpTreeRows(state).at(-1)?.lastModifiedUtc, undefined);
});

test('tree search preserves matching folders and their ancestors without changing expansion', () => {
  let state = revealSftpTreePath(createSftpTree('remote'), '/home/ubuntu');
  for (const [path, names] of [
    ['/', ['home', 'opt']],
    ['/home', ['ubuntu', 'guest']],
    ['/home/ubuntu', ['.cache', '.ssh']],
  ] as const) {
    state = beginSftpTreeRequest(state, path, path);
    state = finishSftpTreeRequest(
      state,
      path,
      path,
      names.map((name) => ({
        name,
        fullPath: `${path === '/' ? '' : path}/${name}`,
        isDirectory: true,
      })),
    );
  }
  const rows = sftpTreeRows(state);
  const snapshot = structuredClone(state);
  assert.equal(filterSftpTreeRows(rows, '  '), rows);
  assert.deepEqual(
    filterSftpTreeRows(rows, ' .SSH ').map((row) => row.path),
    ['/home/ubuntu', '/home/ubuntu/.ssh'],
  );
  assert.deepEqual(
    filterSftpTreeRows(rows, 'guest').map((row) => row.path),
    [],
  );
  assert.deepEqual(
    filterSftpTreeRows(rows, 'opt').map((row) => row.path),
    [],
  );
  assert.deepEqual(filterSftpTreeRows(rows, 'missing'), []);
  assert.deepEqual(filterSftpTreeRows([], 'missing'), []);
  assert.deepEqual(state, snapshot, 'Filtering must preserve cached entries and expansion');
  state = toggleSftpTreePath(state, '/home/ubuntu');
  assert.deepEqual(filterSftpTreeRows(sftpTreeRows(state), '.ssh'), []);
  assert.equal(filterSftpTreeRows(rows, '').length, rows.length);
});

test('tree name and date sorting preserve hierarchy, filters and real directory metadata', () => {
  let state = revealSftpTreePath(createSftpTree('remote'), '/parent');
  const entry = (parent: string, name: string, lastModifiedUtc?: string) => ({
    name,
    fullPath: `${parent}/${name}`,
    isDirectory: true,
    size: 0,
    lastModifiedUtc,
  });
  const children = [
    entry('/parent', 'zulu', '2026-10-24T12:00:00Z'),
    entry('/parent', 'Beta', '2026-10-25T12:00:00Z'),
    entry('/parent', 'alpha', '2026-10-25T12:00:00Z'),
    entry('/parent', 'missing'),
    entry('/parent', 'invalid', 'not a date'),
  ];
  state = beginSftpTreeRequest(state, '/parent', 'parent');
  state = finishSftpTreeRequest(state, '/parent', 'parent', children);
  state = toggleSftpTreePath(state, '/parent/zulu');
  state = beginSftpTreeRequest(state, '/parent/zulu', 'zulu');
  state = finishSftpTreeRequest(state, '/parent/zulu', 'zulu', [
    entry('/parent/zulu', 'small', '2026-10-23T12:00:00Z'),
    entry('/parent/zulu', 'large', '2026-10-26T12:00:00Z'),
  ]);
  const snapshot = structuredClone(state);
  const names = (column: 'name' | 'modified', ascending: boolean, depth = 1) =>
    sftpTreeRows(state, column, ascending)
      .filter((row) => row.depth === depth)
      .map((row) => row.name);
  assert.deepEqual(names('name', true), ['alpha', 'Beta', 'invalid', 'missing', 'zulu']);
  assert.deepEqual(names('name', false), ['zulu', 'missing', 'invalid', 'Beta', 'alpha']);
  assert.deepEqual(names('modified', true), ['invalid', 'missing', 'zulu', 'alpha', 'Beta']);
  assert.deepEqual(names('modified', false), ['alpha', 'Beta', 'zulu', 'invalid', 'missing']);
  assert.deepEqual(names('modified', false, 2), ['large', 'small']);
  const sorted = sftpTreeRows(state, 'name', false);
  assert.deepEqual(
    sorted.slice(0, 4).map((row) => row.path),
    ['/parent', '/parent/zulu', '/parent/zulu/small', '/parent/zulu/large'],
  );
  assert.deepEqual(
    filterSftpTreeRows(sorted, 'large').map((row) => row.path),
    ['/parent', '/parent/zulu', '/parent/zulu/large'],
  );
  assert.deepEqual(
    state,
    snapshot,
    'Sorting must preserve expansion, cached ordering and metadata',
  );
});

test('tree caches, directory listings and expansion remain bounded during long browsing sessions', () => {
  let state = revealSftpTreePath(createSftpTree('remote'), '/');
  for (let index = 0; index < sftpTreeCacheLimit * 3; index++)
    state = revealSftpTreePath(state, `/folder-${index}`);
  assert.ok(Object.keys(state.nodes).length <= sftpTreeCacheLimit);
  assert.ok(state.expanded.length <= sftpTreeCacheLimit);
  assert.ok(state.nodes[state.path]);
  state = revealSftpTreePath(state, '/');
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
  assert.deepEqual(
    sftpTreeRows(revealSftpTreePath(createSftpTree('remote'), deep)).map((row) => row.path),
    [deep],
  );
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

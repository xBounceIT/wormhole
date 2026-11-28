import assert from 'node:assert/strict';
import test from 'node:test';
import { SharedSftpSession, type SharedFileAPI } from '../src/shared-sftp-session.ts';
const tick = async () => {
  for (let i = 0; i < 3; i++) await new Promise<void>((r) => setImmediate(r));
};
function fixture(overrides: Record<string, unknown> = {}) {
  const calls: { name: string; args: any[] }[] = [];
  let changed = 0;
  const api: any = Object.fromEntries(
    [
      'openSftpBrowser',
      'listSftpDirectory',
      'listLocalSftpDirectory',
      'operateSftp',
      'startSftpTransfer',
      'decideSftpConflict',
      'cancelSftpTransfer',
    ].map((name) => [
      name,
      async (...args: any[]) => {
        calls.push({ name, args });
      },
    ]),
  );
  Object.assign(api, overrides);
  const files = new SharedSftpSession('session', api as SharedFileAPI, () => {
    changed++;
  });
  const receive = (value: any) => files.receive({ sessionId: 'session', ...value });
  const ready = (pane: 'remote' | 'local', path: string) =>
    receive({
      type: pane === 'remote' ? 'sftp.ready' : 'sftp.local.ready',
      requestId: pane === 'remote' ? files.state.requestId : files.state.local?.requestId,
      path,
      entries: [{ name: 'file', path: path + '/file', isDirectory: false, size: 3 }],
      truncated: false,
    });
  const transfer = (state: string, id: string, itemId?: string, extra = {}) =>
    receive({ type: 'sftp.transfer', transferId: id, transferState: state, itemId, ...extra });
  return {
    files,
    calls,
    api,
    receive,
    ready,
    transfer,
    get changed() {
      return changed;
    },
  };
}
const items = [{ sourcePath: '/file', name: 'file', isDirectory: false, size: 3 }];

test('shared files correlate remote/local navigation and ignore foreign and stale replies', async () => {
  const f = fixture();
  f.files.start();
  await tick();
  assert.equal(f.calls[0].name, 'openSftpBrowser');
  assert.equal(f.calls[1].name, 'listLocalSftpDirectory');
  const initial = f.files.state.requestId;
  f.receive({ type: 'sftp.opening', requestId: 'stale' });
  f.receive({ type: 'sftp.opening', requestId: initial });
  f.ready('remote', '/remote');
  f.ready('local', '/local');
  assert.equal(f.files.path('remote'), '/remote');
  assert.equal(f.files.path('local'), '/local');
  f.files.navigate('remote', '/next');
  f.files.navigate('local', '/next-local');
  const current = f.files.state;
  f.receive({
    type: 'sftp.ready',
    requestId: initial,
    path: '/stale',
    entries: [],
    truncated: false,
  });
  f.receive({
    type: 'sftp.local.ready',
    requestId: 'stale',
    path: '/stale',
    entries: [],
    truncated: false,
  });
  f.receive({
    type: 'sftp.ready',
    sessionId: 'other',
    requestId: current.requestId,
    path: '/other',
  });
  assert.equal(f.files.state, current);
  f.receive({ type: 'sftp.error', requestId: current.requestId, error: 'private' });
  f.receive({ type: 'sftp.local.error', requestId: current.local?.requestId, error: 'private' });
  assert.equal(f.files.state.status, 'failed');
  assert.equal(f.files.path('remote'), '/remote');
  assert.equal(f.files.path('local'), '/local');
  assert.doesNotMatch(JSON.stringify(f.files.state), /private/);
  f.files.navigate('remote', '/last');
  f.ready('remote', '/last');
  f.files.navigate('local', '/last-local');
  f.receive({
    type: 'sftp.local.ready',
    requestId: f.files.state.local?.requestId,
    path: '/last-local',
    entries: [],
    truncated: true,
    quickPaths: [{ label: 'Home', path: '/home' }],
  });
  assert.equal(f.files.state.local?.quickPaths?.length, 1);
  f.files.navigate('local', '/again');
  f.ready('local', '/again');
  assert.equal(f.files.state.local?.quickPaths?.length, 1);
  f.receive({ type: 'ready' });
  await tick();
  assert.equal(f.calls.filter((c) => c.name === 'listSftpDirectory').length, 2);
  f.files.dispose();
});

test('bridge failures are generic, request-scoped, and survive synchronous throws', async () => {
  for (const method of ['openSftpBrowser', 'listSftpDirectory', 'listLocalSftpDirectory']) {
    const f = fixture({
      [method]: () => {
        throw Error('secret')!;
      },
    });
    f.files.start();
    await tick();
    if (method === 'openSftpBrowser') assert.equal(f.files.state.status, 'failed');
    else if (method === 'listSftpDirectory') {
      f.files.navigate('remote', '/bad');
      await tick();
      assert.equal(f.files.state.status, 'failed');
    } else assert.equal(f.files.state.local?.status, 'failed');
    assert.doesNotMatch(JSON.stringify(f.files.state), /secret/);
    f.files.dispose();
  }
  const f = fixture({
    openSftpBrowser: async () => {
      throw Error('private');
    },
  });
  f.files.start();
  f.files.navigate('remote', '/new');
  await tick();
  assert.notEqual(f.files.state.error, 'Could not open file transfer.');
  f.files.dispose();
});

test('file operations refresh the original pane and do not apply unknown or duplicate completions', async () => {
  const f = fixture();
  f.files.start();
  await tick();
  f.ready('remote', '/remote');
  f.ready('local', '/local');
  f.files.operate('remote', 'rename', '/remote/file', '/remote/new');
  await tick();
  const request = f.calls.find((c) => c.name === 'operateSftp')!.args[1];
  assert.equal(request.destinationPath, '/remote/new');
  const before = f.files.state;
  f.receive({ type: 'sftp.operation', requestId: 'other', pane: 'remote' });
  f.receive({ type: 'sftp.operation', requestId: request.requestId, pane: 'local' });
  assert.equal(f.files.state, before);
  f.receive({ type: 'sftp.operation', requestId: request.requestId, pane: 'remote' });
  assert.equal(f.files.state.refreshRequests?.remote?.path, '/remote');
  assert.equal(f.files.state.status, 'opening');
  const done = f.files.state;
  f.receive({ type: 'sftp.operation', requestId: request.requestId, pane: 'remote' });
  assert.equal(f.files.state, done);
  f.files.operate('local', 'file', '/local/new');
  await tick();
  const local = f.calls.filter((c) => c.name === 'operateSftp').at(-1)!.args[1];
  f.files.navigate('local', '/away');
  f.ready('local', '/away');
  f.receive({ type: 'sftp.operation', requestId: local.requestId, pane: 'local' });
  assert.equal(f.files.path('local'), '/away');
  assert.equal(f.files.state.refreshRequests?.local?.path, '/local');
  f.api.operateSftp = () => {
    throw Error('secret');
  };
  f.files.operate('local', 'delete', '/away/x');
  await tick();
  assert.equal(f.files.state.transferError, 'File operation failed.');
  f.files.clearError();
  assert.equal(f.files.state.transferError, undefined);
  f.files.dispose();
});

test('file request bounds are released by terminal completions', async () => {
  const f = fixture();
  for (let i = 0; i < 70; i++) f.files.operate('local', 'mkdir', '/x');
  await tick();
  const ops = f.calls.filter((c) => c.name === 'operateSftp');
  assert.equal(ops.length, 64);
  f.receive({
    type: 'sftp.operation',
    requestId: ops[0].args[1].requestId,
    pane: 'local',
    error: 'private',
  });
  f.files.operate('local', 'open', '/x');
  await tick();
  assert.equal(f.calls.filter((c) => c.name === 'operateSftp').length, 65);
  f.files.transfer('local-to-remote', '/dest', []);
  for (let i = 0; i < 40; i++) f.files.transfer('local-to-remote', '/dest', items);
  await tick();
  const transfers = f.calls.filter((c) => c.name === 'startSftpTransfer');
  assert.equal(transfers.length, 32);
  f.transfer('batch-cancelled', transfers[0].args[1].transferId);
  f.files.transfer('remote-to-local', '/dest', items);
  await tick();
  assert.equal(f.calls.filter((c) => c.name === 'startSftpTransfer').length, 33);
  f.files.dispose();
});

test('transfers snapshot input, correlate conflict decisions and retain progress metadata', async () => {
  const f = fixture();
  const borrowed = [{ ...items[0] }];
  f.files.transfer('local-to-remote', '/dest', borrowed);
  borrowed[0].name = 'mutated';
  await tick();
  const request = f.calls[0].args[1],
    id = request.transferId;
  assert.equal(request.items[0].name, 'file');
  const old = f.files.state;
  f.receive({ type: 'sftp.conflict', transferId: 'unknown' });
  f.transfer('progress', 'unknown', 'item');
  assert.equal(f.files.state, old);
  f.transfer('running', id, 'item', {
    displayName: 'file',
    expectedBytes: 20,
    bytesTransferred: 0,
  });
  f.transfer('progress', id, 'item', { bytesTransferred: 10 });
  assert.equal(f.files.state.transfers?.[0].displayName, 'file');
  assert.equal(f.files.state.transfers?.[0].expectedBytes, 20);
  assert.equal(f.files.state.transfers?.[0].bytesTransferred, 10);
  f.receive({
    type: 'sftp.conflict',
    transferId: id,
    itemId: 'item',
    path: '/dest/file',
    displayName: 'file',
    direction: 'local-to-remote',
    incomingSize: 20,
    existingSize: 3,
    existingIsDirectory: false,
  });
  f.files.decide('unknown', 'item', 'skip', false);
  f.files.decide(id, 'wrong', 'skip', false);
  assert.equal(f.calls.length, 1);
  f.files.decide(id, 'item', 'overwrite', true);
  await tick();
  assert.equal(f.files.state.conflict, undefined);
  assert.equal(f.calls.at(-1)?.name, 'decideSftpConflict');
  f.files.cancel('unknown');
  f.files.cancel(id, 'item');
  await tick();
  assert.equal(f.calls.at(-1)?.name, 'cancelSftpTransfer');
  f.transfer('failed', id, 'item', { error: 'secret' });
  assert.equal(f.files.state.transfers?.[0].error, 'File transfer failed.');
  f.transfer('batch-failed', id);
  assert.equal(f.files.state.transferError, 'File transfer failed.');
  const done = f.files.state;
  f.transfer('progress', id, 'item');
  assert.equal(f.files.state, done);
  f.files.removeTransfer(id, 'item');
  assert.equal(f.files.state.transfers?.length, 0);
  f.files.clearError();
  assert.equal(f.files.state.transferError, undefined);
  f.files.dispose();
});

test('successful batches refresh only the matching destination and preserve independent conflicts', async () => {
  const f = fixture();
  f.files.start();
  await tick();
  f.ready('remote', '/dest');
  f.ready('local', '/local');
  for (const [direction, path, pane] of [
    ['local-to-remote', '/dest', 'remote'],
    ['remote-to-local', '/local', 'local'],
    ['local-to-local', '/elsewhere', 'local'],
  ] as const) {
    f.files.transfer(direction, path, items);
    await tick();
    const id = f.calls.filter((c) => c.name === 'startSftpTransfer').at(-1)!.args[1].transferId;
    f.transfer('completed', id, 'item');
    f.transfer('batch-completed', id);
    assert.equal(f.files.state.transfers?.at(-1)?.state, 'completed');
    if (path !== '/elsewhere') {
      assert.equal(f.files.state.refreshRequests?.[pane]?.path, path);
      f.ready(pane, path);
    } else assert.notEqual(f.files.state.refreshRequests?.local?.path, path);
  }
  f.files.transfer('local-to-remote', '/dest', items);
  f.files.transfer('remote-to-local', '/local', items);
  await tick();
  const last = f.calls
    .filter((c) => c.name === 'startSftpTransfer')
    .slice(-2)
    .map((c) => c.args[1].transferId);
  f.receive({ type: 'sftp.conflict', transferId: last[0], itemId: 'one' });
  f.transfer('batch-cancelled', last[1]);
  assert.equal(f.files.state.conflict?.transferId, last[0]);
  f.transfer('batch-cancelled', last[0]);
  assert.equal(f.files.state.conflict, undefined);
  f.files.dispose();
});

test('batch failure settles unfinished rows and transfer rows remain bounded', async () => {
  const f = fixture();
  f.files.transfer('remote-to-local', '/dest', items);
  await tick();
  const id = f.calls[0].args[1].transferId;
  f.transfer('progress', id);
  for (let i = 0; i < 260; i++) f.transfer('running', id, String(i));
  assert.equal(f.files.state.transfers?.length, 256);
  f.transfer('completed', id, '0');
  f.transfer('running', id, 'new');
  assert.equal(f.files.state.transfers?.length, 256);
  assert.equal(
    f.files.state.transfers?.some((r) => r.itemId === '0'),
    false,
  );
  f.transfer('batch-cancelled', id);
  assert.equal(
    f.files.state.transfers?.every((r) => r.state === 'cancelled'),
    true,
  );
  f.files.dispose();
  const rejected = fixture({
    startSftpTransfer: () => {
      throw Error('private');
    },
  });
  rejected.files.transfer('local-to-local', '/dest', items);
  await tick();
  assert.equal(rejected.files.state.transferError, 'File transfer failed.');
  rejected.files.dispose();
});

test('conflict and cancellation failures are generic and disposed callbacks cannot publish', async () => {
  const f = fixture({
    decideSftpConflict: async () => {
      throw Error('secret');
    },
    cancelSftpTransfer: async () => {
      throw Error('secret');
    },
  });
  f.files.transfer('local-to-remote', '/dest', items);
  await tick();
  const id = f.calls[0].args[1].transferId;
  f.receive({ type: 'sftp.conflict', transferId: id, itemId: 'item' });
  f.files.decide(id, 'item', 'skip', false);
  await tick();
  assert.equal(f.files.state.transferError, 'Could not apply the conflict choice.');
  f.files.cancel(id);
  await tick();
  assert.equal(f.files.state.transferError, 'Could not cancel the transfer.');
  f.files.dispose();
  const changed = f.changed;
  f.files.start();
  f.files.navigate('remote', '/after');
  f.files.operate('local', 'file', '/after');
  f.files.transfer('local-to-remote', '/after', items);
  f.files.decide(id, 'item', 'skip', false);
  f.files.cancel(id);
  f.files.clearError();
  f.files.removeTransfer(id, 'item');
  f.transfer('progress', id, 'item');
  await tick();
  assert.equal(f.changed, changed);
  const queued = fixture();
  queued.files.start();
  queued.files.transfer('local-to-local', '/dest', items);
  queued.files.operate('local', 'file', '/x');
  queued.files.dispose();
  const last = queued.changed;
  await tick();
  assert.equal(queued.calls.length, 0);
  assert.equal(queued.changed, last);
});

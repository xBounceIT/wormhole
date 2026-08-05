import assert from 'node:assert/strict';
import test from 'node:test';

import {
  compareSftpEntries,
  isSftpTransferTerminal,
  nextSftpOperationRefreshRequests,
  parentLocalSftpPath,
  parentSftpPath,
  pruneSftpSelection,
  removeSftpTransferRow,
  settleSftpTransferRows,
  sftpTransferItemKey,
  shouldApplySftpClosed,
  shouldApplySftpError,
  shouldApplySftpFailure,
  shouldApplySftpReady,
  shouldFinishSftpClose,
  updateSftpTransferError,
} from '../src/sftp-state.ts';
import { hasSftpDragPayload, sftpDragDataType } from '../src/sftp-dnd.ts';

function entry(
  name: string,
  options: { directory?: boolean; size?: number; modified?: string } = {},
) {
  return {
    name,
    fullPath: `/home/operator/${name}`,
    isDirectory: options.directory ?? false,
    isSymbolicLink: false,
    size: options.size ?? 0,
    lastModifiedUtc: options.modified,
  };
}

const readyState = {
  status: 'ready' as const,
  path: '/home/operator',
  entries: [],
  truncated: false,
};

test('SFTP ignores a ready event for an older requested path', () => {
  assert.equal(
    shouldApplySftpReady({ ...readyState, status: 'opening', path: '/tmp' }, '/home'),
    false,
  );
  assert.equal(
    shouldApplySftpReady({ ...readyState, status: 'opening', path: '/tmp' }, '/tmp'),
    true,
  );
  assert.equal(shouldApplySftpReady({ ...readyState, status: 'opening', path: '' }, '/home'), true);
});

test('SFTP drag-over accepts protected custom and Explorer file payload types', () => {
  assert.equal(hasSftpDragPayload([sftpDragDataType]), true);
  assert.equal(hasSftpDragPayload(['Files']), true);
  assert.equal(hasSftpDragPayload(['text/plain']), false);
});

test('SFTP ignores a ready event for an older request at the same path', () => {
  const state = { ...readyState, status: 'opening' as const, requestId: 'remote-2' };
  assert.equal(shouldApplySftpReady(state, '/home/operator', 'remote-1'), false);
  assert.equal(shouldApplySftpReady(state, '/home/operator', 'remote-2'), true);
});

test('scoped SFTP responses may return a canonical path', () => {
  const state = {
    ...readyState,
    status: 'opening' as const,
    path: '/home/../tmp',
    requestId: 'remote-3',
  };
  assert.equal(shouldApplySftpReady(state, '/tmp', 'remote-3'), true);
  assert.equal(shouldApplySftpError(state, '/tmp', 'remote-3'), true);
});

test('SFTP ignores events after the browser starts closing', () => {
  const closing = { ...readyState, status: 'closing' as const };
  assert.equal(shouldApplySftpReady(closing, '/home/operator'), false);
  assert.equal(shouldApplySftpError(closing, '/home/operator'), false);
});

test('SFTP error events are scoped to the active requested path', () => {
  assert.equal(shouldApplySftpError({ ...readyState, status: 'opening' }, '/other'), false);
  assert.equal(shouldApplySftpError({ ...readyState, status: 'opening' }, '/home/operator'), true);
  assert.equal(shouldApplySftpError({ ...readyState, status: 'opening' }), false);
  assert.equal(
    shouldApplySftpError({ ...readyState, status: 'opening', path: '' }, '/other'),
    true,
  );
});

test('SFTP errors are ignored when their request is older than the active request', () => {
  const state = { ...readyState, status: 'opening' as const, requestId: 'remote-2' };
  assert.equal(shouldApplySftpError(state, '/home/operator', 'remote-1'), false);
  assert.equal(shouldApplySftpError(state, '/home/operator', 'remote-2'), true);
  assert.equal(shouldApplySftpError(state, '/home/operator'), false);
});

test('unscoped SFTP ready events cannot overwrite a request-scoped browser', () => {
  const state = { ...readyState, status: 'opening' as const, requestId: 'remote-2' };
  assert.equal(shouldApplySftpReady(state, '/home/operator'), false);
  assert.equal(shouldApplySftpReady(state, '/home/operator', 'remote-2'), true);
});

test('late SFTP promise failures cannot mutate a newer browser request', () => {
  assert.equal(shouldApplySftpFailure(readyState, 2, 1), false);
  assert.equal(shouldApplySftpFailure(undefined, 2, 2), false);
  assert.equal(shouldApplySftpFailure({ ...readyState, status: 'closing' }, 2, 2), false);
  assert.equal(shouldApplySftpFailure(readyState, 2, 2), true);
});

test('an active close can finish on a backend error, but not an old close', () => {
  const closing = { ...readyState, status: 'closing' as const };
  assert.equal(shouldFinishSftpClose(closing, 2, 2), true);
  assert.equal(shouldFinishSftpClose(closing, 2, 1), false);
  assert.equal(shouldFinishSftpClose(readyState, 2, 2), false);
});

test('a closed event only completes the browser that is actually closing', () => {
  assert.equal(shouldApplySftpClosed(readyState), false);
  assert.equal(shouldApplySftpClosed({ ...readyState, status: 'opening' }), false);
  assert.equal(shouldApplySftpClosed({ ...readyState, status: 'closing' }), true);
});

test('SFTP parent navigation stays within absolute POSIX paths', () => {
  assert.equal(parentSftpPath(''), '/');
  assert.equal(parentSftpPath('/'), '/');
  assert.equal(parentSftpPath('/home'), '/');
  assert.equal(parentSftpPath('/home/operator/'), '/home');
});

test('local SFTP parent navigation preserves Windows roots', () => {
  assert.equal(parentLocalSftpPath(''), '');
  assert.equal(parentLocalSftpPath('C:\\'), 'C:\\');
  assert.equal(parentLocalSftpPath('C:\\Users\\operator'), 'C:\\Users');
  assert.equal(parentLocalSftpPath('C:\\Users\\operator\\'), 'C:\\Users');
  assert.equal(parentLocalSftpPath('\\\\server\\share'), '\\\\server\\share');
  assert.equal(parentLocalSftpPath('\\\\server\\share\\'), '\\\\server\\share');
  assert.equal(parentLocalSftpPath('\\\\server\\share\\folder'), '\\\\server\\share');
});

test('SFTP transfer terminal states are stable for queue cleanup', () => {
  assert.equal(isSftpTransferTerminal('running'), false);
  assert.equal(isSftpTransferTerminal('progress'), false);
  assert.equal(isSftpTransferTerminal('completed'), true);
  assert.equal(isSftpTransferTerminal('failed'), true);
  assert.equal(isSftpTransferTerminal('cancelled'), true);
});

test('SFTP transfer errors stay attached to their originating batch', () => {
  const failed = updateSftpTransferError({}, 'transfer-a', 'permission denied');
  assert.deepEqual(failed, {
    transferError: 'permission denied',
    transferErrorTransferId: 'transfer-a',
  });
  assert.deepEqual(updateSftpTransferError(failed, 'transfer-b'), failed);
  assert.deepEqual(updateSftpTransferError(failed, 'transfer-a'), {
    transferError: undefined,
    transferErrorTransferId: undefined,
  });
});

test('batch failures terminalize every unfinished row for that transfer', () => {
  assert.deepEqual(
    settleSftpTransferRows(
      [
        {
          transferId: 'transfer-a',
          itemId: 'item-1',
          direction: 'local-to-remote',
          displayName: 'first.txt',
          expectedBytes: 10,
          bytesTransferred: 4,
          state: 'progress',
        },
        {
          transferId: 'transfer-a',
          itemId: 'item-2',
          direction: 'local-to-remote',
          displayName: 'second.txt',
          expectedBytes: 10,
          bytesTransferred: 0,
          state: 'running',
        },
        {
          transferId: 'transfer-a',
          itemId: 'item-3',
          direction: 'local-to-remote',
          displayName: 'done.txt',
          expectedBytes: 10,
          bytesTransferred: 10,
          state: 'completed',
        },
      ],
      'transfer-a',
      'failed',
      'destination unavailable',
    ),
    [
      {
        transferId: 'transfer-a',
        itemId: 'item-1',
        direction: 'local-to-remote',
        displayName: 'first.txt',
        expectedBytes: 10,
        bytesTransferred: 4,
        state: 'failed',
        error: 'destination unavailable',
      },
      {
        transferId: 'transfer-a',
        itemId: 'item-2',
        direction: 'local-to-remote',
        displayName: 'second.txt',
        expectedBytes: 10,
        bytesTransferred: 0,
        state: 'failed',
        error: 'destination unavailable',
      },
      {
        transferId: 'transfer-a',
        itemId: 'item-3',
        direction: 'local-to-remote',
        displayName: 'done.txt',
        expectedBytes: 10,
        bytesTransferred: 10,
        state: 'completed',
      },
    ],
  );
});

test('failed SFTP operations preserve pane refresh requests', () => {
  const pending = { local: { id: 'operation-1', pane: 'local' as const, path: 'C:\\Users' } };
  assert.deepEqual(
    nextSftpOperationRefreshRequests(pending, {
      id: 'operation-2',
      pane: 'local',
      path: 'C:\\Users',
      error: 'access denied',
    }),
    pending,
  );
  assert.deepEqual(
    nextSftpOperationRefreshRequests(pending, {
      id: 'operation-3',
      pane: 'local',
      path: 'C:\\Users',
    }),
    { local: { id: 'operation-3', pane: 'local', path: 'C:\\Users' } },
  );
});

test('successful SFTP operations retain refresh requests for both panes', () => {
  assert.deepEqual(
    nextSftpOperationRefreshRequests(
      { local: { id: 'operation-1', pane: 'local', path: 'C:\\Users' } },
      { id: 'operation-2', pane: 'remote', path: '/home/operator' },
    ),
    {
      local: { id: 'operation-1', pane: 'local', path: 'C:\\Users' },
      remote: { id: 'operation-2', pane: 'remote', path: '/home/operator' },
    },
  );
});

test('visible SFTP selection is pruned when a search hides the row', () => {
  const selected = new Set(['C:\\Users\\operator\\report.txt', 'C:\\Users\\operator\\notes.txt']);
  const next = pruneSftpSelection(selected, new Set(['C:\\Users\\operator\\report.txt']));

  assert.deepEqual([...next], ['C:\\Users\\operator\\report.txt']);
  assert.notStrictEqual(next, selected);
});

test('unchanged SFTP selection preserves its identity', () => {
  const selected = new Set(['C:\\Users\\operator\\report.txt']);
  assert.strictEqual(
    pruneSftpSelection(selected, new Set(['C:\\Users\\operator\\report.txt'])),
    selected,
  );
});

test('SFTP sorting keeps directories first and name ties ascending', () => {
  const entries = [
    entry('zeta.txt', { size: 5 }),
    entry('alpha.txt', { size: 5 }),
    entry('beta.txt', { size: 10 }),
    entry('folder', { directory: true, size: 1 }),
  ];
  entries.sort((left, right) => compareSftpEntries(left, right, 'size', false));

  assert.deepEqual(
    entries.map((candidate) => candidate.name),
    ['folder', 'beta.txt', 'alpha.txt', 'zeta.txt'],
  );
});

test('cancelling one SFTP row preserves the rest of its batch', () => {
  const transfers = [
    {
      transferId: 'transfer-a',
      itemId: 'item-1',
      direction: 'local-to-remote' as const,
      displayName: 'first.txt',
      expectedBytes: 10,
      bytesTransferred: 0,
      state: 'running' as const,
    },
    {
      transferId: 'transfer-a',
      itemId: 'item-2',
      direction: 'local-to-remote' as const,
      displayName: 'second.txt',
      expectedBytes: 10,
      bytesTransferred: 0,
      state: 'running' as const,
    },
  ];
  assert.deepEqual(
    removeSftpTransferRow(transfers, 'transfer-a', 'item-1').map((item) => item.itemId),
    ['item-2'],
  );
  assert.equal(sftpTransferItemKey('transfer-a', 'item-1'), 'transfer-a\u0000item-1');
});

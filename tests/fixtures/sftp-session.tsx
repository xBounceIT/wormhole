import * as React from 'react';
import { createRoot } from 'react-dom/client';
import { SftpBrowserSurface } from '../../src/components/SftpBrowser';
import {
  SftpEditorSettings,
  SftpEditedFiles,
  SftpRecoveryNotice,
} from '../../src/components/SftpEditors';
import { TooltipProvider } from '../../src/components/ui/tooltip';
declare const assert: typeof import('node:assert/strict');

export async function runSftpSessionTests() {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  const root = createRoot(document.getElementById('root')!);
  const listeners = new Set<(event: WormholeSshEvent) => void>();
  const transfers: unknown[][] = [],
    navigations: string[] = [],
    actions: WormholeSftpEditRequest[] = [];
  let settings: WormholeSftpEditorSettings = {
    editors: [
      { id: 'code', name: 'Code', executable: 'code', arguments: ['{file}'], patterns: '*.conf' },
    ],
    defaultEditor: 'code',
    maxFileSize: 52428800,
    swapPanels: false,
  };
  const treeRequests: string[] = [];
  const treeFailures: Array<'reply' | 'reject'> = [];
  let files: WormholeSftpEditView[] = [];
  let editFailure = '';
  const emit = (event: WormholeSshEvent) => {
    for (const listener of listeners) listener(event);
  };
  window.confirm = () => true;
  window.wormhole = {
    readSftpEditorSettings: async () => settings,
    writeSftpEditorSettings: async (next) => {
      settings = next;
      return { updated: true };
    },
    onSshEvent: (listener) => {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    listSftpTree: async (sessionId, pane, path, requestId) => {
      treeRequests.push(`${pane}:${path}`);
      const failure = treeFailures.shift();
      if (failure === 'reject') throw new Error('Tree request rejected');
      if (failure === 'reply') {
        queueMicrotask(() =>
          emit({
            type: 'sftp.local.error',
            sessionId,
            requestId,
            pane: 'local',
            path,
            error: 'Tree permission denied',
          }),
        );
        return;
      }
      queueMicrotask(() =>
        emit(
          pane === 'local'
            ? {
                type: 'sftp.local.ready',
                sessionId,
                pane,
                requestId,
                path,
                truncated: false,
                entries: [
                  {
                    name: 'child',
                    fullPath: `${path}/child`,
                    isDirectory: true,
                    isSymbolicLink: false,
                    size: 0,
                  },
                ],
              }
            : { type: 'sftp.ready', sessionId, requestId, path, truncated: false, entries: [] },
        ),
      );
    },
    sftpEdit: async (sessionId, request) => {
      actions.push(request);
      if (request.operation === 'start' && editFailure) {
        const error = editFailure;
        editFailure = '';
        return { type: 'sftp.edit', sessionId, edits: files, error };
      }
      if (request.operation === 'start')
        files = [
          {
            id: 'edit',
            sessionId,
            nodeId: 'node',
            name: 'file.conf',
            remotePath: request.path!,
            editor: 'Code',
            state: 'Watching',
            pending: false,
            recovered: false,
          },
        ];
      if (request.operation === 'upload')
        files = files.map((file) => ({
          ...file,
          state:
            request.decision === 'overwrite' || request.destinationPath ? 'Uploaded' : 'Conflict',
          pending: !request.decision && !request.destinationPath,
          uploadedAt: '2026-10-25T10:30:00Z',
        }));
      if (request.operation === 'reload')
        files = files.map((file) => ({ ...file, state: 'Watching', pending: false }));
      if (request.operation === 'recover')
        files = files.map((file) => ({ ...file, sessionId, recovered: false }));
      if (request.operation === 'stop' || request.operation === 'discard') files = [];
      const event: WormholeSftpEditEvent = {
        type: 'sftp.edit',
        sessionId,
        requestId: crypto.randomUUID(),
        edits: files,
      };
      queueMicrotask(() => emit(event));
      return event;
    },
  } as NonNullable<Window['wormhole']>;
  const tick = async () => {
    await React.act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
    });
  };
  const click = async (element: Element | undefined | null) => {
    assert.ok(element, `Missing control in: ${document.body.textContent}`);
    await React.act(async () => (element as HTMLElement).click());
    await tick();
  };
  const button = (text: string) =>
    [...document.querySelectorAll('button')].find(
      (element) => element.textContent?.trim() === text,
    );
  const key = async (element: Element, value: string, options: KeyboardEventInit = {}) => {
    await React.act(async () =>
      element.dispatchEvent(
        new KeyboardEvent('keydown', { key: value, bubbles: true, cancelable: true, ...options }),
      ),
    );
    await tick();
  };
  const input = async (element: HTMLInputElement | HTMLTextAreaElement, value: string) => {
    const setter = Object.getOwnPropertyDescriptor(
      element instanceof HTMLTextAreaElement
        ? HTMLTextAreaElement.prototype
        : HTMLInputElement.prototype,
      'value',
    )!.set!;
    await React.act(async () => {
      setter.call(element, value);
      element.dispatchEvent(new Event('input', { bubbles: true }));
    });
  };
  const browser = {
    status: 'ready' as const,
    path: '/remote',
    entries: [
      {
        name: 'file.conf',
        fullPath: '/remote/file.conf',
        isDirectory: false,
        isSymbolicLink: false,
        size: 12,
      },
    ],
    truncated: false,
    local: {
      status: 'ready' as const,
      path: '/local',
      entries: [
        {
          name: 'file.conf',
          fullPath: '/local/file.conf',
          isDirectory: false,
          isSymbolicLink: false,
          size: 12,
        },
      ],
      truncated: false,
    },
    transfers: [],
  };
  const render = async (
    sftp: unknown = browser,
    host = 'server',
    backendId: string | null = 'native',
  ) => {
    await React.act(async () =>
      root.render(
        <TooltipProvider>
          <div style={{ height: 720 }}>
            <SftpBrowserSurface
              session={{
                id: 'tab',
                title: 'File transfer',
                host,
                backendSessionId: backendId ?? undefined,
                sftp: sftp as typeof browser,
              }}
              onClose={() => actions.push({ operation: 'finish-close' })}
              onNavigate={(path) => navigations.push(path)}
              onLocalNavigate={(path) => navigations.push(path)}
              onRefresh={(pane) => navigations.push(pane)}
              onOperation={() => {}}
              onTransfer={(...args) => transfers.push(args)}
              onConflict={() => {}}
              onTransferCancel={() => {}}
              onTransferErrorClear={() => {}}
              onTransferRemove={() => {}}
            />
          </div>
        </TooltipProvider>,
      ),
    );
    await tick();
  };
  await render();
  assert.ok(document.querySelector('[role="tree"]'));
  assert.equal(
    document.querySelector('dialog'),
    null,
    'File transfer must participate in the ordinary layout',
  );
  await click(document.querySelector('[data-sftp-panel="local"] [role="option"]'));
  const local = document.querySelector('[data-sftp-panel="local"]')!;
  await key(local, 'F5');
  assert.equal(transfers.length, 1);
  assert.equal(transfers[0][0], 'local-to-remote');
  await key(local, 'Tab');
  assert.equal(document.activeElement?.getAttribute('data-sftp-panel'), 'remote');
  await key(local, 'F4');
  assert.ok(actions.some((action) => action.operation === 'start'));
  await click(button('Upload now'));
  assert.ok(document.body.textContent?.includes('Conflict'));
  await click(button('Overwrite remote'));
  assert.ok(document.body.textContent?.includes('Uploaded'));
  await click(button('Upload now'));
  await click(button('Save as'));
  await input(
    document.querySelector('[aria-label="Save edited file as remote path"]')!,
    '/remote/copy.conf',
  );
  await React.act(async () =>
    document
      .querySelector('form')!
      .dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })),
  );
  await tick();
  assert.equal(actions.at(-1)?.destinationPath, '/remote/copy.conf');
  await click(button('Upload now'));
  await click(button('Re-download'));
  await click(button('Open folder'));
  await click(button('Stop editing'));
  assert.equal(document.querySelector('[aria-label="Edited files"]'), null);
  await key(local, 'Backspace');
  const beforeRefresh = treeRequests.length;
  await key(local, 'r', { ctrlKey: true });
  assert.ok(treeRequests.length > beforeRefresh, 'Refresh must invalidate directory trees too');
  assert.ok(navigations.includes('/'));
  assert.ok(navigations.includes('local'));
  await click(button('Swap panels'));
  await click(button('Queue (0)'));
  await click(button('Queue (0)'));
  const resize = document.querySelector('[aria-label="Resize local directory tree"]')!;
  await key(resize, 'ArrowDown');
  assert.equal(resize.getAttribute('aria-valuenow'), '150');
  await key(resize, 'ArrowUp');
  await React.act(async () => {
    resize.dispatchEvent(new PointerEvent('pointerdown', { clientY: 100, bubbles: true }));
    window.dispatchEvent(new PointerEvent('pointermove', { clientY: 125 }));
    window.dispatchEvent(new PointerEvent('pointerup'));
  });
  assert.equal(resize.getAttribute('aria-valuenow'), '165');
  const collapse = document.querySelector('[data-sftp-panel="local"] [aria-label^="Collapse "]')!;
  const collapseLabel = collapse.getAttribute('aria-label')!.replace('Collapse', 'Expand');
  await click(collapse);
  await click(document.querySelector(`[aria-label="${collapseLabel}"]`));
  const drop = async (element: Element, sourcePane: 'local' | 'remote', sourcePath: string) => {
    const dataTransfer = new DataTransfer();
    dataTransfer.setData(
      'application/x-wormhole-sftp-items',
      JSON.stringify({
        sourcePane,
        items: [{ name: 'drag.conf', sourcePath, isDirectory: false, size: 0 }],
      }),
    );
    await React.act(async () => {
      element.dispatchEvent(
        new DragEvent('dragover', { bubbles: true, cancelable: true, dataTransfer }),
      );
      element.dispatchEvent(
        new DragEvent('drop', { bubbles: true, cancelable: true, dataTransfer }),
      );
    });
    await tick();
  };
  const localTreeRow = document.querySelector('[data-sftp-panel="local"] [role="treeitem"]')!;
  await drop(localTreeRow, 'remote', '/remote/drag.conf');
  assert.equal(transfers.at(-1)?.[0], 'remote-to-local');
  await drop(localTreeRow, 'local', '/different/drag.conf');
  assert.equal(transfers.at(-1)?.[0], 'local-to-local');
  await drop(
    document.querySelector('[data-sftp-panel="remote"] [role="treeitem"]')!,
    'local',
    '/local/drag.conf',
  );
  assert.equal(transfers.at(-1)?.[0], 'local-to-remote');
  const beforeInvalidDrop = transfers.length;
  await drop(
    document.querySelector('[data-sftp-panel="remote"] [role="treeitem"]')!,
    'remote',
    '/remote/drag.conf',
  );
  assert.equal(transfers.length, beforeInvalidDrop);
  const remotePanel = document.querySelector('[data-sftp-panel="remote"]')!;
  await click(remotePanel.querySelector('[role="option"]'));
  await key(remotePanel, 'F5');
  assert.equal(transfers.at(-1)?.[0], 'remote-to-local');
  await key(remotePanel, 'r', { ctrlKey: true });
  const treeToggle = document.querySelector('[data-sftp-panel="local"] button[aria-pressed]');
  await click(treeToggle);
  await click(treeToggle);
  treeFailures.push('reject', 'reply');
  await click(treeToggle);
  await click(treeToggle);
  await tick();
  const failedTreeFolder =
    document.querySelector('[title="Tree permission denied"]') ??
    document.querySelector('[title="Tree request rejected"]');
  assert.ok(failedTreeFolder, 'tree errors must leave a navigable retry target');
  await click(failedTreeFolder);
  await key(local, 'F7');
  assert.ok(document.body.textContent?.includes('New folder'));
  await click(button('Cancel'));
  const beforeTransfer = treeRequests.length;
  await render({
    ...browser,
    transfers: [
      {
        transferId: 'done',
        itemId: 'folder',
        direction: 'local-to-remote',
        displayName: 'folder',
        expectedBytes: 0,
        bytesTransferred: 0,
        state: 'completed',
      },
    ],
  });
  assert.ok(
    treeRequests.length > beforeTransfer,
    'Transfers into tree targets must invalidate cached directory children',
  );
  editFailure = 'Configured editor could not start';
  await key(local, 'F4');
  assert.ok(document.body.textContent?.includes('Configured editor could not start'));
  editFailure = 'binary-file-confirmation-required';
  await key(local, 'F4');
  assert.ok(actions.some((action) => action.allowBinary));
  await render(
    {
      ...browser,
      transfers: undefined,
      transferError: 'Queue failed',
      conflict: {
        transferId: 't',
        itemId: 'i',
        direction: 'local-to-remote',
        displayName: 'file',
        path: '/remote/file',
        incomingSize: 1,
        existingSize: 2,
        existingIsDirectory: false,
      },
    },
    '',
    null,
  );
  await click(button('Skip'));
  await render({
    ...browser,
    status: 'failed',
    error: 'Permission denied',
    transferError: 'Transfer failed',
    transfers: [
      {
        transferId: 'transfer',
        itemId: 'item',
        direction: 'remote-to-local',
        displayName: 'file',
        expectedBytes: 12,
        bytesTransferred: 6,
        state: 'progress',
      },
    ],
  });
  assert.ok(document.body.textContent?.includes('Permission denied'));
  await render({ ...browser, status: 'opening', local: undefined });
  await render({ ...browser, status: 'closing' });
  await React.act(async () => root.render(<SftpEditorSettings />));
  await tick();
  await click(button('Add editor'));
  await tick();
  const names = document.querySelectorAll<HTMLInputElement>('input[id$="-name"]');
  await input(names[names.length - 1], 'Kate');
  const executables = document.querySelectorAll<HTMLInputElement>('input[id$="-exe"]');
  await input(executables[executables.length - 1], 'kate');
  const argumentInputs = document.querySelectorAll<HTMLTextAreaElement>('textarea[id$="-args"]');
  await input(argumentInputs[argumentInputs.length - 1], '--new-window\n{file}');
  const patterns = document.querySelectorAll<HTMLInputElement>('input[id$="-patterns"]');
  await input(patterns[patterns.length - 1], '*.conf;*.txt');
  await input(document.querySelector('#sftp-edit-size')!, '75');
  await click(document.querySelector('[role="switch"]'));
  const defaultEditor = document.querySelector<HTMLSelectElement>('#sftp-default-editor')!;
  await React.act(async () => {
    defaultEditor.value = settings.editors[0].id;
    defaultEditor.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await click(button('Save editor settings'));
  assert.equal(settings.editors.at(-1)?.executable, 'kate');
  assert.deepEqual(settings.editors.at(-1)?.arguments, ['--new-window', '{file}']);
  assert.equal(settings.editors.at(-1)?.patterns, '*.conf;*.txt');
  assert.equal(settings.maxFileSize, 75 * 1048576);
  assert.equal(settings.swapPanels, true);
  await click(button('Remove'));
  files = [
    {
      id: 'recovered',
      sessionId: 'old',
      nodeId: 'node',
      name: 'file.conf',
      remotePath: '/remote/file.conf',
      editor: 'Code',
      state: 'Recovered',
      pending: true,
      recovered: true,
    },
  ];
  await React.act(async () =>
    root.render(
      <>
        <SftpRecoveryNotice />
        <SftpEditedFiles sessionId="native" />
      </>,
    ),
  );
  await tick();
  assert.ok(document.body.textContent?.includes('can be recovered'));
  await click(button('Recover'));
  await click(button('Upload now'));
  await click(button('Overwrite remote'));
  files = files.map((file) => ({ ...file, recovered: true }));
  await React.act(async () => root.render(<SftpEditedFiles sessionId="sftp-recovery" recovery />));
  await tick();
  await click(button('Discard'));
  assert.equal(files.length, 0);

  // A failed initial read must be visible rather than an unhandled rejection.
  const originalEdit = window.wormhole!.sftpEdit;
  window.wormhole!.sftpEdit = async () => {
    throw new Error('Editor inventory unavailable');
  };
  await React.act(async () => root.render(<SftpEditedFiles key="failed" sessionId="newer" />));
  await tick();
  assert.ok(
    document.querySelector('[role="alert"]')?.textContent?.includes('inventory unavailable'),
  );

  let resolveList!: (event: WormholeSftpEditEvent) => void;
  const delayedList = new Promise<WormholeSftpEditEvent>((resolve) => {
    resolveList = resolve;
  });
  window.wormhole!.sftpEdit = async () => delayedList;
  await React.act(async () => root.render(<SftpEditedFiles key="delayed" sessionId="newer" />));
  await tick();
  const latest: WormholeSftpEditView = {
    id: 'async',
    sessionId: 'newer',
    nodeId: 'node',
    name: 'latest.conf',
    remotePath: '/latest.conf',
    editor: 'Code',
    state: 'Uploaded',
    pending: false,
    recovered: false,
  };
  await React.act(async () => emit({ type: 'sftp.edit', sessionId: 'newer', edits: [latest] }));
  await React.act(async () => resolveList({ type: 'sftp.edit', sessionId: 'newer', edits: [] }));
  await tick();
  assert.ok(
    document.body.textContent?.includes('latest.conf'),
    'late initial snapshot replaced watcher state',
  );

  // A previous command must not resurrect a working copy after Stop editing.
  const pendingActions: Array<(event: WormholeSftpEditEvent) => void> = [];
  window.wormhole!.sftpEdit = async () =>
    new Promise((resolve) => {
      pendingActions.push(resolve);
    });
  await click(button('Upload now'));
  await click(button('Stop editing'));
  assert.equal(pendingActions.length, 2);
  await React.act(async () =>
    pendingActions[1]({
      type: 'sftp.edit',
      sessionId: 'newer',
      requestId: 'stop-response',
      edits: [],
    }),
  );
  await React.act(async () =>
    pendingActions[0]({
      type: 'sftp.edit',
      sessionId: 'newer',
      requestId: 'upload-response',
      edits: [latest],
    }),
  );
  await tick();
  await React.act(async () =>
    emit({ type: 'sftp.edit', sessionId: 'newer', requestId: 'upload-response', edits: [latest] }),
  );
  await tick();
  assert.ok(
    !document.body.textContent?.includes('latest.conf'),
    'late upload resurrected stopped copy',
  );

  // Recovery inventory and banner react to removal from another tab.
  window.wormhole!.sftpEdit = async (sessionId) => ({
    type: 'sftp.edit',
    sessionId,
    edits: [{ ...latest, recovered: true }],
  });
  await React.act(async () =>
    root.render(
      <>
        <SftpRecoveryNotice />
        <SftpEditedFiles key="recovery" sessionId="sftp-recovery" recovery />
      </>,
    ),
  );
  await tick();
  assert.ok(document.body.textContent?.includes('latest.conf'));
  await React.act(async () =>
    emit({ type: 'sftp.edit', requestId: 'other-tab-discard', sessionId: 'other-tab', edits: [] }),
  );
  await tick();
  assert.ok(!document.body.textContent?.includes('latest.conf'));
  assert.ok(!document.body.textContent?.includes('can be recovered'));
  window.wormhole!.sftpEdit = originalEdit;
  const originalReadSettings = window.wormhole!.readSftpEditorSettings;
  window.wormhole!.readSftpEditorSettings = async () => {
    throw new Error('Settings unavailable');
  };
  window.wormhole!.sftpEdit = async () => {
    throw new Error('Inventory unavailable');
  };
  await React.act(async () =>
    root.render(
      <>
        <SftpEditorSettings />
        <SftpRecoveryNotice />
      </>,
    ),
  );
  await tick();
  assert.ok(document.body.textContent?.includes('Settings unavailable'));
  window.wormhole!.readSftpEditorSettings = originalReadSettings;
  window.wormhole!.sftpEdit = originalEdit;
  await React.act(async () => root.unmount());
}

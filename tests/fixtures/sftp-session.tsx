import * as React from 'react';
import { createRoot } from 'react-dom/client';
import { SftpBrowserSurface, SftpFilePane } from '../../src/components/SftpBrowser';
import { SftpDirectoryTree } from '../../src/components/SftpDirectoryTree';
import { runSftpSearchTests } from './sftp-search';
import { runSftpKeyboardScopeTests } from './sftp-keyboard';
import {
  SftpEditorSettings,
  SftpEditedFiles,
  SftpRecoveryNotice,
} from '../../src/components/SftpEditors';
import { TooltipProvider } from '../../src/components/ui/tooltip';
// The launch stylesheet remains loaded after the React workspace mounts.
import '../../src/startup.css';
import '../../src/index.css';
// Compiled from the production App components by the Chromium harness.
import { SessionSurface } from 'virtual:sftp-session-surface';
declare const assert: typeof import('node:assert/strict');
declare function pressSftpSessionKey(key: string): Promise<void>;

async function runSftpTreeRequestTests(root: ReturnType<typeof createRoot>) {
  const original = window.wormhole;
  const listeners = new Set<(event: WormholeSshEvent) => void>();
  const requests: Array<{
    pane: 'local' | 'remote';
    path: string;
    requestId: string;
    resolve: () => void;
    reject: (error: Error) => void;
  }> = [];
  const active = new Map<string, (typeof requests)[number]>();
  const key = (pane: string, path: string) => `${pane}:${path}`;
  const tick = async () => React.act(async () => new Promise((resolve) => setTimeout(resolve, 20)));
  window.wormhole = {
    onSshEvent: (listener) => {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    listSftpTree: (_sessionId, pane, path, requestId) =>
      new Promise<void>((resolve, reject) => {
        const request = { pane, path, requestId, resolve, reject };
        requests.push(request);
        active.set(requestId, request);
      }),
  } as NonNullable<Window['wormhole']>;
  const render = async (revision: string) => {
    await React.act(async () =>
      root.render(
        <React.StrictMode>
          <TooltipProvider>
            <div style={{ height: 500 }}>
              {(['local', 'remote'] as const).map((pane) => (
                <SftpDirectoryTree
                  key={pane}
                  sessionId="tree-session"
                  pane={pane}
                  path={`/${pane}/home`}
                  revision={revision}
                  height={140}
                  onHeightChange={() => {}}
                  search=""
                  onSearchChange={() => {}}
                  sortColumn="name"
                  ascending={true}
                  onSort={() => {}}
                  onNavigate={() => {}}
                  onDrop={() => {}}
                />
              ))}
            </div>
          </TooltipProvider>
        </React.StrictMode>,
      ),
    );
    await tick();
  };
  const assertUniqueActivePaths = () => {
    const paths = [...active.values()].map((request) => key(request.pane, request.path));
    assert.equal(
      new Set(paths).size,
      paths.length,
      'Each pane must read a path only once at a time',
    );
  };
  const settle = (request: (typeof requests)[number], error?: string) => {
    active.delete(request.requestId);
    request.resolve();
    const event = {
      type:
        request.pane === 'local'
          ? error
            ? 'sftp.local.error'
            : 'sftp.local.ready'
          : error
            ? 'sftp.error'
            : 'sftp.ready',
      sessionId: 'tree-session',
      pane: request.pane,
      path: request.path,
      requestId: request.requestId,
      entries: [],
      truncated: false,
      error,
    } as WormholeSshEvent;
    for (const listener of listeners) listener(event);
  };
  try {
    await render('initial');
    assert.equal(requests.length, 2);
    assert.deepEqual(requests.map((request) => request.path).sort(), [
      '/local/home',
      '/remote/home',
    ]);
    await render('refresh-1');
    await render('refresh-2');
    assert.equal(
      requests.length,
      2,
      'Refreshing must wait for directory requests already in flight',
    );
    assertUniqueActivePaths();
    const rejected = [...active.values()].find(
      (request) => request.pane === 'remote' && request.path === '/remote/home',
    )!;
    await React.act(async () => {
      active.delete(rejected.requestId);
      rejected.reject(new Error('Stale tree send failed'));
    });
    await tick();
    assert.equal(
      requests.length,
      3,
      'A stale IPC failure must release its path for the queued refresh',
    );
    assertUniqueActivePaths();
    for (let wave = 0; wave < 3 && active.size; wave++) {
      await React.act(async () => {
        for (const request of [...active.values()]) settle(request);
      });
      await tick();
      assertUniqueActivePaths();
    }
    assert.equal(active.size, 0);
    assert.equal(requests.length, 4, 'Each invalidated folder must be re-read exactly once');
    await render('permission-error');
    await React.act(async () => {
      for (const request of [...active.values()])
        settle(
          request,
          request.pane === 'remote' && request.path === '/remote/home'
            ? 'Permission denied'
            : undefined,
        );
    });
    await tick();
    assert.ok(
      document.querySelector('[title="Permission denied"]'),
      'Real directory errors must remain visible',
    );
  } finally {
    await React.act(async () => root.render(null));
    window.wormhole = original;
  }
}

export async function runSftpToolbarTooltipTests() {
  const root = createRoot(document.getElementById('root')!);
  // Hidden Chromium windows may suspend exit animations and retain closed portals.
  const animations = document.createElement('style');
  animations.textContent =
    '[data-slot="tooltip-content"] { animation: none !important; transition: none !important; } ' +
    '[data-sftp-panel] button[aria-pressed] { transition: none !important; }';
  document.head.append(animations);
  const tick = async () => React.act(async () => new Promise((resolve) => setTimeout(resolve, 20)));
  const click = async (element: Element) => React.act(async () => (element as HTMLElement).click());
  const expectTooltip = async (control: HTMLElement, label: string) => {
    assert.equal(
      control.getAttribute('title'),
      null,
      'Toolbar buttons must not use native tooltips',
    );
    const bounds = control.getBoundingClientRect();
    await React.act(async () =>
      control.dispatchEvent(
        new PointerEvent('pointermove', {
          bubbles: true,
          pointerType: 'mouse',
          clientX: bounds.x + bounds.width / 2,
          clientY: bounds.y + bounds.height / 2,
        }),
      ),
    );
    await tick();
    const checkDescription = (phase: string) => {
      const content = document.getElementById(control.getAttribute('aria-describedby') ?? '');
      assert.ok(content, `Missing ${phase} tooltip for ${label}`);
      assert.equal(content.getAttribute('data-slot'), 'tooltip-content');
      assert.equal(content.textContent, label);
      assert.ok(
        !control.closest('[data-sftp-panel]')!.contains(content),
        'Tooltips must render outside clipped panes',
      );
    };
    const dismiss = async (action: () => Promise<void>) => {
      const id = control.getAttribute('aria-describedby')!;
      await action();
      for (let attempt = 0; attempt < 20 && document.getElementById(id); attempt++) await tick();
      assert.ok(
        !document.getElementById(id),
        `Tooltip must finish dismissing: ${label}, state=${control.getAttribute('data-state')}`,
      );
    };
    checkDescription('hover');
    await dismiss(async () => {
      await React.act(async () => {
        control.focus();
        control.blur();
      });
    });
    await React.act(async () => control.focus());
    await tick();
    checkDescription('focus');
    await dismiss(async () => {
      await React.act(async () =>
        control.dispatchEvent(
          new KeyboardEvent('keydown', {
            key: 'Escape',
            bubbles: true,
            cancelable: true,
          }),
        ),
      );
    });
    await React.act(async () => {
      control.blur();
      control.dispatchEvent(
        new PointerEvent('pointerout', {
          bubbles: true,
          pointerType: 'mouse',
          relatedTarget: document.body,
        }),
      );
    });
  };
  try {
    await React.act(async () =>
      root.render(
        <TooltipProvider>
          <div className="flex h-[600px] gap-4 overflow-hidden">
            {(['local', 'remote'] as const).map((pane) => (
              <SftpFilePane
                key={pane}
                pane={pane}
                state={{
                  status: 'ready',
                  path: `/${pane}`,
                  truncated: false,
                  entries: [
                    {
                      name: 'file.txt',
                      fullPath: `/${pane}/file.txt`,
                      isDirectory: false,
                      isSymbolicLink: false,
                      size: 12,
                    },
                  ],
                }}
                onNavigate={() => {}}
                onRefresh={() => {}}
                onOperation={() => {}}
                onTransfer={() => {}}
              />
            ))}
          </div>
        </TooltipProvider>,
      ),
    );
    await tick();
    for (const pane of document.querySelectorAll('[data-sftp-panel]')) {
      const kind = pane.getAttribute('data-sftp-panel');
      assert.ok(
        pane.querySelector('button[aria-label="Home"] svg.lucide-house'),
        `${kind} Home must use the house icon`,
      );
      for (const label of [`Go up in ${kind} files`, 'Home', 'Refresh', 'New folder', 'New file'])
        await expectTooltip(
          pane.querySelector<HTMLElement>(`button[aria-label="${label}"]`)!,
          label,
        );
      const tree = pane.querySelector<HTMLElement>('button[aria-pressed]')!;
      assert.ok(
        tree.querySelector('svg.lucide-folder-tree'),
        'Tree must use its dedicated folder icon',
      );
      assert.equal(tree.textContent?.trim(), '', 'Tree must be an icon button');
      assert.equal(tree.getBoundingClientRect().width, tree.getBoundingClientRect().height);
      assert.equal(tree.getAttribute('aria-pressed'), 'true');
      assert.equal(tree.getAttribute('aria-label'), 'Hide directory tree');
      const activeBackground = getComputedStyle(tree).backgroundColor;
      const activeColor = getComputedStyle(tree).color;
      await expectTooltip(tree, 'Hide directory tree');
      await click(tree);
      assert.equal(tree.getAttribute('aria-pressed'), 'false');
      assert.equal(tree.getAttribute('aria-label'), 'Show directory tree');
      assert.notEqual(
        getComputedStyle(tree).backgroundColor,
        activeBackground,
        'Active and inactive tree buttons must have distinct backgrounds',
      );
      assert.notEqual(
        getComputedStyle(tree).color,
        activeColor,
        'Active and inactive tree buttons must have distinct icon colors',
      );
      await expectTooltip(tree, 'Show directory tree');
      await click(tree);
      assert.equal(tree.getAttribute('aria-pressed'), 'true');
      assert.equal(tree.getAttribute('aria-label'), 'Hide directory tree');
      assert.equal(getComputedStyle(tree).backgroundColor, activeBackground);
      const remove = pane.querySelector<HTMLButtonElement>('button[aria-label="Delete selected"]')!;
      assert.equal(remove.disabled, true);
      await click(pane.querySelector('[role="checkbox"]')!);
      assert.equal(remove.disabled, false);
      await expectTooltip(remove, 'Delete selected');
    }
  } finally {
    await React.act(async () => root.unmount());
    animations.remove();
  }
}

async function runSftpCheckboxTests(root: ReturnType<typeof createRoot>) {
  const navigations: string[] = [];
  const copies: string[][] = [];
  const operations: string[] = [];
  const entries = (path: string) => [
    {
      name: 'folder',
      fullPath: `${path}/folder`,
      isDirectory: true,
      isSymbolicLink: false,
      size: 0,
    },
    {
      name: 'alpha.txt',
      fullPath: `${path}/alpha.txt`,
      isDirectory: false,
      isSymbolicLink: false,
      size: 12,
    },
    {
      name: 'zulu.txt',
      fullPath: `${path}/zulu.txt`,
      isDirectory: false,
      isSymbolicLink: false,
      size: 24,
    },
  ];
  const render = async (status: 'ready' | 'opening' = 'ready', bulk = false) => {
    await React.act(async () =>
      root.render(
        <TooltipProvider>
          <div className="flex h-[600px] gap-4 overflow-hidden">
            {(bulk ? (['local'] as const) : (['local', 'remote'] as const)).map((pane) => (
              <SftpFilePane
                key={pane}
                pane={pane}
                state={{
                  status,
                  path: bulk ? '/bulk' : `/${pane}`,
                  truncated: false,
                  entries: bulk
                    ? Array.from({ length: 200 }, (_, index) => ({
                        name: `file-${String(index).padStart(3, '0')}`,
                        fullPath: `/bulk/file-${String(index).padStart(3, '0')}`,
                        isDirectory: false,
                        isSymbolicLink: false,
                        size: index,
                      }))
                    : entries(`/${pane}`),
                }}
                onNavigate={(path) => navigations.push(path)}
                onRefresh={() => {}}
                onOperation={(operation, path) => operations.push(`${operation}:${path}`)}
                onTransfer={() => {}}
                onCopy={(items) => copies.push(items.map((item) => item.sourcePath))}
              />
            ))}
          </div>
        </TooltipProvider>,
      ),
    );
    await tick();
  };
  const tick = async () => React.act(async () => new Promise((resolve) => setTimeout(resolve, 20)));
  const click = async (element: Element) => React.act(async () => (element as HTMLElement).click());
  const key = async (element: Element, value: string, options: KeyboardEventInit = {}) => {
    await React.act(async () =>
      element.dispatchEvent(
        new KeyboardEvent('keydown', {
          key: value,
          bubbles: true,
          cancelable: true,
          ...options,
        }),
      ),
    );
    await tick();
  };
  const checkbox = (row: Element) => row.querySelector<HTMLElement>('[role="checkbox"]')!;
  const checked = (row: Element) => checkbox(row).getAttribute('aria-checked') === 'true';
  await render();
  for (const pane of document.querySelectorAll('[data-sftp-panel]')) {
    const [folder, alpha, zulu] = pane.querySelectorAll<HTMLElement>('[data-sftp-index]');
    assert.equal(pane.querySelectorAll('[role="checkbox"]').length, 3);
    assert.equal(checkbox(alpha).getAttribute('aria-label'), 'Select alpha.txt');
    await click(alpha);
    assert.equal(checked(alpha), false, 'Clicking a file row must not select it');
    await click(checkbox(alpha));
    await click(checkbox(zulu));
    assert.ok(checked(alpha) && checked(zulu), 'Checkbox selection is additive without Ctrl');
    const sortName = pane.querySelector<HTMLButtonElement>('[role="columnheader"] button')!;
    await click(sortName);
    assert.equal(
      sortName.closest('[role="columnheader"]')!.getAttribute('aria-sort'),
      'descending',
    );
    assert.ok(checked(alpha) && checked(zulu), 'Sorting must preserve checked paths');
    await click(sortName);
    await click(folder.querySelector('span.truncate')!);
    assert.equal(checked(folder), false, 'Clicking a folder name must not change selection');
    assert.ok(checked(alpha) && checked(zulu));
    await key(pane, 'F5');
    const prefix = `/${pane.getAttribute('data-sftp-panel')}`;
    assert.deepEqual(copies.at(-1), [`${prefix}/alpha.txt`, `${prefix}/zulu.txt`]);
    const dragged = new DataTransfer();
    await React.act(async () =>
      alpha.dispatchEvent(
        new DragEvent('dragstart', {
          bubbles: true,
          dataTransfer: dragged,
        }),
      ),
    );
    assert.deepEqual(
      JSON.parse(dragged.getData('application/x-wormhole-sftp-items')).items.map(
        (item: { sourcePath: string }) => item.sourcePath,
      ),
      [`${prefix}/alpha.txt`, `${prefix}/zulu.txt`],
    );
    await click(checkbox(alpha));
    assert.equal(checked(alpha), false);
    assert.equal(checked(zulu), true, 'Unchecking one file preserves other checked files');
    await React.act(async () =>
      checkbox(folder).dispatchEvent(
        new MouseEvent('click', {
          bubbles: true,
          shiftKey: true,
        }),
      ),
    );
    assert.ok(
      checked(folder) && checked(alpha) && checked(zulu),
      'Shift-click extends the checked range',
    );
    await key(pane, 'Escape');
    checkbox(folder).focus();
    await React.act(async () => pressSftpSessionKey(' '));
    assert.equal(checked(folder), true, 'Space must toggle the focused checkbox');
    assert.equal(navigations.length, 0, 'Checking a folder with Space must not open it');
    await React.act(async () => pressSftpSessionKey(' '));
    assert.equal(checked(folder), false);
    await React.act(async () => pressSftpSessionKey('Enter'));
    assert.equal(checked(folder), false, 'Enter on a checkbox must not open its folder');
    assert.equal(navigations.length, 0);
    await key(checkbox(folder), 'ArrowDown');
    assert.equal(checked(alpha), true, 'Arrow navigation must work from a focused checkbox');
    await React.act(
      async () => new Promise<void>((resolve) => requestAnimationFrame(() => resolve())),
    );
    assert.equal(document.activeElement, alpha);
    await key(pane, 'F2');
    const rename = alpha.querySelector<HTMLInputElement>('input')!;
    assert.ok(rename);
    await key(rename, 'ArrowDown');
    assert.equal(checked(alpha), true, 'Editing a name must not move file selection');
    await key(rename, 'Escape');
    assert.deepEqual(operations, [], 'Cancelling a rename must not perform a file operation');
    await key(pane, 'Escape');
    await React.act(async () =>
      checkbox(folder).dispatchEvent(
        new MouseEvent('dblclick', {
          bubbles: true,
        }),
      ),
    );
    assert.equal(navigations.length, 0, 'Double-clicking a folder checkbox must not open it');
    await React.act(async () =>
      checkbox(alpha).dispatchEvent(new MouseEvent('dblclick', { bubbles: true })),
    );
    assert.deepEqual(operations, [], 'Double-clicking a file checkbox must not open it');
    await React.act(async () => alpha.dispatchEvent(new MouseEvent('dblclick', { bubbles: true })));
    assert.deepEqual(operations.splice(0), prefix === '/local' ? [`open:${prefix}/alpha.txt`] : []);
    await React.act(async () =>
      folder.dispatchEvent(new MouseEvent('dblclick', { bubbles: true })),
    );
    assert.deepEqual(navigations.splice(0), [`${prefix}/folder`]);
    await key(folder, 'ArrowDown');
    assert.equal(checked(alpha), true, 'Keyboard selection must update its checkbox');
    await key(alpha, 'ArrowDown', { shiftKey: true });
    assert.ok(checked(alpha) && checked(zulu));
    await key(alpha, 'Home');
    assert.equal(checked(folder), true);
    await key(folder, 'End');
    assert.equal(checked(zulu), true);
    await key(folder, 'Enter');
    await key(folder, ' ');
    assert.deepEqual(navigations.splice(0), [`${prefix}/folder`, `${prefix}/folder`]);
    await key(alpha, 'Enter');
    await key(pane, 'Escape');
    await click(checkbox(alpha));
    await click(checkbox(zulu));
    await click(folder);
    await key(pane, 'Delete');
    assert.ok(pane.textContent?.includes('2 item(s) will be permanently removed.'));
    assert.deepEqual(operations, [], 'Opening the confirmation must not delete files');
    await click(
      [...pane.querySelectorAll('button')].find((button) => button.textContent === 'Cancel')!,
    );
    assert.ok(checked(alpha) && checked(zulu), 'Cancelling deletion must preserve checked files');
    await key(pane, 'Delete');
    await click(
      [...pane.querySelectorAll('button')].find((button) => button.textContent === 'Delete')!,
    );
    assert.deepEqual(operations.splice(0), [
      `delete:${prefix}/alpha.txt`,
      `delete:${prefix}/zulu.txt`,
    ]);
    assert.ok(!checked(folder) && !checked(alpha) && !checked(zulu));
  }
  await render('opening');
  for (const row of document.querySelectorAll('[data-sftp-index]')) {
    await key(row, 'ArrowDown');
    await key(row, 'Enter');
  }
  for (const control of document.querySelectorAll<HTMLButtonElement>('[role="checkbox"]')) {
    assert.equal(control.disabled, true, 'Selection is disabled while a folder loads');
    await click(control);
    assert.equal(control.getAttribute('aria-checked'), 'false');
  }
  await render('ready', true);
  const grid = document.querySelector('[aria-label="Local file list"]')!;
  const viewport = grid.parentElement!;
  await click(checkbox(grid.querySelector('[data-sftp-index="0"]')!));
  await React.act(async () => {
    viewport.scrollTop = viewport.scrollHeight;
    viewport.dispatchEvent(new Event('scroll', { bubbles: true }));
  });
  await tick();
  assert.ok(
    grid.querySelectorAll('[role="checkbox"]').length < 60,
    'Checkboxes must stay virtualized',
  );
  await click(checkbox(grid.querySelector('[data-sftp-index="199"]')!));
  await React.act(async () => {
    viewport.scrollTop = 0;
    viewport.dispatchEvent(new Event('scroll', { bubbles: true }));
  });
  await tick();
  assert.equal(checked(grid.querySelector('[data-sftp-index="0"]')!), true);
  await key(grid, 'F5');
  assert.deepEqual(copies.at(-1), ['/bulk/file-000', '/bulk/file-199']);
}

export async function runSftpSessionTests() {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  const root = createRoot(document.getElementById('root')!);
  await runSftpTreeRequestTests(root);
  await runSftpSearchTests(root);
  await runSftpKeyboardScopeTests(root);
  await runSftpCheckboxTests(root);
  const reconnects: string[] = [];
  for (const [width, height] of [
    [1180, 700],
    [520, 450],
  ]) {
    for (const status of ['connecting', 'failed', 'closed'] as const) {
      for (const tunnelProgress of status === 'connecting'
        ? [undefined, { phase: 'starting' }, { phase: 'ready' }]
        : [undefined]) {
        await React.act(async () =>
          root.render(
            <div
              data-sftp-session-pane
              className="absolute min-h-0 min-w-0 overflow-hidden"
              style={{ left: 17, top: 53, width, height }}
            >
              <SessionSurface
                session={{
                  id: 'sftp-connecting',
                  protocol: 'sftp',
                  status,
                  host: 'server',
                  error: status === 'failed' ? 'Permission denied' : undefined,
                  tunnelProgress,
                }}
                onReconnectSession={(id: string) => reconnects.push(id)}
              />
            </div>,
          ),
        );
        const pane = document.querySelector('[data-sftp-session-pane]')!;
        const content = tunnelProgress
          ? pane.firstElementChild!.firstElementChild!
          : pane.querySelector('h3')!.parentElement!;
        const bounds = pane.getBoundingClientRect();
        const contentBounds = content.getBoundingClientRect();
        const label = `${status}, ${width}x${height}, VPN ${tunnelProgress?.phase ?? 'off'}`;
        assert.ok(
          Math.abs(contentBounds.x + contentBounds.width / 2 - bounds.x - bounds.width / 2) <= 1,
          `SFTP status must be horizontally centered: ${label}`,
        );
        assert.ok(
          Math.abs(contentBounds.y + contentBounds.height / 2 - bounds.y - bounds.height / 2) <= 1,
          `SFTP status must be vertically centered: ${label}`,
        );
        if (status !== 'connecting') {
          assert.ok(
            pane.textContent?.includes(status === 'failed' ? 'Permission denied' : 'closed'),
          );
          await React.act(async () => pane.querySelector('button')!.click());
        }
      }
    }
  }
  assert.deepEqual(reconnects, Array(4).fill('sftp-connecting'));
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
  const directory = (parent: string, name: string) => ({
    name,
    fullPath: `${parent === '/' ? '' : parent}/${name}`,
    isDirectory: true,
    isSymbolicLink: false,
    size: 0,
    lastModifiedUtc: '2026-10-25T10:30:00Z',
  });
  const remoteTreeEntries = new Map([
    [
      '/',
      [
        ...Array.from({ length: 24 }, (_, index) => directory('/', `a-root-${index}`)),
        directory('/', 'home'),
        directory('/', 'remote'),
        directory('/', 'zulu'),
      ],
    ],
    [
      '/home',
      [
        ...Array.from({ length: 24 }, (_, index) => directory('/home', `a-user-${index}`)),
        directory('/home', 'ubuntu'),
      ],
    ],
    ['/home/ubuntu', [directory('/home/ubuntu', '.cache'), directory('/home/ubuntu', '.ssh')]],
  ]);
  let deferRemoteRoot = true;
  const delayedTreeReplies = new Map<string, () => void>();
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
      const reply = () =>
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
            : {
                type: 'sftp.ready',
                sessionId,
                requestId,
                path,
                truncated: false,
                entries: remoteTreeEntries.get(path) ?? [],
              },
        );
      if (deferRemoteRoot && pane === 'remote' && path === '/remote')
        delayedTreeReplies.set(path, reply);
      else queueMicrotask(reply);
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
    title = 'File transfer',
  ) => {
    await React.act(async () =>
      root.render(
        <TooltipProvider>
          <div style={{ height: 720 }}>
            <SftpBrowserSurface
              session={{
                id: 'tab',
                title,
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
  const target = '192.0.2.10';
  await render(browser, target, 'native', target);
  const toolbar = document.querySelector('[aria-label="SFTP browser"]')!.firstElementChild!;
  assert.equal(
    toolbar.textContent?.includes(target),
    false,
    'SFTP toolbar must omit target labels',
  );
  assert.ok(toolbar.textContent?.includes('Swap panels') && toolbar.textContent.includes('Queue'));
  const assertTreePathVisible = (pane: 'local' | 'remote', path: string) => {
    const tree = document.querySelector(`[aria-label="${pane} directory tree"]`)!;
    const selected = tree.querySelector('[aria-selected="true"]');
    assert.ok(selected, `${pane} tree must select ${path}`);
    assert.equal(selected.querySelector('button[title]')?.getAttribute('title'), path);
    const treeBounds = tree.getBoundingClientRect();
    const headerBounds = tree.querySelector('[data-sftp-tree-header]')?.getBoundingClientRect();
    if (headerBounds && tree.scrollTop > 0)
      assert.ok(
        Math.abs(headerBounds.top - treeBounds.top) <= 1,
        'Tree headers must remain pinned while scrolling',
      );
    const selectedBounds = selected.getBoundingClientRect();
    assert.ok(
      selectedBounds.top >= (headerBounds?.bottom ?? treeBounds.top) - 1 &&
        selectedBounds.bottom <= treeBounds.bottom + 1,
      `${pane} tree must reveal ${path} inside its viewport`,
    );
    assert.equal(
      document.querySelector<HTMLInputElement>(
        `[aria-label="${pane === 'local' ? 'Local' : 'Remote'} path"]`,
      )!.value,
      path,
    );
  };
  const homeBrowser = {
    ...browser,
    path: '/home/ubuntu',
    entries: [
      ...remoteTreeEntries.get('/home/ubuntu')!,
      { ...browser.entries[0], fullPath: '/home/ubuntu/file.conf' },
    ],
  };
  await render(homeBrowser);
  for (const pane of ['local', 'remote'] as const) {
    const tree = document.querySelector(`[aria-label="${pane} directory tree"]`)!;
    assert.deepEqual(
      [...tree.querySelectorAll('[role="columnheader"]')].map((column) =>
        column.textContent?.trim(),
      ),
      ['Name', 'Size', 'Modified'],
      'Directory trees must expose the file-list column headers',
    );
    assert.equal(tree.getAttribute('role'), 'treegrid');
    const fileList = document.querySelector(
      `[aria-label="${pane === 'local' ? 'Local' : 'Remote'} file list"]`,
    )!;
    const listColumns = [...fileList.querySelectorAll('[role="columnheader"]')].filter((column) =>
      ['Name', 'Size', 'Modified'].includes(column.textContent?.trim() ?? ''),
    );
    const treeColumns = [...tree.querySelectorAll('[role="columnheader"]')];
    const name = document.createRange();
    name.selectNodeContents(treeColumns[0].querySelector('span')!);
    assert.ok(
      Math.abs(
        name.getBoundingClientRect().x -
          listColumns[0].querySelector('button')!.getBoundingClientRect().x,
      ) <= 1,
      `${pane} Name headers must align`,
    );
    for (const index of [1, 2]) {
      const expected = listColumns[index].getBoundingClientRect();
      const actual = treeColumns[index].getBoundingClientRect();
      assert.ok(
        Math.abs(expected.x - actual.x) <= 1 && Math.abs(expected.width - actual.width) <= 1,
        `${pane} tree metadata columns must align with the file list`,
      );
    }
    const separator = document.querySelector(`[aria-label="Resize ${pane} directory tree"]`)!;
    await React.act(async () => {
      for (let step = 0; step < 20; step++)
        separator.dispatchEvent(
          new KeyboardEvent('keydown', { key: 'ArrowUp', bubbles: true, cancelable: true }),
        );
    });
    await tick();
    assert.equal(separator.getAttribute('aria-valuenow'), '80');
    assertTreePathVisible(pane, pane === 'local' ? browser.local.path : homeBrowser.path);
    await React.act(async () => {
      for (let step = 0; step < 6; step++)
        separator.dispatchEvent(
          new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true, cancelable: true }),
        );
    });
    await tick();
    assert.equal(separator.getAttribute('aria-valuenow'), '140');
  }
  assertTreePathVisible('remote', '/home/ubuntu');
  const remotePath = document.querySelector<HTMLInputElement>('[aria-label="Remote path"]')!;
  remotePath.focus();
  assert.equal(delayedTreeReplies.size, 1);
  assert.equal(delayedTreeReplies.has('/remote'), true);
  assert.ok(
    !treeRequests.includes('remote:/') && !treeRequests.includes('remote:/home'),
    'A current-folder tree must not read ancestor directories',
  );
  await React.act(async () => {
    deferRemoteRoot = false;
    delayedTreeReplies.get('/remote')!();
  });
  await tick();
  assertTreePathVisible('remote', '/home/ubuntu');
  assert.deepEqual(
    [
      ...document.querySelectorAll('[aria-label="remote directory tree"] [data-sftp-tree-path]'),
    ].map((row) => row.getAttribute('data-sftp-tree-path')),
    ['/home/ubuntu', '/home/ubuntu/.cache', '/home/ubuntu/.ssh'],
    'A late reply for the previous root must not reveal parents or siblings',
  );
  for (const name of ['.cache', '.ssh']) {
    const tree = document.querySelector('[aria-label="remote directory tree"]')!;
    const child = tree
      .querySelector(`[title="/home/ubuntu/${name}"]`)!
      .closest('[data-sftp-tree-path]')!;
    const bounds = child.getBoundingClientRect();
    const viewportBounds = tree.getBoundingClientRect();
    assert.ok(
      bounds.top >= viewportBounds.top - 1 && bounds.bottom <= viewportBounds.bottom + 1,
      'The current folder and its children must be visible together',
    );
    const file = document
      .querySelector(`[data-sftp-panel="remote"] [aria-label="Select ${name}"]`)!
      .closest('[data-sftp-index]')!;
    const modified = child.querySelector('[aria-colindex="3"]')!.textContent;
    assert.ok(modified, 'Directory modification dates must be visible');
    assert.equal(modified, file.lastElementChild!.textContent);
    assert.equal(child.querySelector('[aria-colindex="2"]')!.textContent, '');
  }
  assert.equal(document.activeElement, remotePath, 'Revealing a tree path must preserve focus');
  await input(remotePath, '/zulu/project');
  await key(remotePath, 'Enter');
  assert.equal(navigations.at(-1), '/zulu/project');
  await render({ ...homeBrowser, path: '/zulu/project', entries: [] });
  assertTreePathVisible('remote', '/zulu/project');
  assert.equal(
    document.querySelectorAll('[aria-label="remote directory tree"] [data-sftp-tree-path]').length,
    1,
  );
  await render({ ...homeBrowser, path: '/', entries: [] });
  assertTreePathVisible('remote', '/');
  const remoteTree = document.querySelector<HTMLElement>('[aria-label="remote directory tree"]')!;
  remoteTree.scrollTop = 40;
  await click(remoteTree.querySelector('[aria-label="Expand /a-root-0"]'));
  assert.equal(remoteTree.scrollTop, 40, 'Expanding another folder must preserve manual scrolling');
  await render();
  assertTreePathVisible('remote', '/remote');
  assertTreePathVisible('local', '/local');
  assert.ok(document.querySelector('[role="treegrid"]'));
  assert.equal(
    document.querySelector('dialog'),
    null,
    'File transfer must participate in the ordinary layout',
  );
  await click(
    document.querySelector('[data-sftp-panel="local"] [data-sftp-index] [role="checkbox"]'),
  );
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
  await key(document.querySelector('[aria-label="Resize remote directory tree"]')!, 'ArrowDown');
  const treeHeights = { local: 165, remote: 150 };
  const assertTreeHeights = () => {
    for (const pane of ['local', 'remote'] as const) {
      const separator = document.querySelector(`[aria-label="Resize ${pane} directory tree"]`)!;
      assert.equal(
        separator.getAttribute('aria-valuenow'),
        String(treeHeights[pane]),
        `${pane} tree must retain its own resized height`,
      );
      assert.ok(
        Math.abs(separator.parentElement!.getBoundingClientRect().height - treeHeights[pane]) <= 1,
      );
    }
  };
  for (const pane of ['local', 'remote'] as const) {
    const pendingHome =
      pane === 'local'
        ? {
            ...browser,
            local: {
              ...browser.local,
              status: 'opening',
              previousPath: browser.local.path,
              path: '',
            },
          }
        : { ...browser, status: 'opening', previousPath: browser.path, path: '' };
    await click(document.querySelector(`[data-sftp-panel="${pane}"] button[aria-label="Home"]`));
    assert.equal(navigations.at(-1), '');
    await render(pendingHome);
    await render(
      pane === 'local'
        ? { ...browser, local: { ...browser.local, path: '/home/operator', entries: [] } }
        : { ...browser, path: '/home/ubuntu', entries: [] },
    );
    assertTreeHeights();
    await render();
    assertTreeHeights();
    await click(document.querySelector(`[data-sftp-panel="${pane}"] button[aria-label="Home"]`));
    await render(pendingHome);
    await render(
      pane === 'local'
        ? { ...browser, local: { ...browser.local, status: 'failed', error: 'Home unavailable' } }
        : { ...browser, status: 'failed', error: 'Home unavailable' },
    );
    assert.ok(
      document
        .querySelector(`[data-sftp-panel="${pane}"]`)!
        .textContent?.includes('Home unavailable'),
    );
    assertTreeHeights();
    await render();
    const toggle = document.querySelector(`[data-sftp-panel="${pane}"] button[aria-pressed]`)!;
    await click(toggle);
    assert.ok(!document.querySelector(`[aria-label="${pane} directory tree"]`));
    await click(toggle);
    assertTreeHeights();
  }
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
  const localTreeRow = document.querySelector('[data-sftp-panel="local"] [data-sftp-tree-path]')!;
  await drop(localTreeRow, 'remote', '/remote/drag.conf');
  assert.equal(transfers.at(-1)?.[0], 'remote-to-local');
  await drop(localTreeRow, 'local', '/different/drag.conf');
  assert.equal(transfers.at(-1)?.[0], 'local-to-local');
  await drop(
    document.querySelector('[data-sftp-panel="remote"] [data-sftp-tree-path]')!,
    'local',
    '/local/drag.conf',
  );
  assert.equal(transfers.at(-1)?.[0], 'local-to-remote');
  const beforeInvalidDrop = transfers.length;
  await drop(
    document.querySelector('[data-sftp-panel="remote"] [data-sftp-tree-path]')!,
    'remote',
    '/remote/drag.conf',
  );
  assert.equal(transfers.length, beforeInvalidDrop);
  const remotePanel = document.querySelector('[data-sftp-panel="remote"]')!;
  await click(remotePanel.querySelector('[data-sftp-index] [role="checkbox"]'));
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

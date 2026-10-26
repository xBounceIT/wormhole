import * as React from 'react';
import { SftpFilePane } from '../../src/components/SftpBrowser';
import { TooltipProvider } from '../../src/components/ui/tooltip';

declare const assert: typeof import('node:assert/strict');
declare function setSftpSearchActive(selector: string, active: boolean): Promise<void>;

export async function runSftpSearchTests(
  root: ReturnType<typeof import('react-dom/client').createRoot>,
) {
  const original = window.wormhole;
  const listeners = new Set<(event: WormholeSshEvent) => void>();
  const requests: string[] = [];
  const navigations: string[] = [];
  const copies: string[][] = [];
  const entry = (parent: string, name: string, isDirectory = true): WormholeSftpEntry => ({
    name,
    fullPath: `${parent === '/' ? '' : parent}/${name}`,
    isDirectory,
    isSymbolicLink: false,
    size: isDirectory ? 0 : 12,
    lastModifiedUtc: name === 'Needle' ? '2026-10-26T10:30:00Z' : '2026-10-25T10:30:00Z',
  });
  window.wormhole = {
    onSshEvent: (listener) => {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    listSftpTree: async (sessionId, pane, path, requestId) => {
      requests.push(`${pane}:${path}`);
      const names =
        path === '/'
          ? [pane, 'outside']
          : path === `/${pane}`
            ? ['alpha', 'beta']
            : ['Needle', 'Other'];
      queueMicrotask(() => {
        const event = {
          type: pane === 'local' ? 'sftp.local.ready' : 'sftp.ready',
          sessionId,
          pane,
          path,
          requestId,
          entries: names.map((name) => entry(path, name)),
          truncated: false,
        } as WormholeSshEvent;
        for (const listener of listeners) listener(event);
      });
    },
  } as NonNullable<Window['wormhole']>;
  const tick = async () => React.act(async () => new Promise((resolve) => setTimeout(resolve, 20)));
  const render = async (homeLoading = false) => {
    await React.act(async () =>
      root.render(
        <TooltipProvider>
          <div className="flex h-[600px] gap-4 overflow-hidden">
            {(['local', 'remote'] as const).map((pane) => {
              const path = `/${pane}/alpha`;
              return (
                <SftpFilePane
                  key={pane}
                  pane={pane}
                  sessionId="search-session"
                  state={{
                    status: homeLoading && pane === 'local' ? 'opening' : 'ready',
                    path: homeLoading && pane === 'local' ? '' : path,
                    truncated: false,
                    entries: [
                      entry(path, 'Needle'),
                      entry(path, 'Other'),
                      entry(path, 'alpha.txt', false),
                      entry(path, 'beta.txt', false),
                      ...Array.from({ length: 120 }, (_, index) =>
                        entry(path, `file-${index}`, false),
                      ),
                    ],
                  }}
                  onNavigate={(next) => navigations.push(next)}
                  onRefresh={() => {}}
                  onOperation={() => {}}
                  onTransfer={() => {}}
                  onCopy={(items) => copies.push(items.map((item) => item.sourcePath))}
                />
              );
            })}
          </div>
        </TooltipProvider>,
      ),
    );
    await tick();
  };
  const panel = (pane: string) =>
    document.querySelector<HTMLElement>(`[data-sftp-panel="${pane}"]`)!;
  const tree = (pane: string) => panel(pane).querySelector<HTMLElement>('[role="treegrid"]')!;
  const list = (pane: string) => panel(pane).querySelector<HTMLElement>('[role="grid"]')!;
  const header = (pane: string, view: 'tree' | 'files', index: number) =>
    (view === 'tree' ? tree(pane) : list(pane)).querySelector<HTMLElement>(
      `[role="columnheader"][aria-colindex="${index + (view === 'tree' ? 1 : 3)}"]`,
    )!;
  const sort = async (pane: string, view: 'tree' | 'files', index: number) => {
    await React.act(async () =>
      header(pane, view, index).querySelector<HTMLButtonElement>('button')!.click(),
    );
    await tick();
    if (view === 'tree') {
      const selected = tree(pane).querySelector('[aria-selected="true"]')!.getBoundingClientRect();
      const heading = tree(pane).querySelector('[data-sftp-tree-header]')!.getBoundingClientRect();
      assert.ok(
        selected.top >= heading.bottom - 1 &&
          selected.bottom <= tree(pane).getBoundingClientRect().bottom + 1,
        'Sorting must keep the selected directory visible below the fixed header',
      );
    }
  };
  const search = (pane: string, view: 'tree' | 'files') =>
    (view === 'tree' ? tree(pane) : list(pane)).querySelector<HTMLInputElement>(
      'input[type="search"]',
    )!;
  const sectionHeader = (pane: string, view: 'tree' | 'files') =>
    (view === 'tree' ? tree(pane) : list(pane)).querySelector<HTMLElement>(
      view === 'tree' ? '[data-sftp-tree-header]' : '[data-sftp-file-header]',
    )!;
  const searchToggle = (pane: string, view: 'tree' | 'files') =>
    sectionHeader(pane, view).querySelector<HTMLButtonElement>('button[aria-expanded]')!;
  const clickToggle = async (pane: string, view: 'tree' | 'files') => {
    await React.act(async () => searchToggle(pane, view).click());
    await tick();
  };
  const pressToggle = async (pane: string, view: 'tree' | 'files') => {
    const button = searchToggle(pane, view);
    const before = button.getBoundingClientRect();
    const transition = button.style.transition;
    // Hidden windows can suspend transition frames; inspect the final pressed position.
    button.style.transition = 'none';
    const selector = `button[aria-controls="${searchToggle(pane, view).getAttribute('aria-controls')}"]`;
    try {
      await React.act(async () => {
        // Synthetic clicks skip :active. Force Chromium's press style in the hidden window.
        await setSftpSearchActive(selector, true);
      });
      const pressed = searchToggle(pane, view);
      const during = pressed.getBoundingClientRect();
      assert.ok(
        Math.abs(during.top - before.top) <= 0.5 && Math.abs(during.left - before.left) <= 0.5,
        'Holding the search button must not shift it',
      );
      assert.ok(
        during.bottom <= sectionHeader(pane, view).getBoundingClientRect().bottom,
        'The pressed search button must stay inside its header',
      );
    } finally {
      await React.act(async () => setSftpSearchActive(selector, false));
      button.style.transition = transition;
      await tick();
    }
    await clickToggle(pane, view);
    const after = searchToggle(pane, view).getBoundingClientRect();
    assert.ok(
      Math.abs(after.top - before.top) <= 0.5 && Math.abs(after.left - before.left) <= 0.5,
      'Switching between search and close must preserve the button position',
    );
  };
  const treePaths = (pane: string) =>
    [...tree(pane).querySelectorAll('[data-sftp-tree-path]')].map((row) =>
      row.getAttribute('data-sftp-tree-path'),
    );
  const fileNames = (pane: string) =>
    [...list(pane).querySelectorAll('[data-sftp-index]')].map((row) =>
      row.querySelector('[role="checkbox"]')!.getAttribute('aria-label')!.slice(7),
    );
  const input = async (pane: string, view: 'tree' | 'files', value: string) => {
    if (!search(pane, view)) await clickToggle(pane, view);
    const field = search(pane, view);
    await React.act(async () => {
      field.focus();
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(field, value);
      field.dispatchEvent(new Event('input', { bubbles: true }));
    });
    await tick();
    assert.equal(search(pane, view).value, value);
  };
  const key = async (element: Element, value: string, options: KeyboardEventInit = {}) => {
    await React.act(async () =>
      element.dispatchEvent(
        new KeyboardEvent('keydown', { key: value, bubbles: true, cancelable: true, ...options }),
      ),
    );
    await tick();
  };
  try {
    await render();
    const requestCount = requests.length;
    assert.equal(requestCount, 2);
    assert.deepEqual([...requests].sort(), ['local:/local/alpha', 'remote:/remote/alpha']);
    const headingStyles: Record<string, string>[] = [];
    for (const pane of ['local', 'remote']) {
      assert.equal(
        !!header(pane, 'tree', 1).querySelector('button'),
        false,
        'Directory trees must not offer sorting by unavailable folder sizes',
      );
      assert.equal(header(pane, 'tree', 1).hasAttribute('aria-sort'), false);
      assert.ok(header(pane, 'files', 1).querySelector('button'));
      for (const view of ['tree', 'files'] as const) {
        for (const index of [0, 1, 2]) {
          const label = header(pane, view, index).querySelector(':scope > button, :scope > span')!;
          const style = getComputedStyle(label);
          headingStyles.push(
            Object.fromEntries(
              [
                'fontFamily',
                'fontSize',
                'fontWeight',
                'lineHeight',
                'letterSpacing',
                'textTransform',
              ].map((property) => [property, style[property as keyof CSSStyleDeclaration]]),
            ),
          );
        }
        assert.ok(!search(pane, view), 'Search must start collapsed');
        const toggle = searchToggle(pane, view);
        const toggleBounds = toggle.getBoundingClientRect();
        const bounds = sectionHeader(pane, view).getBoundingClientRect();
        assert.equal(toggle.getAttribute('aria-expanded'), 'false');
        assert.equal(toggle.getAttribute('title'), null);
        assert.ok(toggle.querySelector('svg.lucide-search'));
        assert.equal(toggle.textContent?.trim(), '', 'The collapsed search must be an icon button');
        assert.equal(toggleBounds.width, 24);
        assert.equal(toggleBounds.height, 24);
        assert.ok(
          bounds.right - toggleBounds.right >= 0 && bounds.right - toggleBounds.right <= 9,
          'Each search button must sit at the right edge of its section',
        );
        assert.ok(
          header(pane, view, 2).querySelector('button')!.getBoundingClientRect().right <=
            toggleBounds.left,
          'Search must not overlap a sort button',
        );
        await pressToggle(pane, view);
        const field = search(pane, view);
        const columnHeader = field.closest('[role="columnheader"]')!;
        assert.ok(columnHeader);
        assert.equal(
          field.getAttribute('aria-label'),
          view === 'tree' ? `Search ${pane} directory tree` : `Search ${pane} folder`,
        );
        const fieldBounds = field.getBoundingClientRect();
        assert.equal(getComputedStyle(field).fontSize, '11px', 'Expanded search must stay compact');
        const headerBounds = sectionHeader(pane, view).getBoundingClientRect();
        assert.ok(
          fieldBounds.width >= headerBounds.width - 60 && fieldBounds.height >= 24,
          'Expanded search must use the section width',
        );
        assert.ok(
          fieldBounds.left >= headerBounds.left && fieldBounds.right <= headerBounds.right + 1,
        );
        assert.equal(
          document.activeElement?.getAttribute('id'),
          field.id,
          'Opening search must focus its input',
        );
        assert.equal(searchToggle(pane, view).getAttribute('aria-controls'), field.id);
        assert.equal(searchToggle(pane, view).getAttribute('aria-expanded'), 'true');
        assert.ok(searchToggle(pane, view).querySelector('svg.lucide-x'));
        assert.equal(
          sectionHeader(pane, view).querySelectorAll('[aria-sort]').length,
          0,
          'Search must replace all column headings in its section',
        );
        assert.equal(columnHeader.getAttribute('aria-colspan'), view === 'tree' ? '3' : '5');
        assert.equal(
          headerBounds.height,
          bounds.height,
          'Expanding search must not resize the header',
        );
        assert.equal(
          document.querySelectorAll('input[type="search"]').length,
          1,
          'Opening search must leave the other three sections collapsed',
        );
        await pressToggle(pane, view);
        assert.ok(!search(pane, view), 'The close button must collapse search');
        await clickToggle(pane, view);
        await key(search(pane, view), 'Escape');
        assert.ok(!search(pane, view));
        assert.equal(searchToggle(pane, view).getAttribute('aria-expanded'), 'false');
        assert.ok(
          document.activeElement === searchToggle(pane, view),
          'Closing search must return focus to its button',
        );
      }
      assert.equal(panel(pane).querySelectorAll('input[type="search"]').length, 0);
    }
    for (const style of headingStyles)
      assert.deepEqual(
        style,
        headingStyles[0],
        'All Tree and file-list headings must use identical typography',
      );
    assert.equal(headingStyles[0].fontSize, '9px');
    assert.equal(headingStyles[0].fontWeight, '500');
    assert.equal(headingStyles[0].textTransform, 'uppercase');
    const directoryNames = (pane: string) =>
      treePaths(pane)
        .filter((path) => path!.startsWith(`/${pane}/alpha/`))
        .map((path) => path!.split('/').at(-1));
    await sort('local', 'tree', 0);
    assert.deepEqual(directoryNames('local'), ['Other', 'Needle']);
    assert.equal(header('local', 'tree', 0).getAttribute('aria-sort'), 'descending');
    assert.equal(header('local', 'files', 0).getAttribute('aria-sort'), 'ascending');
    assert.equal(header('remote', 'tree', 0).getAttribute('aria-sort'), 'ascending');
    await sort('local', 'tree', 2);
    assert.equal(header('local', 'tree', 2).getAttribute('aria-sort'), 'ascending');
    assert.equal(header('local', 'tree', 0).getAttribute('aria-sort'), 'none');
    assert.deepEqual(directoryNames('local'), ['Other', 'Needle']);
    await sort('local', 'tree', 2);
    assert.equal(header('local', 'tree', 2).getAttribute('aria-sort'), 'descending');
    assert.deepEqual(directoryNames('local'), ['Needle', 'Other']);
    await sort('local', 'files', 1);
    assert.equal(header('local', 'files', 1).getAttribute('aria-sort'), 'ascending');
    await sort('local', 'files', 1);
    assert.equal(header('local', 'files', 1).getAttribute('aria-sort'), 'descending');
    await sort('local', 'files', 2);
    await sort('local', 'files', 2);
    assert.equal(header('local', 'files', 2).getAttribute('aria-sort'), 'descending');
    assert.equal(header('local', 'tree', 2).getAttribute('aria-sort'), 'descending');
    await sort('local', 'files', 0);
    await sort('local', 'tree', 0);
    await sort('local', 'tree', 0);
    const localFiles = fileNames('local');
    const remoteFiles = fileNames('remote');
    const remoteTree = treePaths('remote');
    await input('local', 'tree', ' nEeDLe ');
    assert.deepEqual(treePaths('local'), ['/local/alpha', '/local/alpha/Needle']);
    assert.deepEqual(
      fileNames('local'),
      localFiles,
      'Tree searches must leave the file list unchanged',
    );
    assert.deepEqual(treePaths('remote'), remoteTree);
    const checkbox = list('local').querySelector<HTMLElement>('[aria-label="Select beta.txt"]')!;
    await React.act(async () => checkbox.click());
    await input('local', 'files', 'beta.txt');
    await key(search('local', 'files'), 'Escape');
    assert.ok(!search('local', 'files'));
    assert.equal(
      list('local').querySelector('[aria-label="Select beta.txt"]')!.getAttribute('aria-checked'),
      'true',
      'Escape in search must not clear the file selection',
    );
    await input('local', 'files', ' ALPHA.TXT ');
    assert.deepEqual(fileNames('local'), ['alpha.txt']);
    assert.equal(
      panel('local').querySelector<HTMLButtonElement>('[aria-label="Delete selected"]')!.disabled,
      true,
    );
    assert.equal(treePaths('local').length, 2);
    assert.deepEqual(fileNames('remote'), remoteFiles);
    await input('remote', 'tree', 'Other');
    await input('remote', 'files', 'beta.txt');
    assert.deepEqual(treePaths('remote'), ['/remote/alpha', '/remote/alpha/Other']);
    assert.deepEqual(fileNames('remote'), ['beta.txt']);
    assert.deepEqual(fileNames('local'), ['alpha.txt']);
    await input('local', 'tree', 'missing');
    assert.equal(treePaths('local').length, 0);
    assert.ok(tree('local').textContent?.includes('No folders match your search'));
    assert.equal(tree('local').getAttribute('aria-rowcount'), '2');
    assert.equal(fileNames('local').length, 1);
    await input('local', 'files', 'missing');
    assert.equal(fileNames('local').length, 0);
    assert.ok(list('local').textContent?.includes('No files match your search'));
    for (const view of ['tree', 'files'] as const) {
      await key(search('local', view), 'F5');
      await key(search('local', view), 'Backspace');
      await key(search('local', view), 'Delete');
      await key(search('local', view), 'Enter');
    }
    assert.deepEqual(navigations, [], 'Search fields must retain text editing shortcuts');
    assert.deepEqual(copies, []);
    await input('local', 'tree', 'Needle');
    assert.equal(requests.length, requestCount, 'Typing must not issue more directory requests');
    await clickToggle('local', 'tree');
    assert.ok(!search('local', 'tree'));
    assert.ok(
      treePaths('local').includes('/local/alpha/Other'),
      'Closing search must clear its filter',
    );
    assert.equal(header('local', 'tree', 0).getAttribute('aria-sort'), 'descending');
    assert.equal(
      search('local', 'files').value,
      'missing',
      'Closing a search must leave other filters unchanged',
    );
    await input('local', 'tree', 'Needle');
    await React.act(async () =>
      panel('local')
        .querySelector<HTMLButtonElement>('[aria-label="Hide directory tree"]')!
        .click(),
    );
    assert.ok(!panel('local').querySelector('[role="treegrid"]'));
    await React.act(async () =>
      panel('local')
        .querySelector<HTMLButtonElement>('[aria-label="Show directory tree"]')!
        .click(),
    );
    await tick();
    assert.equal(search('local', 'tree').value, 'Needle');
    assert.equal(searchToggle('local', 'tree').getAttribute('aria-expanded'), 'true');
    assert.equal(search('local', 'files').value, 'missing');
    await render(true);
    assert.ok(!panel('local').querySelector('[role="treegrid"]'));
    await render();
    assert.equal(search('local', 'tree').value, 'Needle', 'Home must preserve the tree search');
    await clickToggle('local', 'tree');
    assert.equal(
      header('local', 'tree', 0).getAttribute('aria-sort'),
      'descending',
      'Home and closing search must preserve each Tree sort order',
    );
    assert.equal(search('remote', 'tree').value, 'Other');
    assert.equal(search('remote', 'files').value, 'beta.txt');
    await input('local', 'tree', '');
    assert.ok(treePaths('local').includes('/local/alpha/Other'));
    const selectedFolder = tree('local').querySelector('[aria-selected="true"]')!;
    assert.ok(
      selectedFolder.getBoundingClientRect().top >=
        tree('local').querySelector('[data-sftp-tree-header]')!.getBoundingClientRect().bottom - 1,
      'Clearing the tree search must reveal the selected folder below the header',
    );
    await input('local', 'files', '');
    const container = panel('local').parentElement!;
    container.style.width = '720px';
    await tick();
    const compact = search('local', 'files').getBoundingClientRect();
    const compactHeader = sectionHeader('local', 'files').getBoundingClientRect();
    assert.ok(
      compact.width >= compactHeader.width - 60 && compact.right < compactHeader.right,
      'Expanded search must fit a narrow pane',
    );
    container.style.width = '';
    await tick();
    const first = list('local').querySelector<HTMLElement>('[data-sftp-index="0"]')!;
    await key(first, 'End');
    const last = list('local').querySelector<HTMLElement>('[data-sftp-index="123"]')!;
    assert.ok(last, 'Clearing the filter must restore the virtual list');
    const viewport = list('local').parentElement!;
    const stickyHeader = list('local').querySelector('[data-sftp-file-header]')!;
    assert.ok(
      Math.abs(stickyHeader.getBoundingClientRect().top - viewport.getBoundingClientRect().top) <=
        2,
    );
    assert.ok(last.getBoundingClientRect().bottom <= viewport.getBoundingClientRect().bottom + 1);
    await key(last, 'Home');
    const restored = list('local').querySelector<HTMLElement>('[data-sftp-index="0"]')!;
    assert.ok(
      restored.getBoundingClientRect().top >= stickyHeader.getBoundingClientRect().bottom - 1,
    );
    await key(panel('local'), 'Escape');
    await key(restored, 'ArrowDown', { shiftKey: true });
    const checkedNames = () =>
      [...list('local').querySelectorAll('[role="checkbox"][aria-checked="true"]')].map((control) =>
        control.getAttribute('aria-label'),
      );
    assert.deepEqual(checkedNames(), ['Select Needle', 'Select Other']);
    const second = list('local').querySelector<HTMLElement>('[data-sftp-index="1"]')!;
    await key(second, 'ArrowUp', { ctrlKey: true });
    await key(restored, 'ArrowDown', { metaKey: true });
    assert.deepEqual(
      checkedNames(),
      ['Select Needle', 'Select Other'],
      'Ctrl/Cmd navigation must preserve the selection after clearing a search',
    );
    await key(second, 'ArrowUp', { shiftKey: true });
    assert.deepEqual(checkedNames(), ['Select Needle', 'Select Other']);
    await key(second, 'ArrowUp');
    assert.deepEqual(checkedNames(), ['Select Needle']);
    await key(restored, 'Home');
    assert.deepEqual(checkedNames(), ['Select Needle']);
  } finally {
    await React.act(async () => root.render(null));
    window.wormhole = original;
  }
}

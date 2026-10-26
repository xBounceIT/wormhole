import * as React from 'react';
import { SftpFilePane } from '../../src/components/SftpBrowser';
import { TooltipProvider } from '../../src/components/ui/tooltip';

declare const assert: typeof import('node:assert/strict');

export async function runSftpKeyboardScopeTests(
  root: ReturnType<typeof import('react-dom/client').createRoot>,
) {
  const tick = async () =>
    React.act(async () => new Promise<void>((resolve) => requestAnimationFrame(() => resolve())));
  const key = async (element: HTMLElement, value: string) => {
    await React.act(async () =>
      element.dispatchEvent(
        new KeyboardEvent('keydown', {
          key: value,
          bubbles: true,
          cancelable: true,
        }),
      ),
    );
    await tick();
  };
  try {
    await React.act(async () =>
      root.render(
        <TooltipProvider>
          <div className="grid h-[600px] grid-cols-2 gap-4">
            {['first', 'second'].map((connection) => (
              <div
                key={connection}
                aria-label="SFTP browser"
                data-test-connection={connection}
                className="flex min-w-0 gap-2"
              >
                {(['local', 'remote'] as const).map((pane) => (
                  <SftpFilePane
                    key={pane}
                    pane={pane}
                    state={{
                      status: 'ready',
                      path: `/${connection}/${pane}`,
                      truncated: false,
                      entries: ['alpha', 'beta'].map((name) => ({
                        name,
                        fullPath: `/${connection}/${pane}/${name}`,
                        isDirectory: false,
                        isSymbolicLink: false,
                        size: 1,
                      })),
                    }}
                    onNavigate={() => {}}
                    onRefresh={() => {}}
                    onOperation={() => {}}
                    onTransfer={() => {}}
                  />
                ))}
              </div>
            ))}
          </div>
        </TooltipProvider>,
      ),
    );
    await tick();
    const browser = document.querySelector<HTMLElement>('[data-test-connection="second"]')!;
    const pane = browser.querySelector<HTMLElement>('[data-sftp-panel="remote"]')!;
    const first = pane.querySelector<HTMLElement>('[data-sftp-index="0"]')!;
    first.focus();
    await key(first, 'ArrowDown');
    assert.equal(
      document.activeElement
        ?.closest('[data-test-connection]')
        ?.getAttribute('data-test-connection'),
      'second',
      'Arrow navigation must stay in the originating SFTP connection',
    );
    assert.equal(document.activeElement?.getAttribute('data-sftp-index'), '1');
    await key(pane, 'Tab');
    assert.equal(
      document.activeElement
        ?.closest('[data-test-connection]')
        ?.getAttribute('data-test-connection'),
      'second',
    );
    assert.equal(document.activeElement?.getAttribute('data-sftp-panel'), 'local');
  } finally {
    await React.act(async () => root.render(null));
  }
}

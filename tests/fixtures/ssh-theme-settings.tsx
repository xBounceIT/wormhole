import assert from 'node:assert/strict';
import { act, StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { SshThemeSettings, useSshTerminalTheme } from '../../src/components/SshThemeSettings';
import { sshTerminal, retainSshTerminals } from '../../src/xterm-terminal';
import { sshTerminalColors } from '../../src/terminal-themes';

export async function runSshThemeSettingsTests() {
  const host = document.createElement('div');
  document.body.append(host);
  const root = createRoot(host);
  const bridge = window.wormhole;
  const saved: string[] = [];
  let fail = false;
  let finishSave: (() => void) | undefined;
  window.wormhole = {
    ...bridge,
    setSshTerminalTheme: async (theme: string) => {
      saved.push(theme);
      if (fail) throw new Error('disk unavailable');
      if (finishSave)
        await new Promise<void>((resolve) => {
          finishSave = resolve;
        });
      return { updated: true };
    },
  } as typeof bridge;
  let state: ReturnType<typeof useSshTerminalTheme>;
  function Settings({ initialTheme, visible }: { initialTheme: unknown; visible: boolean }) {
    state = useSshTerminalTheme(initialTheme);
    return visible ? (
      <SshThemeSettings {...state} onChange={(value) => void state.changeTheme(value)} />
    ) : null;
  }
  const render = async (initialTheme: unknown, key = 'settings', visible = true) => {
    await act(async () =>
      root.render(
        <StrictMode>
          <Settings key={key} initialTheme={initialTheme} visible={visible} />
        </StrictMode>,
      ),
    );
  };
  const trigger = () => host.querySelector<HTMLButtonElement>('#settings-ssh-theme')!;
  const assertPreviewFits = async () => {
    await new Promise<void>((resolve) =>
      requestAnimationFrame(() => requestAnimationFrame(() => resolve())),
    );
    const preview = host.querySelector<HTMLElement>('[aria-label="SSH theme preview"]')!;
    assert.equal(
      preview.querySelectorAll('.xterm').length,
      1,
      'preview leaked a terminal on remount',
    );
    const screen = preview.querySelector<HTMLElement>('.xterm-screen')!;
    const container = screen.closest('.xterm')!.parentElement!;
    assert.ok(screen.querySelector('.xterm-rows')!.textContent!.includes('shared-777/'));
    assert.ok(
      screen.getBoundingClientRect().bottom <= container.getBoundingClientRect().bottom + 1,
      `theme preview clips its last row: ${screen.offsetHeight}px terminal inside ${container.clientHeight}px host`,
    );
  };
  const pick = async (label: string) => {
    await act(async () => trigger().click());
    const option = [...document.querySelectorAll<HTMLElement>('[role="option"]')].find(
      (element) => element.textContent === label,
    );
    assert.ok(option, 'missing SSH theme: ' + label);
    await act(async () => option.click());
    await assertPreviewFits();
  };
  await render('invalid');
  await assertPreviewFits();
  assert.ok(trigger().textContent!.includes('Tango (default)'));
  assert.equal(saved.length, 0);
  const detached = sshTerminal('theme-detached');
  const unopened = sshTerminal('theme-unopened');
  detached.attach(host);
  detached.detach();
  await pick('Dracula');
  assert.deepEqual(saved, ['dracula']);
  for (const runtime of [detached, unopened, sshTerminal('theme-new')]) {
    assert.equal(
      runtime.terminal.options.theme!.background,
      sshTerminalColors('dracula').background,
    );
  }
  const preview = host.querySelector<HTMLElement>('[aria-label="SSH theme preview"]')!;
  assert.equal(preview.style.backgroundColor, 'rgb(40, 42, 54)');
  await act(async () => {
    await state!.changeTheme('invalid');
    await state!.changeTheme('dracula');
  });
  assert.equal(saved.length, 1);

  finishSave = () => {};
  await pick('Tango (default)');
  assert.equal(trigger().disabled, true);
  await act(async () => {
    await state!.changeTheme('light');
  });
  assert.equal(saved.length, 2, 'a second save overlapped the first');
  await render('invalid', 'settings', false);
  assert.equal(host.querySelector('#settings-ssh-theme'), null);
  await act(async () => {
    finishSave!();
  });
  finishSave = undefined;
  await render('invalid');
  await assertPreviewFits();
  assert.equal(trigger().disabled, false);
  assert.equal(detached.terminal.options.theme!.background, sshTerminalColors('tango').background);

  fail = true;
  await pick('Wormhole Light');
  assert.ok(host.querySelector('[role="alert"]')!.textContent!.includes('Could not save'));
  assert.ok(trigger().textContent!.includes('Tango'));
  assert.equal(unopened.terminal.options.theme!.background, sshTerminalColors('tango').background);
  fail = false;
  await pick('Wormhole Light');
  assert.equal(host.querySelector('[role="alert"]'), null);
  assert.equal(unopened.terminal.options.theme!.background, sshTerminalColors('light').background);

  window.wormhole = undefined;
  await pick('Dracula');
  assert.ok(host.querySelector('[role="alert"]'));
  assert.ok(trigger().textContent!.includes('Wormhole Light'));
  window.wormhole = bridge;
  await render('dracula', 'reload');
  assert.equal(state!.theme, 'dracula', 'persisted theme was not restored on mount');
  await act(async () => root.unmount());
  host.remove();
  retainSshTerminals(new Set());
}

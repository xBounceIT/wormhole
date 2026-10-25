import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { SshTunnelFields } from '../../src/components/SshTunnelFields';

declare const assert: typeof import('node:assert/strict');

export async function runSshTunnelEditorTests() {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  const root = createRoot(document.getElementById('root')!);
  const changes: [string, unknown][] = [];
  let forgotten = 0;
  let fail = false;
  window.wormhole = {
    readTunnel: async () => {
      if (fail) throw new Error('unavailable');
      return { settings: { Mode: 'manual' } };
    },
  } as unknown as Window['wormhole'];
  const pin = 'SHA256:' + 'A'.repeat(43);
  const tree = [
    { id: 'direct', name: 'Direct bastion', kind: 'connection', protocol: 'ssh' },
    {
      id: 'cycle',
      name: 'Unsafe cycle',
      kind: 'connection',
      protocol: 'ssh',
      tunnelEnabled: true,
      tunnelConfigId: 'editing',
    },
    { id: 'rdp', name: 'RDP host', kind: 'connection', protocol: 'rdp' },
  ] as const;
  const credentials = [{ id: 'credential', name: 'Local SSH key' }];
  async function render(settings: Record<string, unknown>, fingerprint = pin) {
    await act(async () =>
      root.render(
        <SshTunnelFields
          tree={[...tree]}
          credentials={credentials}
          tunnels={[
            { id: 'other', kind: 'SSH tunnel (jump host)' },
            { id: 'vpn', kind: 'WireGuard' },
          ]}
          tunnelId="editing"
          settings={settings}
          pin={fingerprint}
          onChange={(key, value) => changes.push([key, value])}
          onForgetPin={() => forgotten++}
        />,
      ),
    );
  }
  await render({ Mode: 'manual', Port: 22, KeepaliveSeconds: 30 });
  assert.equal(document.querySelector('#ssh-tunnel-connection'), null);
  assert.equal((document.querySelector('#ssh-tunnel-pin') as HTMLInputElement).readOnly, true);
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!;
  for (const [id, value] of [
    ['host', 'bastion.test'],
    ['port', '2222'],
    ['username', 'ops'],
    ['keepalive', '45'],
  ]) {
    const input = document.querySelector<HTMLInputElement>('#ssh-tunnel-' + id)!;
    await act(async () => {
      setter.call(input, value);
      input.dispatchEvent(new Event('input', { bubbles: true }));
    });
  }
  assert.deepEqual(changes.slice(0, 4), [
    ['Host', 'bastion.test'],
    ['Port', '2222'],
    ['Username', 'ops'],
    ['KeepaliveSeconds', '45'],
  ]);
  await act(async () =>
    [...document.querySelectorAll('button')]
      .find((item) => item.textContent === 'Forget pin')!
      .click(),
  );
  assert.equal(forgotten, 1);
  await act(async () =>
    document.querySelector<HTMLButtonElement>('#ssh-tunnel-credential')!.click(),
  );
  const keyOption = [...document.querySelectorAll<HTMLElement>('[role="option"]')].find((item) =>
    item.textContent?.includes('Local SSH key'),
  );
  assert.ok(keyOption);
  await act(async () => keyOption.click());
  assert.deepEqual(changes.at(-1), ['CredentialId', 'credential']);

  await render({ Mode: 'connection', JumpConnectionId: 'direct' }, '');
  assert.equal(document.querySelector('#ssh-tunnel-host'), null);
  assert.equal(
    [...document.querySelectorAll<HTMLButtonElement>('button')].find(
      (item) => item.textContent === 'Forget pin',
    )!.disabled,
    true,
  );
  await act(async () =>
    document.querySelector<HTMLButtonElement>('#ssh-tunnel-connection')!.click(),
  );
  const optionLabels = [...document.querySelectorAll<HTMLElement>('[role="option"]')].map(
    (item) => item.textContent,
  );
  assert.ok(optionLabels.some((label) => label?.includes('Direct bastion')));
  assert.ok(
    optionLabels.every((label) => !label?.includes('Unsafe cycle') && !label?.includes('RDP host')),
  );
  const directOption = [...document.querySelectorAll<HTMLElement>('[role="option"]')].find((item) =>
    item.textContent?.includes('Direct bastion'),
  )!;
  await act(async () => directOption.click());

  const mode = document.querySelector<HTMLButtonElement>('#ssh-tunnel-mode')!;
  await act(async () =>
    mode.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true })),
  );
  const manual = [...document.querySelectorAll<HTMLElement>('[role="option"]')].find(
    (item) => item.textContent === 'Manual',
  );
  assert.ok(manual);
  await act(async () =>
    manual.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true })),
  );
  assert.deepEqual(changes.at(-1), ['Mode', 'manual']);
  fail = true;
  await render({ Mode: 'connection' }, '');
  assert.match(document.querySelector('[role="alert"]')!.textContent!, /Could not load/);
  await act(async () => root.unmount());
}

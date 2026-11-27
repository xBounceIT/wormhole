import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { useTunnelCapabilities } from '../../src/tunnel-capabilities';
import { tunnelKindAvailable } from '../../src/tunnel-state';

declare const assert: typeof import('node:assert/strict');

export async function runTunnelCapabilitiesTests() {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  const root = createRoot(document.getElementById('root')!);
  let request = 0;
  const pending: {
    resolve: (value: { openVpn: boolean }) => void;
    reject: (error: Error) => void;
  }[] = [];
  function Editor({ open }: { open: boolean }) {
    const capabilities = useTunnelCapabilities(open);
    return (
      <>
        <output>{JSON.stringify(capabilities)}</output>
        <select>
          {[0, 1, 2, 3, 4, 5, 6, 7, 8]
            .filter((kind) => tunnelKindAvailable(kind, capabilities))
            .map((kind) => (
              <option key={kind}>{kind}</option>
            ))}
        </select>
      </>
    );
  }
  async function render(open: boolean) {
    await act(async () => root.render(<Editor open={open} />));
  }
  const value = () => document.querySelector('output')!.textContent;
  const kinds = () =>
    [...document.querySelectorAll('option')].map((option) => Number(option.textContent));
  window.wormhole = undefined;
  await render(false);
  assert.equal(value(), 'null');
  await render(true);
  assert.equal(value(), '{"openVpn":false}');
  await render(false);
  window.wormhole = {
    getTunnelCapabilities: () => {
      request++;
      return new Promise((resolve, reject) => pending.push({ resolve, reject }));
    },
  } as unknown as Window['wormhole'];
  await render(true);
  assert.equal(request, 1);
  assert.equal(value(), 'null');
  assert.deepEqual(kinds(), [0, 2, 6, 7, 8]);
  await act(async () => pending[0].resolve({ openVpn: true }));
  assert.deepEqual(kinds(), [0, 1, 2, 3, 4, 5, 6, 7, 8]);
  await render(false);
  await render(true);
  await act(async () => pending[1].reject(new Error('unavailable')));
  assert.deepEqual(kinds(), [0, 2, 6, 7, 8]);
  await render(false);
  await render(true);
  await render(false);
  await render(true);
  await act(async () => pending[3].resolve({ openVpn: false }));
  await act(async () => pending[2].resolve({ openVpn: true }));
  assert.equal(value(), '{"openVpn":false}', 'stale success changed availability');
  await render(false);
  await render(true);
  await render(false);
  await render(true);
  await act(async () => pending[5].resolve({ openVpn: true }));
  await act(async () => pending[4].reject(new Error('late failure')));
  assert.equal(value(), '{"openVpn":true}', 'stale failure changed availability');
  await act(async () => root.unmount());
}

import { act, useState, type ComponentProps } from 'react';
import { flushSync } from 'react-dom';
import { createRoot } from 'react-dom/client';
import { TunnelsPage } from '../../src/App';
import { TooltipProvider } from '../../src/components/ui/tooltip';

type Tunnel = ComponentProps<typeof TunnelsPage>['tunnels'][number];

const tunnels: Tunnel[] = [
  { id: '1', name: 'Amsterdam', kind: 'Stormshield', endpoint: '192.0.2.21:443' },
  { id: '2', name: 'Azure Gateway', kind: 'Azure VPN', endpoint: 'azure-gateway.example.test:443' },
  { id: '3', name: 'Berlin', kind: 'Fortinet', endpoint: 'berlin.example.test:443' },
  { id: '4', name: 'Cloud Office', kind: 'Azure VPN', endpoint: 'cloud.example.test:443' },
  { id: '5', name: 'Dublin', kind: 'Cisco Secure Client', endpoint: 'dublin.example.test:443' },
  { id: '6', name: 'Frankfurt', kind: 'Fortinet', endpoint: '192.0.2.32:10443' },
  { id: '7', name: 'London', kind: 'WatchGuard', endpoint: 'london.example.test:443' },
  { id: '8', name: 'North Office', kind: 'Azure VPN', endpoint: 'north.example.test:443' },
  { id: '9', name: 'Oslo', kind: 'WatchGuard', endpoint: 'oslo.example.test:6443' },
  { id: '10', name: 'Paris', kind: 'Stormshield', endpoint: '192.0.2.55:443' },
  { id: '11', name: 'Remote Office', kind: 'Other provider' },
];

function Harness({ initial }: { initial: Tunnel[] }) {
  const [records, setRecords] = useState(initial);
  return (
    <TooltipProvider>
      <TunnelsPage
        credentials={[]}
        isAuthorized
        onTunnelCreated={(record) => setRecords((current) => [...current, record])}
        onTunnelDeleted={(id) =>
          setRecords((current) => current.filter((record) => record.id !== id))
        }
        onTunnelUpdated={(record) =>
          setRecords((current) => current.map((item) => (item.id === record.id ? record : item)))
        }
        onTunnelsLoaded={setRecords}
        tree={[]}
        tunnels={records}
      />
    </TooltipProvider>
  );
}

export async function run(columns: number, paneWidth = window.innerWidth) {
  const assert = (globalThis as typeof globalThis & { assert: typeof import('node:assert/strict') })
    .assert;
  const deleted: string[] = [];
  const updated: Parameters<NonNullable<Window['wormhole']>['updateTunnel']>[0][] = [];
  const importedProfile = Promise.withResolvers<{ contents: string }>();
  const initialList = Promise.withResolvers<Tunnel[]>();
  let deletionAllowed = false;
  const readDetails = (id: string) => ({ id, name: 'Dublin', kind: 6, settings: {} });
  let pendingRead: Promise<ReturnType<typeof readDetails>> | undefined;
  Object.assign(window, {
    confirm: () => true,
    wormhole: {
      listTunnels: () => initialList.promise,
      importOvpnProfile: () => importedProfile.promise,
      updateTunnel: async (request: (typeof updated)[number]) => {
        updated.push(request);
        return request;
      },
      onTunnelTestProgress: () => () => {},
      readTunnel: async (id: string) => pendingRead ?? readDetails(id),
      deleteTunnel: async (id: string) => {
        if (!deletionAllowed) return { deleted: false, error: 'This tunnel is in use.' };
        deleted.push(id);
        return { deleted: true };
      },
    },
  });
  document.documentElement.classList.toggle('dark', columns > 1);
  const pane = document.getElementById('root')!;
  pane.style.width = `${paneWidth}px`;
  const root = createRoot(pane);
  const settleLayout = () =>
    new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done)));
  // Wide layouts exercise deletion while a refresh is pending. Smaller
  // layouts start empty and must populate from the successful bridge reply.
  await act(async () => root.render(<Harness initial={columns >= 3 ? tunnels : []} />));
  if (columns < 3) {
    assert.equal(document.querySelector('[data-slot="card-title"]'), null);
    await act(async () => initialList.resolve(tunnels));
    assert.ok(
      document.querySelector('[aria-label="Edit Berlin"]'),
      'the bridge reply must populate the tunnel list',
    );
  }
  await act(settleLayout);

  const providerGroup = document.querySelector('[aria-label="Filter tunnels by provider"]')!;
  const provider = (label: string) =>
    [...providerGroup.querySelectorAll('button')].find(
      (button) =>
        [...button.childNodes]
          .map((node) => node.textContent?.trim())
          .filter(Boolean)
          .join(' ') === label,
    )!;
  const cards = () => [...document.querySelectorAll('[data-slot="card"]')];
  const names = () =>
    cards().map((card) => card.querySelector('[data-slot="card-title"]')?.textContent);
  const action = (label: string) =>
    document.querySelector<HTMLButtonElement>(`button[aria-label="${label}"]`)!;
  const search = document.querySelector<HTMLInputElement>('input[aria-label="Search tunnels"]')!;
  const add = [...document.querySelectorAll('button')].find(
    (button) => button.textContent === 'Add VPN tunnel',
  )!;
  const click = async (button: HTMLButtonElement) => act(async () => button.click());
  const changeSearch = (value: string) => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(search, value);
    search.dispatchEvent(new Event('input', { bubbles: true }));
  };
  const enterSearch = (value: string) => act(async () => changeSearch(value));
  const assertDialog = (title: string) =>
    assert.equal(
      document.querySelector('[role="dialog"][data-state="open"] [data-slot="dialog-title"]')
        ?.textContent,
      title,
    );
  const closeDialog = async () => {
    await click(
      document.querySelector<HTMLButtonElement>(
        '[role="dialog"][data-state="open"] [data-slot="dialog-close"]',
      )!,
    );
    await act(settleLayout);
  };

  const firstRowTop = cards()[0]!.getBoundingClientRect().top;
  assert.equal(
    cards().filter((card) => card.getBoundingClientRect().top === firstRowTop).length,
    columns,
  );
  assert.ok(firstRowTop > providerGroup.getBoundingClientRect().bottom);
  assert.ok(search.getBoundingClientRect().right <= add.getBoundingClientRect().left);
  assert.ok(add.getBoundingClientRect().right <= paneWidth);
  assert.ok(
    Math.abs(search.getBoundingClientRect().top - add.getBoundingClientRect().top) < 2,
    'Search and Add should share one row in the workspace pane',
  );
  assert.ok(document.querySelector('ul[aria-label="VPN tunnels"]')?.contains(cards()[0]!));
  const openEditor = async (kind: number, settings = {}) => {
    pendingRead = Promise.resolve({ id: '3', name: 'Berlin', kind, settings });
    await click(action('Edit Berlin'));
    const dialog = document.querySelector<HTMLElement>('[role="dialog"][data-state="open"]')!;
    const button = (label: string) =>
      [...dialog.querySelectorAll('button')].find((item) => item.textContent === label)!;
    return { dialog, button };
  };
  if (window.innerHeight <= 560) {
    const { dialog, button } = await openEditor(3, { Domain: 'example.test' });
    const field = dialog.querySelector<HTMLElement>('#tunnel-VerifyX509Name')!;
    field.scrollIntoView({ block: 'center' });
    const bounds = field.getBoundingClientRect();
    assert.ok(
      document.elementFromPoint(bounds.x + bounds.width / 2, bounds.y + bounds.height / 2) ===
        field,
    );
    const save = button('Save changes');
    assert.ok(save.getBoundingClientRect().bottom <= window.innerHeight);
    assert.ok(save.getBoundingClientRect().top >= bounds.bottom);
    await closeDialog();
    pendingRead = undefined;
  }
  if (columns < 3) return;

  assert.match(document.body.textContent!, /11 tunnels configured/);
  assert.equal(provider('All 11').getAttribute('aria-pressed'), 'true');
  assert.equal(provider('Azure VPN 3').querySelector('svg')?.getAttribute('aria-hidden'), 'true');

  await act(async () => {
    flushSync(() => changeSearch('berlin'));
    assert.equal(search.value, 'berlin');
    for (const label of ['Test Dublin', 'Edit Dublin', 'Delete Dublin']) {
      const button = action(label);
      assert.ok(button?.disabled, `${label} should be disabled while the search is deferred`);
    }
  });
  assert.deepEqual(names(), ['Berlin']);
  assert.equal(action('Delete Berlin').disabled, false);
  await enterSearch('');

  await click(provider('Azure VPN 3'));
  assert.deepEqual(names(), ['Azure Gateway', 'Cloud Office', 'North Office']);
  await enterSearch('  NORTH.EXAMPLE ');
  assert.deepEqual(names(), ['North Office']);
  assert.equal(provider('Azure VPN 3').getAttribute('aria-pressed'), 'true');
  await enterSearch('berlin');
  assert.match(document.body.textContent!, /No matching tunnels/);
  await click(provider('All 11'));
  assert.deepEqual(names(), ['Berlin']);
  await enterSearch('');

  await click(provider('Other provider 1'));
  assert.match(cards()[0]!.textContent!, /Endpoint unavailable/);
  assert.ok(cards()[0]!.querySelector('svg.lucide-network'));

  await click(provider('Cisco Secure Client 1'));
  const staleRead = Promise.withResolvers<ReturnType<typeof readDetails>>();
  pendingRead = staleRead.promise;
  await click(action('Edit Dublin'));
  add.focus();
  await click(add);
  await act(async () => staleRead.resolve(readDetails('5')));
  assertDialog('Add VPN tunnel');
  await closeDialog();
  assert.ok(document.activeElement === add, 'Closing Add should return focus to its button');
  const staleFailure = Promise.withResolvers<ReturnType<typeof readDetails>>();
  pendingRead = staleFailure.promise;
  const editButton = action('Edit Dublin');
  const testButton = action('Test Dublin');
  await click(editButton);
  await click(testButton);
  await act(async () => staleFailure.reject(new Error('Stale VPN read failure')));
  assertDialog('Test VPN tunnel');
  await closeDialog();
  assert.ok(document.activeElement === testButton, 'Closing Test should focus its button');
  assert.equal(document.querySelector('[role="alert"]'), null);

  pendingRead = undefined;
  await click(editButton);
  assertDialog('Edit VPN tunnel');
  await closeDialog();
  assert.ok(document.activeElement === editButton, 'Closing Edit should focus its button');

  await click(action('Delete Dublin'));
  assert.equal(document.querySelector('[role="alert"]')?.textContent, 'This tunnel is in use.');
  assert.deepEqual(names(), ['Dublin']);
  deletionAllowed = true;
  await click(action('Delete Dublin'));
  assert.deepEqual(deleted, ['5']);
  await act(async () => initialList.resolve(tunnels));
  assert.equal(document.querySelector('[role="alert"]'), null);
  assert.equal(provider('Cisco Secure Client 0').getAttribute('aria-pressed'), 'true');
  assert.match(document.body.textContent!, /No matching tunnels/);
  await click(provider('All 10'));
  assert.equal(provider('Cisco Secure Client 0'), undefined);
  assert.match(document.body.textContent!, /10 tunnels configured/);

  const providers = [
    [
      2,
      {
        UseSingleSignOn: 'switch',
        TrustServerCertificate: 'switch',
        TotpSecret: 'password',
        ServerCertSha256Pin: 'text',
      },
    ],
    [3, { TrustServerCertificate: 'switch', VerifyX509Name: 'text' }],
    [4, { UseOtp: 'checkbox', TrustServerCertificate: 'checkbox' }],
    [6, { TrustServerCertificate: 'checkbox' }],
    [
      7,
      {
        Host: 'text',
        Port: 'number',
        Username: 'text',
        Password: 'password',
        ServerCertSha256Pin: 'text',
        Mtu: 'number',
      },
    ],
  ] as const;
  for (const [kind, fields] of providers) {
    const { dialog } = await openEditor(kind);
    await click(
      [...dialog.querySelectorAll('button')].find((item) => /advanced/i.test(item.textContent!))!,
    );
    for (const [key, type] of Object.entries(fields)) {
      const control = dialog.querySelector<HTMLInputElement | HTMLButtonElement>('#tunnel-' + key)!;
      assert.ok(control.labels?.[0]?.textContent, 'Missing label for ' + key);
      assert.equal(control.getAttribute('role') ?? control.type, type, key);
      if (type === 'switch' || type === 'checkbox') {
        const before = control.getAttribute('aria-checked');
        await click(control as HTMLButtonElement);
        assert.equal(control.getAttribute('aria-checked'), before === 'true' ? 'false' : 'true');
      }
    }
    if (kind === 2) {
      assert.ok(dialog.querySelector('#tunnel-UseSamlCallback'));
      assert.ok(dialog.querySelector<HTMLInputElement>('#tunnel-Username')!.disabled);
      assert.equal(dialog.querySelector<HTMLInputElement>('#tunnel-Realm')!.disabled, false);
      await click(dialog.querySelector<HTMLButtonElement>('#tunnel-UseSingleSignOn')!);
      assert.equal(dialog.querySelector('#tunnel-UseSamlCallback'), null);
    }
    await closeDialog();
  }

  for (const authMode of [1, 2]) {
    const { dialog } = await openEditor(3, { AuthMode: authMode });
    assert.equal(
      dialog.querySelector('#tunnel-AuthMode')?.textContent,
      authMode === 1 ? 'Username and password' : 'SAML',
    );
    assert.equal(Boolean(dialog.querySelector('#tunnel-Username')), authMode === 1);
    assert.equal(
      Boolean(dialog.querySelector('input#tunnel-Password[type="password"]')),
      authMode === 1,
    );
    await closeDialog();
  }

  const { dialog, button } = await openEditor(1, { ProfileOvpn: 'original profile' });
  const importButton = button('Import from file…');
  await click(importButton);
  assert.equal(importButton.disabled, true);
  await act(async () => importedProfile.resolve({ contents: 'client\nremote vpn.example.test' }));
  assert.equal(dialog.querySelector('textarea')!.value, 'client\nremote vpn.example.test');
  assert.equal(updated.length, 0);
  await click(button('Save changes'));
  assert.equal(updated.length, 1);
  assert.equal(updated[0]!.settings.ProfileOvpn, 'client\nremote vpn.example.test');
}

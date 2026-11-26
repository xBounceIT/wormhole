import { act, useState, type ComponentProps } from 'react';
import { flushSync } from 'react-dom';
import { createRoot } from 'react-dom/client';
import { CredentialsPage, TunnelsPage } from '../../src/App';
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
  { id: '12', name: 'Rome', kind: 'Forcepoint' },
  { id: '13', name: 'Stockholm', kind: 'WireGuard' },
  { id: '14', name: 'Vienna', kind: 'OpenVPN' },
  { id: '15', name: 'Warsaw', kind: 'Fortinet IPsec' },
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
  const deletionAttempts: string[] = [];
  let deletionAllowed = false;
  const readDetails = (id: string) => ({ id, name: 'Dublin', kind: 6, settings: {} });
  let pendingRead: Promise<ReturnType<typeof readDetails>> | undefined;
  Object.assign(window, {
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
        deletionAttempts.push(id);
        if (!deletionAllowed) return { deleted: false, error: 'This tunnel is in use.' };
        deleted.push(id);
        return { deleted: true };
      },
    },
  });
  const dark = columns > 1;
  const oled = dark && paneWidth === 600;
  document.documentElement.classList.toggle('dark', dark);
  document.documentElement.classList.toggle('oled', oled);
  const pane = document.getElementById('root')!;
  pane.style.width = `${paneWidth}px`;
  pane.style.backgroundColor = 'var(--canvas)';
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

  const providerTrigger = document.querySelector<HTMLButtonElement>(
    '[aria-label^="Filter tunnels by provider:"]',
  )!;
  const providerMenu = () =>
    document.querySelector('[data-slot="dropdown-menu-content"][data-state="open"]');
  const provider = (label: string) =>
    [...(providerMenu()?.querySelectorAll<HTMLElement>('[role="menuitemradio"]') ?? [])].find(
      (item) =>
        [...item.childNodes]
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
  const click = async (element: HTMLElement) => act(async () => element.click());
  const openProviderMenu = async () => {
    await act(async () => {
      providerTrigger.focus();
      providerTrigger.dispatchEvent(
        new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true, cancelable: true }),
      );
    });
    assert.ok(providerMenu(), 'The provider menu opens with the keyboard');
  };
  const selectProvider = async (label: string) => {
    if (!providerMenu()) await openProviderMenu();
    const option = provider(label);
    assert.ok(option, `Provider option ${label} should be available`);
    await click(option);
    assert.equal(providerTrigger.getAttribute('aria-expanded'), 'false');
  };
  const changeSearch = (value: string) => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(search, value);
    search.dispatchEvent(new Event('input', { bubbles: true }));
  };
  const enterSearch = (value: string) => act(async () => changeSearch(value));
  const assertDialog = (title: string) => {
    const dialog = document.querySelector('[role="dialog"][data-state="open"]')!;
    assert.equal(dialog.querySelector('[data-slot="dialog-title"]')?.textContent, title);
    assert.equal(getComputedStyle(dialog).borderRadius, '16px');
  };
  const closeDialog = async () => {
    await click(
      document.querySelector<HTMLButtonElement>(
        '[role="dialog"][data-state="open"] [data-slot="dialog-close"]',
      )!,
    );
    await act(settleLayout);
  };

  const firstRowTop = cards()[0]!.getBoundingClientRect().top;
  assert.ok(document.querySelector('ul[aria-label="VPN tunnels"]')?.contains(cards()[0]!));
  assert.equal(
    cards().filter((card) => card.getBoundingClientRect().top === firstRowTop).length,
    columns,
  );
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
  const heading = document.querySelector('h2')!;
  const headingBounds = heading.getBoundingClientRect();
  const searchBounds = search.getBoundingClientRect();
  const filterBounds = providerTrigger.getBoundingClientRect();
  const addBounds = add.getBoundingClientRect();
  assert.equal(searchBounds.left, headingBounds.left);
  assert.equal(searchBounds.top - headingBounds.bottom, 16);
  assert.equal(firstRowTop - addBounds.bottom, 16);
  assert.ok(filterBounds.right <= addBounds.left && addBounds.right <= paneWidth - 24);
  assert.equal(filterBounds.top, addBounds.top);
  if (paneWidth >= 600) {
    assert.equal(searchBounds.top, addBounds.top);
    assert.ok(searchBounds.right <= filterBounds.left);
  } else {
    assert.ok(searchBounds.bottom < filterBounds.top, 'Actions wrap below search in narrow panes');
  }
  assert.equal(getComputedStyle(heading).fontSize, '20px');
  assert.equal(searchBounds.height, 32);
  assert.ok(parseFloat(getComputedStyle(search).borderTopLeftRadius) >= 16);
  assert.equal(addBounds.height, 32);
  assert.equal(filterBounds.height, 32);
  assert.match(providerTrigger.getAttribute('aria-label')!, /All providers$/);
  const visibleLogo = (element: Element) => {
    const visibleImages = [...element.querySelectorAll('img')].filter(
      (image) => getComputedStyle(image).display !== 'none',
    );
    assert.equal(visibleImages.length, 1, element.textContent ?? undefined);
    const image = visibleImages[0]!;
    assert.equal(image.alt, '');
    assert.equal(image.getAttribute('aria-hidden'), 'true');
    assert.equal(getComputedStyle(image.parentElement!).backgroundColor, 'rgb(255, 255, 255)');
    assert.match(image.src, /^(data:image\/svg\+xml[;,])|\.svg$/);
    return image;
  };
  const sample = document.createElement('canvas');
  sample.width = sample.height = 24;
  const context = sample.getContext('2d', { willReadFrequently: true })!;
  const filterLogos = new Map<string, string>();
  await openProviderMenu();
  assert.equal(provider('All providers 15')?.getAttribute('aria-checked'), 'true');
  for (const kind of new Set(tunnels.map((tunnel) => tunnel.kind))) {
    if (kind === 'Other provider') continue;
    const count = tunnels.filter((tunnel) => tunnel.kind === kind).length;
    const filter = provider(`${kind} ${count}`)!;
    const image = visibleLogo(filter);
    await image.decode();
    assert.equal(image.offsetWidth, 14);
    const tile = image.parentElement!;
    assert.equal(tile.offsetWidth, tile.offsetHeight);
    assert.ok(parseFloat(getComputedStyle(tile).borderTopLeftRadius) >= tile.offsetWidth / 2);
    context.clearRect(0, 0, 24, 24);
    context.drawImage(image, 0, 0, 24, 24);
    const pixels = context.getImageData(0, 0, 24, 24).data;
    const alpha = pixels.filter((_, index) => index % 4 === 3);
    assert.ok(
      alpha.some((value) => value === 0),
      `${kind} SVG needs transparency`,
    );
    assert.ok(
      alpha.some((value) => value > 128),
      `${kind} SVG needs a visible mark`,
    );
    filterLogos.set(kind, image.src);
  }
  await selectProvider('All providers 15');
  assert.equal(filterLogos.get('Fortinet IPsec'), filterLogos.get('Fortinet'));
  const appFont = getComputedStyle(document.body).fontFamily;
  for (const card of cards()) {
    const bounds = card.getBoundingClientRect();
    assert.ok(bounds.height <= 128, 'Tunnel cards should fit in a compact row');
    const endpoint = card.querySelector('[data-slot="card-description"]')!;
    assert.equal(getComputedStyle(endpoint).fontFamily, appFont, 'Endpoints use the app font');
    const badge = card.querySelector('[data-slot="badge"]')!;
    assert.equal(badge.getAttribute('data-state'), null, 'Provider badges need no tooltip trigger');
    const kind = badge.textContent ?? '';
    const source = filterLogos.get(kind);
    if (source) {
      const image = visibleLogo(card);
      await image.decode();
      assert.equal(image.src, source);
      assert.equal(image.getBoundingClientRect().width, 20);
    }
    for (const button of card.querySelectorAll('button')) {
      const actionBounds = button.getBoundingClientRect();
      assert.ok(
        actionBounds.top >= bounds.top && actionBounds.bottom <= bounds.bottom,
        'Every action must fit inside the compact card',
      );
    }
  }
  if (oled) {
    const tunnelCard = cards()[0]!;
    const reference = document.createElement('div');
    reference.style.cssText = 'position:fixed;inset:0;visibility:hidden;background:var(--canvas)';
    pane.append(reference);
    const referenceRoot = createRoot(reference);
    try {
      await act(async () =>
        referenceRoot.render(
          <TooltipProvider>
            <CredentialsPage
              initialCredentials={[
                {
                  id: 'reference',
                  name: 'Reference credential',
                  protocol: 'ssh',
                  kind: 'password',
                  username: 'example',
                  provider: 'Local',
                  canEdit: true,
                  canDelete: true,
                },
              ]}
              isAuthorized
              onCreate={async () => {}}
              onDelete={async () => {}}
              onUpdate={async () => {}}
            />
          </TooltipProvider>,
        ),
      );
      await act(settleLayout);
      const paint = (element: Element) => {
        const { backgroundColor, borderTopColor, color } = getComputedStyle(element);
        return { backgroundColor, borderTopColor, color };
      };
      assert.deepEqual(paint(tunnelCard), paint(reference.querySelector('[data-slot="card"]')!));
      assert.deepEqual(
        paint(tunnelCard.querySelector('[data-slot="badge"]')!),
        paint(reference.querySelector('[data-slot="badge"]')!),
      );
      assert.deepEqual(
        paint(search),
        paint(reference.querySelector('[aria-label="Search credentials"]')!),
      );
      const sourceFilter = reference.querySelector<HTMLButtonElement>(
        '[aria-label^="Filter credentials by source"]',
      )!;
      assert.deepEqual(paint(providerTrigger), paint(sourceFilter));
      const referenceHeading = reference.querySelector('h2')!.getBoundingClientRect();
      const referenceSearch = reference
        .querySelector('[aria-label="Search credentials"]')!
        .getBoundingClientRect();
      assert.equal(headingBounds.left, referenceHeading.left);
      assert.equal(headingBounds.top, referenceHeading.top);
      assert.equal(searchBounds.top, referenceSearch.top);
    } finally {
      await act(async () => referenceRoot.unmount());
      reference.remove();
    }
  } else if (dark) {
    const shade = (color: string, behind: string) => {
      context.fillStyle = behind;
      context.fillRect(0, 0, 1, 1);
      context.fillStyle = color;
      context.fillRect(0, 0, 1, 1);
      return context.getImageData(0, 0, 1, 1).data[0]!;
    };
    const canvas = getComputedStyle(pane).backgroundColor;
    const card = getComputedStyle(cards()[0]!);
    const background = shade(canvas, '#000');
    const cardBackground = shade(card.backgroundColor, canvas);
    assert.ok(cardBackground - background >= 10, 'Cards must stand out against the canvas');
    assert.ok(shade(card.borderTopColor, card.backgroundColor) - cardBackground >= 30);
    const input = getComputedStyle(search);
    assert.ok(shade(input.borderTopColor, canvas) - shade(input.backgroundColor, canvas) >= 20);
  }
  await selectProvider('OpenVPN 1');
  assert.equal(providerTrigger.dataset.active, 'true');
  assert.match(providerTrigger.getAttribute('aria-label')!, /OpenVPN$/);
  assert.equal(visibleLogo(cards()[0]!).src, filterLogos.get('OpenVPN'));
  await openProviderMenu();
  assert.equal(provider('OpenVPN 1')?.getAttribute('aria-checked'), 'true');
  if (paneWidth >= 600) {
    await selectProvider('Cisco Secure Client 1');
    assert.equal(search.getBoundingClientRect().top, add.getBoundingClientRect().top);
  }
  await selectProvider('All providers 15');
  assert.equal(providerTrigger.dataset.active, 'false');
  if (columns < 3) return;

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
  await click(action('Clear search'));
  assert.equal(search.value, '');
  assert.ok(document.activeElement === search);

  await selectProvider('Azure VPN 3');
  assert.deepEqual(names(), ['Azure Gateway', 'Cloud Office', 'North Office']);
  await enterSearch('  NORTH.EXAMPLE ');
  assert.deepEqual(names(), ['North Office']);
  assert.match(providerTrigger.getAttribute('aria-label')!, /Azure VPN$/);
  await enterSearch('berlin');
  assert.match(document.body.textContent!, /No matching tunnels/);
  await selectProvider('All providers 15');
  assert.deepEqual(names(), ['Berlin']);
  await enterSearch('');

  await selectProvider('Other provider 1');
  assert.match(cards()[0]!.textContent!, /Endpoint unavailable/);
  assert.ok(cards()[0]!.querySelector('svg.lucide-network'));

  await selectProvider('Cisco Secure Client 1');
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

  const deleteButton = action('Delete Dublin');
  const deleteDialog = () => document.querySelector('[role="alertdialog"][data-state="open"]')!;
  const deleteAction = (label: string) =>
    [...deleteDialog().querySelectorAll('button')].find(
      (button) => button.textContent?.trim() === label,
    )!;
  deleteButton.focus();
  await click(deleteButton);
  assert.equal(getComputedStyle(deleteDialog()).borderRadius, '16px');
  const footer = getComputedStyle(deleteDialog().querySelector('[data-slot="dialog-footer"]')!);
  assert.equal(footer.borderBottomLeftRadius, '16px');
  assert.equal(footer.borderBottomRightRadius, '16px');
  assert.equal(document.activeElement, deleteAction('Cancel'));
  await click(deleteAction('Cancel'));
  assert.deepEqual(deletionAttempts, []);
  await click(deleteButton);
  await click(deleteAction('Delete VPN tunnel'));
  assert.equal(document.querySelector('[role="alert"]')?.textContent, 'This tunnel is in use.');
  assert.deepEqual(names(), ['Dublin']);
  deletionAllowed = true;
  await click(action('Delete Dublin'));
  await click(deleteAction('Delete VPN tunnel'));
  assert.deepEqual(deleted, ['5']);
  await act(async () => initialList.resolve(tunnels));
  assert.equal(document.querySelector('[role="alert"]'), null);
  assert.match(document.body.textContent!, /No matching tunnels/);
  await openProviderMenu();
  assert.equal(provider('Cisco Secure Client 0')?.getAttribute('aria-checked'), 'true');
  await selectProvider('All providers 14');
  await openProviderMenu();
  assert.equal(provider('Cisco Secure Client 0'), undefined);
  await selectProvider('All providers 14');
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

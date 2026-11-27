import { mountVaultTunnelScreen, type VaultTunnelApi } from '../../src/vault-tunnel-screen.ts';
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm } from '@hpke/core';
const id = '11111111-1111-4111-8111-111111111111';
const selection = { id, rowVersion: '7' };
const context = { workspaceId: id, requestId: id, selection };
const check = (condition: unknown, message: string) => {
  if (!condition) throw Error(message);
};
const tick = () => new Promise((resolve) => setTimeout(resolve, 5));
async function until(check: () => boolean) {
  for (let i = 0; i < 200; i++) {
    if (check()) return;
    await tick();
  }
  throw Error('Timed out');
}
async function sealed(
  publicKey: string,
  projection: unknown,
  imported?: { importId: string; kind: number },
) {
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });
  const encoder = new TextEncoder();
  const parts = [
    encoder.encode(imported ? 'wormhole/v1/tunnel-import' : 'wormhole/v1/tunnel-editor'),
    ...(imported ? [id, id, imported.importId, String(imported.kind)] : [id, id, id, '7']).flatMap(
      (value) => {
        const size = new Uint8Array(4);
        new DataView(size.buffer).setUint32(0, value.length);
        return [size, encoder.encode(value)];
      },
    ),
  ];
  const info = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    info.set(part, offset);
    offset += part.length;
  }
  const sender = await suite.createSenderContext({
    recipientPublicKey: await suite.kem.deserializePublicKey(
      Uint8Array.from(atob(publicKey), (c) => c.charCodeAt(0)),
    ),
    info,
  });
  const base64 = (value: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(value)));
  return {
    ...(imported
      ? { workspaceId: id, editorId: id, importId: imported.importId, kind: imported.kind }
      : { workspaceId: id, tunnelId: id, requestId: id, rowVersion: '7' }),
    bundle: {
      formatVersion: 1,
      suiteId: 2,
      enc: base64(sender.enc),
      ciphertext: base64(await sender.seal(encoder.encode(JSON.stringify(projection)))),
    },
  };
}
export async function runVaultTunnelScreenTests() {
  function setup(overrides: Partial<VaultTunnelApi> = {}) {
    const card = document.createElement('section');
    card.className = 'startup-card';
    document.body.append(card);
    let calls = 0,
      closed = 0,
      patch: Uint8Array | undefined,
      submitted: any;
    const dispose = mountVaultTunnelScreen(card, {
      contentProtectionAvailable: true,
      importProfile: async () => null,
      discardImport: async () => {},
      capabilities: async () => ({ openVpn: true }),
      context: async () => ({ ...context, selection: null }),
      references: async () => ({
        connections: [{ id, name: 'SSH' }],
        credentials: [],
        tunnels: [],
      }),
      read: async (key) =>
        sealed(key, {
          name: 'Stored',
          kind: 2,
          settings: { Host: 'gateway', Port: 443 },
          present: ['Password'],
        }),
      save: async (input) => {
        calls++;
        patch = input.patch;
        submitted = { ...input, patch: new TextDecoder().decode(input.patch) };
        return false;
      },
      close: async () => {
        closed++;
      },
      ...overrides,
    });
    return {
      card,
      dispose,
      get calls() {
        return calls;
      },
      get closed() {
        return closed;
      },
      get patch() {
        return patch;
      },
      get submitted() {
        return submitted;
      },
      status: () => card.querySelector('[role=status]')!.textContent!,
      controls: () => card.querySelector('fieldset')!,
      name: () => card.querySelector<HTMLInputElement>('[name=name]')!,
      kind: () => card.querySelector<HTMLSelectElement>('[name=kind]')!,
      submit: () =>
        card.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true })),
      remove() {
        dispose();
        card.remove();
      },
    };
  }
  const ready = async (v: ReturnType<typeof setup>) => until(() => !v.controls().disabled);
  const change = (
    element: HTMLInputElement | HTMLSelectElement,
    value: string,
    event = 'input',
  ) => {
    element.value = value;
    element.dispatchEvent(new Event(event));
  };
  let confirm = true;
  window.confirm = () => confirm;
  const v = setup();
  await ready(v);
  check(v.card.querySelector('h1')!.textContent === 'Add VPN tunnel', 'create heading');
  v.submit();
  check(v.status().includes('128'), 'blank name accepted');
  v.name().value = 'x'.repeat(129);
  v.submit();
  check(v.calls === 0, 'long name accepted');
  v.name().value = 'Draft';
  change(v.kind(), '2', 'change');
  const secret = v.card.querySelector<HTMLSelectElement>('[data-field=Password] select')!;
  change(secret, 'replace', 'change');
  v.submit();
  check(v.status().includes('Enter password'), 'empty replacement accepted');
  const password = v.card.querySelector<HTMLInputElement>('[name=Password]')!;
  change(password, 'temporary-password');
  v.submit();
  v.submit();
  check(v.calls === 1 && v.controls().disabled, 'duplicate submission');
  check(password.value === '' && v.patch!.every((x) => x === 0), 'submitted factor retained');
  await ready(v);
  check(v.status().includes('not saved'), 'save error absent');
  check(JSON.parse(v.submitted.patch).Password === 'temporary-password', 'factor absent');
  v.submit();
  check(v.calls === 1, 'failed factor silently reused');
  confirm = false;
  change(v.kind(), '6', 'change');
  check(v.kind().value === '2', 'declined provider change');
  confirm = true;
  change(v.kind(), '6', 'change');
  check(!v.card.textContent!.includes('temporary-password'), 'factor survived provider switch');
  for (const eventName of ['copy', 'cut']) {
    const event = new Event(eventName, { cancelable: true });
    v.card.dispatchEvent(event);
    check(event.defaultPrevented, 'copy allowed');
  }
  v.card.querySelector<HTMLButtonElement>('button[name=cancel]')!.click();
  await tick();
  check(v.closed === 1 && v.name().value === '', 'close failed');
  v.remove();
  const existing = setup({ context: async () => context });
  await ready(existing);
  check(
    existing.name().value === 'Stored' && existing.kind().value === '2',
    'stored projection not loaded',
  );
  existing.submit();
  await ready(existing);
  check(
    existing.submitted.rowVersion === '7' &&
      existing.submitted.metadata.id === id &&
      existing.submitted.patch === '{}',
    'edit did not preserve',
  );
  change(existing.kind(), '6', 'change');
  change(existing.kind(), '2', 'change');
  check(
    existing.card.querySelector<HTMLInputElement>('[name=Host]')!.value === 'gateway' &&
      existing.card.textContent!.includes('Keep stored value'),
    'return lost original config',
  );
  existing.submit();
  await ready(existing);
  check(existing.submitted.patch === '{}', 'restored provider replaced factors');
  existing.remove();
  for (const result of ['success', 'throw', 'reject']) {
    let held: Uint8Array | undefined;
    const s = setup({
      save: (input) => {
        held = input.patch;
        if (result === 'throw') throw Error('private-secret');
        return result === 'success'
          ? Promise.resolve(true)
          : Promise.reject(Error('private-secret'));
      },
      close: async () => {
        throw Error('close unavailable');
      },
    });
    await ready(s);
    s.name().value = 'Draft';
    s.submit();
    await tick();
    check(
      held!.every((x) => x === 0),
      'failure retained patch',
    );
    check(!s.status().includes('private-secret'), 'backend error disclosure');
    check(
      result === 'success' ? s.controls().disabled : s.status().includes('not saved'),
      'save outcome',
    );
    s.remove();
  }
  const unsupported = setup({
    context: async () => context,
    capabilities: async () => ({ openVpn: false }),
    read: async (key) =>
      sealed(key, { name: 'Stored OpenVPN', kind: 1, settings: {}, present: ['ProfileOvpn'] }),
  });
  await ready(unsupported);
  check(
    unsupported.card.querySelector<HTMLButtonElement>('button[type=submit]')!.disabled &&
      unsupported.status().includes('no usable OpenVPN'),
    'unavailable provider enabled',
  );
  unsupported.submit();
  check(unsupported.calls === 0, 'unsupported save dispatched');
  change(unsupported.kind(), '3', 'change');
  check(unsupported.kind().value === '1', 'unsupported provider selected');
  change(unsupported.kind(), '2', 'change');
  check(
    !unsupported.card.querySelector<HTMLButtonElement>('button[type=submit]')!.disabled,
    'available provider blocked',
  );
  unsupported.remove();
  const badRefs: unknown[] = [
    null,
    { connections: [], credentials: [], tunnels: [], extra: true },
    { connections: null, credentials: [], tunnels: [] },
    { connections: Array(50_001).fill(null), credentials: [], tunnels: [] },
    {
      connections: [
        { id, name: 'SSH' },
        { id, name: 'duplicate' },
      ],
      credentials: [],
      tunnels: [],
    },
    { connections: [{ id: 'bad', name: 'SSH' }], credentials: [], tunnels: [] },
    { connections: [], credentials: [{ id, name: '', extra: true }] },
  ];
  const failures: Partial<VaultTunnelApi>[] = [
    { capabilities: async () => null },
    {
      capabilities: async () => {
        throw Error('private-secret');
      },
    },
    { context: async () => null },
    { context: async () => ({ ...context, selection: { id: 'bad' } }) },
    {
      context: async () => {
        throw Error('private-secret');
      },
    },
    {
      references: async () => {
        throw Error('private-secret');
      },
    },
    ...badRefs.map((refs) => ({ references: async () => refs })),
    { context: async () => context, read: async () => ({}) },
    {
      context: async () => context,
      read: async (key) =>
        sealed(key, {
          name: 'bad',
          kind: 2,
          settings: { Password: 'private-secret' },
          present: [],
        }),
    },
  ];
  for (const options of failures) {
    const s = setup(options);
    await until(() => s.status().includes('unavailable'));
    check(
      s.controls().disabled && !s.card.textContent!.includes('private-secret'),
      'unsafe initialization',
    );
    s.remove();
  }
  for (const phase of ['context', 'references', 'capabilities', 'read', 'save']) {
    let release!: (value: any) => void,
      requested = false;
    const wait = () => {
      requested = true;
      return new Promise<any>((r) => (release = r));
    };
    const s = setup(
      phase === 'context'
        ? { context: wait }
        : phase === 'references'
          ? { references: wait }
          : phase === 'capabilities'
            ? { capabilities: wait }
            : phase === 'read'
              ? { context: async () => context, read: wait }
              : { save: wait },
    );
    if (phase === 'save') {
      await ready(s);
      s.name().value = 'Pending';
      s.submit();
    }
    await until(() => requested);
    window.dispatchEvent(new Event('pagehide'));
    release(
      phase === 'context'
        ? context
        : phase === 'references'
          ? { connections: [], credentials: [], tunnels: [] }
          : true,
    );
    await tick();
    check(
      s.controls().disabled && s.name().value === '' && !s.card.querySelector('[name=Password]'),
      'late result revived editor',
    );
    s.remove();
  }

  const legacy = setup({
    context: async () => context,
    read: async (key) =>
      sealed(key, {
        name: 'Legacy WatchGuard',
        kind: 3,
        settings: { Server: 'vpn.example', AuthMode: 2, UseSingleSignOn: true },
        present: [],
      }),
    importProfile: async (choice) =>
      sealed(
        choice.publicKey,
        { name: 'Imported', kind: 3, settings: { AuthMode: 1 }, present: ['ProfileOvpn'] },
        choice,
      ),
  });
  await ready(legacy);
  check(
    legacy.card.querySelector<HTMLSelectElement>('[name=AuthMode]')!.value === '2',
    'legacy SSO not shown',
  );
  legacy.card.querySelector<HTMLButtonElement>('[data-import=openvpn]')!.click();
  await until(() => legacy.status().startsWith('Profile imported'));
  check(
    legacy.card.querySelector<HTMLSelectElement>('[name=AuthMode]')!.value === '1',
    'legacy flag hid imported manual mode',
  );
  check(
    !legacy.card.querySelector<HTMLElement>('[data-field=Password]')!.hidden,
    'manual password hidden',
  );
  legacy.submit();
  await ready(legacy);
  check(legacy.submitted.patch === '{}', 'import unexpectedly copied fields to patch');
  legacy.remove();
  for (const provider of [1, 3, 4, 5, 6]) {
    let importedCalls = 0,
      discards = 0;
    const s = setup({
      importProfile: async (choice) => {
        importedCalls++;
        check(choice.kind === provider, 'wrong import provider');
        check(
          Object.keys(choice).sort().join(',') === 'format,importId,kind,publicKey',
          'path in document',
        );
        return sealed(
          choice.publicKey,
          {
            name: 'Imported tunnel',
            kind: provider,
            settings:
              provider === 6
                ? { Host: 'imported.example' }
                : provider === 3
                  ? { AuthMode: 1 }
                  : provider === 4
                    ? { Mode: 1 }
                    : {},
            present: provider === 5 ? ['ServerSecretHex'] : provider === 6 ? [] : ['ProfileOvpn'],
          },
          choice,
        );
      },
      discardImport: async () => {
        discards++;
      },
    });
    await ready(s);
    change(s.kind(), String(provider), 'change');
    const buttons = s.card.querySelectorAll<HTMLButtonElement>('[data-import]');
    check(buttons.length === (provider === 3 ? 2 : 1), 'wrong formats');
    confirm = false;
    buttons[0].click();
    await tick();
    check(importedCalls === 0, 'declined import');
    confirm = true;
    buttons[0].click();
    s.submit();
    buttons[0].click();
    await until(() => s.status().startsWith('Profile imported'));
    check(importedCalls === 1 && s.calls === 0, 'parallel import/save allowed');
    check(s.name().value === 'Imported tunnel', 'import name missing');
    if (provider === 5) check(s.card.textContent!.includes('Stored'), 'Azure presence absent');
    if ([1, 3, 4].includes(provider))
      check(
        s.card.querySelector<HTMLSelectElement>('[data-field=ProfileOvpn] select')!.options[0]
          .textContent === 'Keep stored value',
        'import presence absent',
      );
    s.submit();
    await ready(s);
    check(!('ProfileOvpn' in JSON.parse(s.submitted.patch)), 'profile serialized into UI patch');
    change(s.kind(), '2', 'change');
    await until(() => !s.controls().disabled);
    check(discards === 1, 'provider change did not discard');
    s.remove();
  }
  for (const mode of [
    'cancel',
    'failure',
    'invalid-preview',
    'wrong-provider',
    'invalid-projection',
    'discard-failure',
    'late-import',
    'late-discard',
  ]) {
    let release!: (value: unknown) => void,
      requested = false;
    const s = setup({
      importProfile: async (choice) => {
        if (mode === 'late-import') {
          requested = true;
          return new Promise((r) => (release = r));
        }
        if (mode === 'cancel') return null;
        if (mode === 'failure') throw Error('private-secret');
        if (mode === 'invalid-preview') return {};
        return sealed(
          choice.publicKey,
          {
            name: 'Imported',
            kind: mode === 'wrong-provider' ? 3 : 1,
            settings: mode === 'invalid-projection' ? { Password: 'private-secret' } : {},
            present: ['ProfileOvpn'],
          },
          choice,
        );
      },
      discardImport: async () => {
        if (mode === 'late-discard') {
          requested = true;
          await new Promise((r) => (release = r));
        }
        if (mode === 'discard-failure') throw Error('private-secret');
      },
    });
    await ready(s);
    change(s.kind(), '1', 'change');
    s.name().value = 'Keep name';
    s.card.querySelector<HTMLButtonElement>('[data-import]')!.click();
    if (mode === 'late-import') {
      await until(() => requested);
      s.card.querySelector<HTMLButtonElement>('[name=cancel]')!.click();
      release({});
      await tick();
      check(s.name().value === '' && s.controls().disabled, 'late import revived');
    } else if (mode === 'cancel' || mode === 'failure') {
      await until(() => !s.controls().disabled);
      check(s.name().value === 'Keep name', 'failure destroyed form');
      check(
        s.status().includes(mode === 'cancel' ? 'canceled' : 'could not'),
        'failure not reported',
      );
    } else if (mode === 'discard-failure' || mode === 'late-discard') {
      await until(() => s.status().startsWith('Profile imported'));
      check(s.name().value === 'Keep name', 'name overwritten');
      change(s.kind(), '2', 'change');
      if (mode === 'late-discard') {
        await until(() => requested);
        s.dispose();
        release(undefined);
        await tick();
      } else await until(() => s.closed === 1);
      check(s.controls().disabled, 'uncertain discard kept editor active');
    } else {
      await until(() => s.closed === 1);
      check(s.controls().disabled, 'invalid preview allowed save');
    }
    check(!s.card.textContent!.includes('private-secret'), 'diagnostic exposed');
    s.remove();
  }
  const linux = setup({ contentProtectionAvailable: false });
  await ready(linux);
  check(linux.card.textContent!.includes('unavailable on Linux'), 'capture warning');
  linux.remove();
  const visual = setup({
    context: async () => context,
    read: async (key) =>
      sealed(key, {
        name: 'WatchGuard imported profile',
        kind: 3,
        settings: { Server: 'vpn.example', AuthMode: 1 },
        present: ['ProfileOvpn'],
      }),
  });
  await ready(visual);
  return () => visual.remove();
}

import {
  mountVaultRdpCredentialsScreen,
  type VaultRdpCredentialsApi,
} from '../../src/vault-rdp-credentials-screen.ts';
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm } from '@hpke/core';
import { rdpCredentialsInfo } from '../../electron/vault-rdp-credentials.ts';
const check = (condition: unknown, message: string) => {
  if (!condition) throw Error(message);
};
const tick = () => new Promise((r) => setTimeout(r, 0));
async function until(predicate: () => unknown) {
  const deadline = Date.now() + 10000;
  while (!predicate() && Date.now() < deadline) await tick();
  check(predicate(), 'password screen timed out');
}
export async function runRdpCredentialsScreenTests() {
  check(
    typeof (globalThis as any).require === 'undefined' &&
      typeof (globalThis as any).process === 'undefined',
    'Node exposed to password document',
  );
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });
  const key = await suite.kem.generateKeyPair(),
    id = '11111111-1111-4111-8111-111111111111';
  const context = {
    binding: {
      workspaceId: id,
      nodeId: id,
      sessionId: id,
      requestId: id,
      protocol: 'rdp',
      host: 'café.example',
      port: 3389,
      epoch: 1,
      tunnelConfigId: '',
      useExternalClient: false,
    },
    publicKey: btoa(
      String.fromCharCode(...new Uint8Array(await suite.kem.serializePublicKey(key.publicKey))),
    ),
  };
  const bytes = (v: string) => Uint8Array.from(atob(v), (c) => c.charCodeAt(0));
  function setup(overrides: Partial<VaultRdpCredentialsApi> = {}) {
    const card = document.createElement('section');
    card.className = 'startup-card';
    document.body.append(card);
    let envelope: any,
      closed = 0;
    const dispose = mountVaultRdpCredentialsScreen(card, {
      contentProtectionAvailable: false,
      context: async () => context,
      submit: async (value) => {
        envelope = value;
        return true;
      },
      cancel: async () => {
        closed++;
      },
      ...overrides,
    });
    check(
      card.textContent?.includes('Gateway settings come from this connection.'),
      'temporary entry must describe saved and unsaved targets accurately',
    );
    return {
      card,
      dispose,
      get envelope() {
        return envelope;
      },
      get closed() {
        return closed;
      },
      get input() {
        return card.querySelector<HTMLInputElement>('input[type=password]')!;
      },
      get status() {
        return card.querySelector('[role=status]')!.textContent!;
      },
      submit() {
        (card.querySelector('[aria-label="RDP username"]') as HTMLInputElement).value =
          'temporary-user';
        (card.querySelector('[aria-label="RDP domain"]') as HTMLInputElement).value = 'TEMP';
        card.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
      },
      remove() {
        dispose();
        card.remove();
      },
    };
  }
  let v = setup();
  v.submit();
  await tick();
  check(v.card.textContent!.includes('café.example:3389'), 'native target not shown');
  check(
    v.card.textContent!.includes('capture protection is unavailable'),
    'Linux limitation missing',
  );
  v.input.value = 'é'.repeat(16384);
  v.submit();
  check(v.input.value === '' && v.status.includes('too long'), 'UTF-8 limit');
  v.remove();
  v = setup({
    context: async () => ({
      ...context,
      binding: { ...context.binding, host: 'a'.repeat(63) + '.example' },
    }),
  });
  await tick();
  const target = v.card.querySelector('.vault-rdp-credentials-target') as HTMLElement;
  check(
    target.clientWidth > 0 &&
      target.clientWidth < 450 &&
      getComputedStyle(target).overflowWrap === 'anywhere',
    'actual document styles missing',
  );
  check(
    target.scrollWidth <= target.clientWidth,
    'long authenticated target overflows its document',
  );
  v.remove();
  for (const password of ['', 'one-use-browser']) {
    v = setup({ contentProtectionAvailable: true });
    await tick();
    v.input.value = password;
    v.submit();
    check(
      Array.from(v.card.querySelectorAll('input')).every(
        (input) => input.value === '' && input.disabled,
      ),
      'DOM credentials retained',
    );
    v.submit();
    await until(() => v.envelope);
    await tick();
    check(v.input.disabled, 'success reenabled form');
    const sealed = v.envelope;
    check(JSON.stringify(sealed).indexOf('one-use-browser') < 0, 'plaintext envelope');
    const opened = new Uint8Array(
      await suite.open(
        { recipientKey: key.privateKey, enc: bytes(sealed.enc), info: rdpCredentialsInfo(context) },
        bytes(sealed.ciphertext),
      ),
    );
    check(opened[0] === 1 && opened[1] === 1, 'manual credential header');
    let offset = 2;
    for (const value of ['temporary-user', 'TEMP', password]) {
      const size = new DataView(opened.buffer).getUint32(offset);
      offset += 4;
      check(
        new TextDecoder().decode(opened.subarray(offset, offset + size)) === value,
        'credential round trip',
      );
      offset += size;
    }
    check(offset === opened.length, 'trailing credential bytes');
    opened.fill(0);
    v.remove();
  }
  for (const result of [false, 'unexpected', 'error']) {
    v = setup({
      submit: async () => {
        if (result === 'error') throw Error('private diagnostic');
        return result;
      },
    });
    await tick();
    v.input.value = 'secret';
    v.submit();
    await until(() => v.status.includes('could not'));
    check(
      !v.input.disabled &&
        v.input.value === '' &&
        !v.card.textContent!.includes('private diagnostic'),
      'public error recovery',
    );
    v.remove();
  }
  for (const value of [
    null,
    {},
    { ...context, password: 'injected' },
    { ...context, publicKey: 'bad' },
  ]) {
    v = setup({ context: async () => value });
    await tick();
    check(v.input.disabled && v.status.includes('unavailable'), 'invalid context admitted');
    v.remove();
  }
  v = setup({
    context: async () => {
      throw Error('private');
    },
  });
  await tick();
  check(v.status.includes('unavailable'), 'context failure hidden');
  v.remove();
  let release!: (value: any) => void;
  v = setup({ context: () => new Promise((r) => (release = r)) });
  v.dispose();
  release(context);
  await tick();
  check(v.input.disabled, 'late context enabled');
  v.remove();
  let submits = 0;
  v = setup({
    submit: async () => {
      submits++;
      return true;
    },
  });
  await tick();
  v.input.value = 'late-secret';
  v.submit();
  v.dispose();
  await tick();
  await tick();
  check(
    v.input.value === '' && submits === 0 && v.input.disabled,
    'cancelled encryption delivered',
  );
  v.submit();
  v.remove();
  v = setup({
    submit: async () => {
      submits++;
      return new Promise((r) => (release = r));
    },
  });
  await tick();
  v.submit();
  await until(() => submits === 1);
  window.dispatchEvent(new Event('pagehide'));
  release(false);
  await tick();
  check(v.input.disabled, 'late response reenabled');
  v.remove();
  v = setup({
    cancel: async () => {
      throw Error('private');
    },
  });
  await tick();
  v.input.value = 'cancel-secret';
  (v.card.querySelector('[type=button]') as HTMLButtonElement).click();
  await tick();
  check(v.input.value === '' && v.input.disabled, 'cancel retained input');
  v.remove();
  v = setup();
  await tick();
  (v.card.querySelector('[type=button]') as HTMLButtonElement).click();
  await tick();
  check(v.closed === 1, 'cancel IPC missing');
  v.remove();
}

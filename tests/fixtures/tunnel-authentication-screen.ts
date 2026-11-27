import {
  mountVaultTunnelAuthenticationScreen,
  type VaultTunnelAuthenticationApi,
} from '../../src/vault-tunnel-authentication-screen.ts';
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm } from '@hpke/core';
import { tunnelAuthenticationInfo } from '../../electron/vault-tunnel-authentication.ts';
const check = (condition: unknown, message: string) => {
  if (!condition) throw Error(message);
};
const tick = () => new Promise((r) => setTimeout(r, 0));
async function until(predicate: () => unknown) {
  const deadline = Date.now() + 10000;
  while (!predicate() && Date.now() < deadline) await tick();
  check(predicate(), 'VPN document timed out');
}
export async function runTunnelAuthenticationScreenTests() {
  check(
    typeof (globalThis as any).require === 'undefined' &&
      typeof (globalThis as any).process === 'undefined',
    'Node exposed',
  );
  const suite = new CipherSuite({
      kem: new DhkemX25519HkdfSha256(),
      kdf: new HkdfSha256(),
      aead: new Aes256Gcm(),
    }),
    pair = await suite.kem.generateKeyPair(),
    id = '11111111-1111-4111-8111-111111111111';
  const context = {
    binding: {
      workspaceId: id,
      fileId: id,
      nodeId: id,
      sessionId: id,
      requestId: id,
      protocol: 'ssh',
      host: 'café.example',
      port: 22,
      epoch: 1,
      tunnelConfigId: id,
      kind: 9,
      rowVersion: '2',
      configurationVersion: '1',
      useExternalClient: false,
    },
    challengeId: id,
    publicKey: btoa(
      String.fromCharCode(...new Uint8Array(await suite.kem.serializePublicKey(pair.publicKey))),
    ),
    usernameRequired: true,
  };
  const bytes = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  function setup(overrides: Partial<VaultTunnelAuthenticationApi> = {}) {
    const card = document.createElement('section');
    card.className = 'startup-card';
    document.body.append(card);
    let envelope: any,
      closed = 0;
    const dispose = mountVaultTunnelAuthenticationScreen(card, {
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
    return {
      card,
      dispose,
      get envelope() {
        return envelope;
      },
      get closed() {
        return closed;
      },
      get name() {
        return card.querySelector('input[type=text]') as HTMLInputElement;
      },
      get password() {
        return card.querySelector('input[type=password]') as HTMLInputElement;
      },
      get status() {
        return card.querySelector('[role=status]')!.textContent!;
      },
      submit() {
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
  check(
    v.card.textContent!.includes('capture protection is unavailable'),
    'platform notice missing',
  );
  v.remove();
  for (const required of [true, false]) {
    const c = { ...context, usernameRequired: required };
    v = setup({ contentProtectionAvailable: true, context: async () => c });
    await tick();
    check(
      v.name.disabled === !required && v.name.parentElement!.hidden === !required,
      'username shape',
    );
    check(
      v.card.textContent!.includes(required ? 'They are not saved' : 'saved VPN username'),
      'factor persistence explanation',
    );
    v.name.value = required ? 'utente-é' : '';
    v.password.value = 'one-use-browser';
    v.submit();
    check(
      v.name.value === '' && v.password.value === '' && v.password.disabled,
      'DOM factors retained',
    );
    v.submit();
    await until(() => v.envelope);
    await tick();
    check(v.password.disabled, 'success reenabled');
    const sealed = v.envelope,
      raw = new Uint8Array(
        await suite.open(
          {
            recipientKey: pair.privateKey,
            enc: bytes(sealed.enc),
            info: tunnelAuthenticationInfo(c),
          },
          bytes(sealed.ciphertext),
        ),
      ),
      view = new DataView(raw.buffer),
      n = view.getUint32(2);
    check(raw[0] === 1 && raw[1] === 1 && view.getUint32(6) === 15, 'factor framing');
    check(
      new TextDecoder().decode(raw.subarray(10, 10 + n)) === (required ? 'utente-é' : ''),
      'username mismatch',
    );
    check(
      new TextDecoder().decode(raw.subarray(10 + n)) === 'one-use-browser',
      'password mismatch',
    );
    raw.fill(0);
    v.remove();
  }
  for (const mode of ['empty', 'blank', 'unicode-limit', 'fixed-injection']) {
    v = setup({
      context: async () => ({ ...context, usernameRequired: mode !== 'fixed-injection' }),
    });
    await tick();
    v.name.value = mode === 'blank' ? '\u2003' : 'u';
    v.password.value = mode === 'empty' ? '' : mode === 'unicode-limit' ? 'é'.repeat(4096) : 'p';
    v.submit();
    await until(() => v.status.includes('could not'));
    check(
      v.name.value === '' && v.password.value === '' && !v.password.disabled,
      'invalid factors retained',
    );
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
    v.name.value = 'u';
    v.password.value = 'p';
    v.submit();
    await until(() => v.status.includes('could not'));
    check(
      !v.password.disabled &&
        v.password.value === '' &&
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
    check(v.password.disabled && v.status.includes('unavailable'), 'invalid context admitted');
    v.remove();
  }
  v = setup({
    context: async () => {
      throw Error('private');
    },
  });
  await tick();
  check(v.status.includes('unavailable'), 'context failure');
  v.remove();
  let release!: (v: any) => void;
  v = setup({ context: () => new Promise((r) => (release = r)) });
  v.dispose();
  release(context);
  await tick();
  check(v.password.disabled, 'late context');
  v.remove();
  let submits = 0;
  v = setup({
    submit: async () => {
      submits++;
      return true;
    },
  });
  await tick();
  v.name.value = 'u';
  v.password.value = 'p';
  v.submit();
  v.dispose();
  await tick();
  await tick();
  check(
    submits === 0 && v.password.value === '' && v.password.disabled,
    'cancelled crypto delivered',
  );
  v.remove();
  v = setup({
    submit: async () => {
      submits++;
      return new Promise((r) => (release = r));
    },
  });
  await tick();
  v.name.value = 'u';
  v.password.value = 'p';
  v.submit();
  await until(() => submits === 1);
  window.dispatchEvent(new Event('pagehide'));
  release(false);
  await tick();
  check(v.password.disabled, 'late response reenabled');
  v.remove();
  for (const reject of [false, true]) {
    v = setup({
      cancel: async () => {
        if (reject) throw Error('private');
        submits++;
      },
    });
    await tick();
    v.name.value = 'u';
    v.password.value = 'p';
    (v.card.querySelector('[type=button]') as HTMLButtonElement).click();
    await tick();
    check(
      v.password.value === '' && v.name.value === '' && v.password.disabled,
      'cancel retained factors',
    );
    v.remove();
  }
  v = setup();
  await tick();
  (v.card.querySelector('[type=button]') as HTMLButtonElement).click();
  await tick();
  check(v.closed === 1, 'cancel IPC');
  v.remove();
}

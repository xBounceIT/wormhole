import {
  mountVaultSshCredentialsScreen,
  type VaultSshCredentialsApi,
} from '../../src/vault-ssh-credentials-screen.ts';
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm } from '@hpke/core';
import { sshManualInfo } from '../../electron/vault-ssh-manual.ts';
const check = (condition: unknown, message: string) => {
  if (!condition) throw Error(message);
};
const tick = () => new Promise((r) => setTimeout(r, 0));
async function until(predicate: () => unknown) {
  const deadline = Date.now() + 10000;
  while (!predicate() && Date.now() < deadline) await tick();
  check(predicate(), 'SSH document timed out');
}

export async function runSshCredentialsScreenTests() {
  check(
    typeof (globalThis as any).require === 'undefined' &&
      typeof (globalThis as any).process === 'undefined' &&
      !(window as any).wormhole,
    'ordinary app exposed',
  );
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });
  const pair = await suite.kem.generateKeyPair(),
    id = '11111111-1111-4111-8111-111111111111';
  const context = {
    plan: {
      host: {
        binding: {
          workspaceId: id,
          nodeId: id,
          sessionId: id,
          requestId: id,
          protocol: 'ssh',
          host: 'café.example',
          port: 22,
          epoch: 1,
          tunnelConfigId: '',
          useExternalClient: false,
        },
        fileId: id,
        revision: 'a'.repeat(64),
        fingerprint: 'SHA256:' + btoa('\0'.repeat(32)).slice(0, -1),
      },
      mode: 'account',
      autoSudo: false,
      sftpOnly: false,
    },
    route: null,
    endpoint: '',
    publicKey: btoa(
      String.fromCharCode(...new Uint8Array(await suite.kem.serializePublicKey(pair.publicKey))),
    ),
  };
  const bytes = (v: string) => Uint8Array.from(atob(v), (c) => c.charCodeAt(0));
  function setup(overrides: Partial<VaultSshCredentialsApi> = {}) {
    const card = document.createElement('section');
    card.className = 'startup-card';
    document.body.append(card);
    let envelope: any,
      closed = 0;
    const dispose = mountVaultSshCredentialsScreen(card, {
      contentProtectionAvailable: false,
      context: async () => context,
      submit: async (v) => {
        envelope = v;
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
      get status() {
        return card.querySelector('[role=status]')!.textContent!;
      },
      input: (name: string) =>
        card.querySelector<HTMLInputElement | HTMLTextAreaElement>(`[aria-label="${name}"]`)!,
      auth: (value: string) => {
        const select = card.querySelector('select')!;
        select.value = value;
        select.dispatchEvent(new Event('change'));
      },
      submit: () =>
        card.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true })),
      remove() {
        dispose();
        card.remove();
      },
    };
  }
  for (const kind of ['password', 'key', 'certificate', 'passphrase', 'empty-passphrase']) {
    const c = structuredClone(context);
    if (kind.includes('passphrase')) c.plan.mode = 'passphrase';
    const v = setup({ contentProtectionAvailable: true, context: async () => c });
    v.submit();
    await tick();
    check(v.card.textContent!.includes('café.example:22'), 'target missing');
    check(v.card.textContent!.includes(c.plan.host.fingerprint), 'fingerprint missing');
    if (kind.includes('passphrase')) {
      check(v.input('Username').parentElement!.hidden, 'passphrase leaked identity field');
      check(v.card.textContent!.includes('Leave empty'), 'empty override unexplained');
      v.input('Key passphrase').value = kind === 'passphrase' ? 'override' : '';
    } else {
      v.auth(kind);
      v.input('Username').value = '例-user';
      if (kind === 'password') v.input('Password').value = 'one-use-browser';
      else {
        v.input('Private key').value = 'document-key';
        v.input('Key passphrase').value = 'key-passphrase';
        if (kind === 'certificate') v.input('Certificate').value = 'document-certificate';
      }
    }
    v.submit();
    v.submit();
    for (const f of v.card.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>(
      'input,textarea',
    ))
      check(f.value === '' && f.disabled, 'DOM retained secret');
    await until(() => v.envelope);
    await tick();
    check(v.input('Password').disabled, 'success enabled form');
    const sealed = v.envelope;
    check(!JSON.stringify(sealed).includes('one-use-browser'), 'plaintext envelope');
    const raw = new Uint8Array(
      await suite.open(
        { recipientKey: pair.privateKey, enc: bytes(sealed.enc), info: sshManualInfo(c) },
        bytes(sealed.ciphertext),
      ),
    );
    if (kind.includes('passphrase'))
      check(
        new TextDecoder().decode(raw.subarray(6)) === (kind === 'passphrase' ? 'override' : ''),
        'passphrase changed',
      );
    else {
      let offset = 2;
      const fields: string[] = [];
      for (let i = 0; i < 6; i++) {
        const size = new DataView(raw.buffer).getUint32(offset);
        fields.push(new TextDecoder().decode(raw.subarray(offset + 4, offset + 4 + size)));
        offset += 4 + size;
      }
      check(fields[0] === '例-user' && fields[1] === c.plan.host.fingerprint, 'account changed');
      check(fields[2] === (kind === 'password' ? 'one-use-browser' : ''), 'password changed');
      check(fields[3] === (kind === 'password' ? '' : 'document-key'), 'key changed');
      check(
        fields[5] === (kind === 'certificate' ? 'document-certificate' : ''),
        'certificate changed',
      );
    }
    raw.fill(0);
    v.remove();
  }
  let v = setup();
  await tick();
  check(
    v.card.textContent!.includes('capture protection is unavailable'),
    'Linux limitation missing',
  );
  v.input('Password').value = 'discard-on-mode-change';
  v.auth('certificate');
  check(v.input('Password').value === '', 'mode change retained input');
  v.input('Username').value = 'u';
  v.input('Private key').value = 'k';
  v.submit();
  check(v.status.includes('Enter a certificate'), 'certificate omission');
  v.remove();
  for (const result of [false, 'error']) {
    v = setup({
      submit: async () => {
        if (result === 'error') throw Error('private diagnostic');
        return result;
      },
    });
    await tick();
    v.input('Username').value = 'u';
    v.input('Password').value = 'p';
    v.submit();
    await until(() => v.status.includes('could not'));
    check(
      !v.input('Password').disabled &&
        v.input('Password').value === '' &&
        !v.card.textContent!.includes('private diagnostic'),
      'error recovery',
    );
    v.remove();
  }
  v = setup();
  await tick();
  v.input('Username').value = 'u';
  v.input('Password').value = 'é'.repeat(16384);
  v.submit();
  await until(() => v.status.includes('could not'));
  check(v.input('Password').value === '', 'oversized input retained');
  v.remove();
  for (const value of [null, {}, { ...context, publicKey: 'bad' }]) {
    v = setup({ context: async () => value });
    await tick();
    check(v.input('Password').disabled && v.status.includes('unavailable'), 'invalid context');
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
  v = setup({
    context: () =>
      new Promise((r) => {
        release = r;
      }),
  });
  v.dispose();
  release(context);
  await tick();
  check(v.input('Password').disabled, 'late context admitted');
  v.remove();
  let delivered = 0;
  v = setup({
    submit: async () => {
      delivered++;
      return true;
    },
  });
  await tick();
  v.input('Username').value = 'u';
  v.input('Password').value = 'p';
  v.submit();
  v.dispose();
  await tick();
  await tick();
  check(delivered === 0 && v.input('Password').disabled, 'cancelled encryption delivered');
  v.remove();
  v = setup({
    submit: () => {
      delivered++;
      return new Promise((r) => {
        release = r;
      });
    },
  });
  await tick();
  v.input('Username').value = 'u';
  v.input('Password').value = 'p';
  v.submit();
  await until(() => delivered === 1);
  window.dispatchEvent(new Event('pagehide'));
  release(false);
  await tick();
  check(v.input('Password').disabled, 'late submit enabled');
  v.remove();
  for (const reject of [false, true]) {
    v = setup({
      cancel: async () => {
        if (reject) throw Error('private');
      },
    });
    await tick();
    v.input('Password').value = 'cancel-secret';
    (v.card.querySelector('[type=button]') as HTMLButtonElement).click();
    await tick();
    check(
      v.input('Password').value === '' && v.input('Password').disabled,
      'cancel retained secret',
    );
    v.remove();
  }
  const long = structuredClone(context);
  long.plan.host.binding.host = 'a'.repeat(63) + '.example';
  v = setup({ context: async () => long });
  await tick();
  const label = v.card.querySelector('.vault-ssh-credentials-target') as HTMLElement;
  check(
    label.clientWidth > 0 &&
      label.scrollWidth <= label.clientWidth &&
      getComputedStyle(label).overflowWrap === 'anywhere',
    'long target overflow',
  );
  v.remove();
}

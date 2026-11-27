import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { once } from 'node:events';
import { vaultFields, vaultRecord } from './vault-contract.ts';
import {
  canonicalBase64,
  parseVaultSshBundle,
  type VaultSshBundle,
  type VaultSshRequest,
} from './vault-ssh.ts';
import {
  parseVaultRoutedSshBundle,
  type VaultRoutedSshBundle,
  type VaultRoutedSshRequest,
} from './vault-ssh-route.ts';

export const maxBitwardenFrame = 144 * 1024;
export type VaultSSHBitwardenRequest = VaultSshRequest | VaultRoutedSshRequest;
export type VaultBitwardenRecipient = { publicKey: string; revision: string };
type Ticket = {
  binding: Omit<VaultSshBundle['binding'], 'tunnelConfigId'> & { tunnelConfigId: string };
  ticket: VaultSshBundle['bundle'];
};
export type VaultSSHBitwardenPreparation =
  | { required: false }
  | { required: true; revision: string; release?: Ticket };

export const validBitwardenRevision = (v: unknown): v is string =>
  typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);

export function parseVaultSSHBitwardenPreparation(
  value: unknown,
  request: VaultSSHBitwardenRequest,
  recipient?: VaultBitwardenRecipient,
): VaultSSHBitwardenPreparation | undefined {
  if (!vaultRecord(value)) return undefined;
  if (value.required === false)
    return !recipient && vaultFields(value, ['required']) ? { required: false } : undefined;
  if (
    value.required !== true ||
    !validBitwardenRevision(value.revision) ||
    !vaultFields(value, ['required', 'revision', ...(recipient ? ['release'] : [])])
  )
    return undefined;
  if (!recipient) return { required: true, revision: value.revision };
  if (value.revision !== recipient.revision) return undefined;
  const release = value.release;
  if (!vaultRecord(release) || !vaultFields(release, ['binding', 'ticket'])) return undefined;
  const binding = release.binding;
  const ticket = release.ticket;
  if (
    !vaultRecord(binding) ||
    !vaultRecord(ticket) ||
    !vaultFields(ticket, ['formatVersion', 'suiteId', 'enc', 'ciphertext']) ||
    ticket.formatVersion !== 1 ||
    ticket.suiteId !== 2 ||
    !canonicalBase64(ticket.enc, 32, 32) ||
    !canonicalBase64(ticket.ciphertext, 16, 96 * 1024 + 16)
  )
    return undefined;
  if ('route' in request) {
    const {
      fileId: _fileId,
      kind: _kind,
      rowVersion: _rowVersion,
      configurationVersion: _configurationVersion,
      ...expected
    } = request.route;
    if (
      !vaultFields(binding, Object.keys(expected)) ||
      Object.entries(expected).some(([key, part]) => binding[key] !== part)
    )
      return undefined;
  } else if (
    !parseVaultSshBundle(
      { binding, bundle: ticket, ...(request.sftpOnly ? { sftpOnly: true } : {}) },
      request,
    )
  )
    return undefined;
  return { required: true, revision: value.revision, release: release as Ticket };
}

async function* brokerFrames(child: ChildProcessWithoutNullStreams) {
  let pending = Buffer.alloc(0);
  const utf8 = new TextDecoder('utf-8', { fatal: true });
  for await (const chunk of child.stdout) {
    const data: Buffer = chunk;
    for (let offset = 0; offset < data.length;) {
      const newline = data.indexOf(10, offset);
      const end = newline === -1 ? data.length : newline;
      if (pending.length + end - offset >= maxBitwardenFrame)
        throw Error('Bitwarden reply exceeded its limit.');
      pending = Buffer.concat([pending, data.subarray(offset, end)]);
      if (newline === -1) break;
      const frame: unknown = JSON.parse(utf8.decode(pending));
      pending = Buffer.alloc(0);
      offset = newline + 1;
      yield frame;
    }
  }
  if (pending.length !== 0) throw Error('Incomplete Bitwarden reply.');
}

type Resolution = {
  executable: string;
  databasePath: string;
  request: VaultSSHBitwardenRequest;
  prepare: (recipient?: VaultBitwardenRecipient) => Promise<VaultSSHBitwardenPreparation>;
  signal: AbortSignal;
  start?: (executable: string, args: string[]) => ChildProcessWithoutNullStreams;
};

export async function resolveVaultSSHBitwarden({
  executable,
  databasePath,
  request,
  prepare,
  signal,
  start,
}: Resolution): Promise<VaultSshBundle | VaultRoutedSshBundle | undefined> {
  signal.throwIfAborted();
  const plan = await prepare();
  signal.throwIfAborted();
  if (!plan.required) return undefined;

  return runVaultBitwardenExchange({
    executable,
    databasePath,
    signal,
    start,
    mode: 'ssh',
    otherRecipient: request.publicKey,
    prepare: async (publicKey) => {
      const release = await prepare({ publicKey, revision: plan.revision });
      if (!release.required || !release.release)
        throw Error('Bitwarden credential is unavailable.');
      return release.release;
    },
    parse: (value): VaultSshBundle | VaultRoutedSshBundle | undefined =>
      'route' in request
        ? parseVaultRoutedSshBundle(value, request)
        : parseVaultSshBundle(value, request),
  });
}

type Exchange<T> = Pick<Resolution, 'executable' | 'databasePath' | 'signal' | 'start'> & {
  mode: 'ssh' | 'vnc' | 'rdp' | 'unlock';
  otherRecipient: string;
  prepare: (publicKey: string, signal: AbortSignal) => Promise<object>;
  parse: (value: unknown) => T | undefined;
};

export async function runVaultBitwardenExchange<T>({
  executable,
  databasePath,
  signal,
  start = (exe, args) => spawn(exe, args, { stdio: 'pipe', windowsHide: true }),
  mode,
  otherRecipient,
  prepare,
  parse,
}: Exchange<T>): Promise<T> {
  signal.throwIfAborted();
  const active = AbortSignal.any([
    signal,
    AbortSignal.timeout(mode === 'unlock' ? 300_000 : 95_000),
  ]);
  const flag = mode === 'unlock' ? '--sealed-bitwarden-unlock' : `--sealed-${mode}-bitwarden`;
  const child = start(executable, ['--operation', 'serve', flag, '--database', databasePath]);
  const prompt = new AbortController();
  const abortPrompt = () => prompt.abort();
  child.once('close', abortPrompt);
  const stopped = once(child, 'close').catch(() => [null]);
  let closing = false;
  const close = () => {
    if (closing) return;
    closing = true;
    child.stdin.destroy();
    if (mode === 'ssh' && child.exitCode === null && child.signalCode === null) {
      const kill = setTimeout(() => child.kill(), 1_000);
      kill.unref();
      child.once('close', () => clearTimeout(kill));
    }
  };
  child.stdin.on('error', close);
  child.stderr.on('error', close);
  child.stderr.resume();
  active.addEventListener('abort', close, { once: true });
  if (active.aborted) close();
  try {
    const frames = brokerFrames(child);
    const recipient = (await frames.next()).value;
    if (
      !vaultRecord(recipient) ||
      !vaultFields(recipient, ['publicKey']) ||
      !canonicalBase64(recipient.publicKey, 32, 32) ||
      recipient.publicKey === otherRecipient
    )
      throw Error('Bitwarden resolver recipient is unavailable.');
    active.throwIfAborted();
    const release = await prepare(recipient.publicKey, AbortSignal.any([active, prompt.signal]));
    active.throwIfAborted();
    prompt.signal.throwIfAborted();
    child.stdin.write(JSON.stringify(release) + '\n');
    const result = parse((await frames.next()).value);
    if (result === undefined || !(await frames.next()).done || (await stopped)[0] !== 0)
      throw Error('Bitwarden credential is unavailable.');
    active.throwIfAborted();
    return result;
  } catch {
    throw Error(
      mode === 'unlock'
        ? 'Bitwarden CLI could not be unlocked.'
        : 'Bitwarden credential is unavailable.',
    );
  } finally {
    active.removeEventListener('abort', close);
    child.removeListener('close', abortPrompt);
    close();
    // Lock waits for this dedicated worker even if the password dialog was
    // already closed. EOF cancels the CLI and lets Go reap it before exiting.
    if (mode !== 'ssh') await stopped;
  }
}

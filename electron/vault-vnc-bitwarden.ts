import { vaultRecord, vaultFields } from './vault-contract.ts';
import { canonicalBase64 } from './vault-ssh.ts';
import {
  runVaultBitwardenExchange,
  validBitwardenRevision,
  type VaultBitwardenRecipient,
} from './vault-ssh-bitwarden.ts';
import { parseVaultVncPlan } from './vault-vnc-manual.ts';
import {
  parseVaultVncBundle,
  parseVaultRoutedVncBundle,
  type VaultVncRequest,
  type VaultRoutedVncRequest,
  type VaultVncBundle,
  type VaultRoutedVncBundle,
} from './vault-vnc.ts';

export type VaultVNCBitwardenRequest = VaultVncRequest | VaultRoutedVncRequest;
type VNCBitwardenTicket = {
  binding: Omit<VaultVncBundle['binding'], 'tunnelConfigId'> & { tunnelConfigId: string };
  ticket: VaultVncBundle['bundle'];
};
export type VaultVNCBitwardenPlan =
  | { required: false }
  | { required: true; revision: string; release?: VNCBitwardenTicket };

export function parseVaultVNCBitwardenPlan(
  value: unknown,
  request: VaultVNCBitwardenRequest,
  recipient?: VaultBitwardenRecipient,
): VaultVNCBitwardenPlan | undefined {
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
  if (recipient.revision !== value.revision) return undefined;
  const release = value.release;
  if (!vaultRecord(release) || !vaultFields(release, ['binding', 'ticket'])) return undefined;
  const { binding, ticket } = release;
  if (
    !vaultRecord(binding) ||
    !vaultRecord(ticket) ||
    !vaultFields(ticket, ['formatVersion', 'suiteId', 'enc', 'ciphertext']) ||
    ticket.formatVersion !== 1 ||
    ticket.suiteId !== 2 ||
    !canonicalBase64(ticket.enc, 32, 32) ||
    !canonicalBase64(ticket.ciphertext, 17, 96 * 1024 + 16)
  )
    return undefined;
  if ('route' in request) {
    const {
      fileId: _file,
      kind: _kind,
      rowVersion: _row,
      configurationVersion: _config,
      ...expected
    } = request.route;
    if (
      !vaultFields(binding, Object.keys(expected)) ||
      Object.entries(expected).some(([field, part]) => binding[field] !== part)
    )
      return undefined;
  } else {
    const { publicKey: _key, ...planRequest } = request;
    if (!parseVaultVncPlan({ binding }, planRequest)) return undefined;
  }
  return { required: true, revision: value.revision, release: release as VNCBitwardenTicket };
}

export async function resolveVaultVNCBitwarden({
  executable,
  databasePath,
  request,
  prepare,
  signal,
  exchange = runVaultBitwardenExchange,
}: {
  executable: string;
  databasePath: string;
  request: VaultVNCBitwardenRequest;
  prepare: (recipient?: VaultBitwardenRecipient) => Promise<VaultVNCBitwardenPlan>;
  signal: AbortSignal;
  exchange?: typeof runVaultBitwardenExchange;
}): Promise<VaultVncBundle | VaultRoutedVncBundle | undefined> {
  signal.throwIfAborted();
  const plan = await prepare();
  signal.throwIfAborted();
  if (!plan.required) return undefined;
  let release: VNCBitwardenTicket | undefined;
  return exchange<VaultVncBundle | VaultRoutedVncBundle>({
    executable,
    databasePath,
    mode: 'vnc',
    signal,
    otherRecipient: request.publicKey,
    prepare: async (publicKey) => {
      const grant = await prepare({ publicKey, revision: plan.revision });
      if (!grant.required || !grant.release) throw Error('Bitwarden credential is unavailable.');
      release = grant.release;
      return release;
    },
    parse: (value) => {
      if (!release) return undefined;
      if ('route' in request) return parseVaultRoutedVncBundle(value, request);
      const parsed = parseVaultVncBundle(value, request);
      const expected = release.binding;
      return parsed &&
        Object.entries(parsed.binding).every(
          ([key, val]) => expected[key as keyof typeof expected] === val,
        )
        ? parsed
        : undefined;
    },
  });
}

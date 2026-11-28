import { vaultFields, vaultRecord } from './vault-contract.ts';
import { canonicalBase64 } from './vault-ssh.ts';
import {
  runVaultBitwardenExchange,
  validBitwardenRevision,
  type VaultBitwardenRecipient,
} from './vault-ssh-bitwarden.ts';
import {
  parseVaultRdpBundle,
  parseVaultRoutedRdpBundle,
  type VaultRdpBundle,
  type VaultRdpRequest,
  type VaultRoutedRdpBundle,
  type VaultRoutedRdpRequest,
} from './vault-rdp.ts';

export type VaultRDPBitwardenRequest = VaultRdpRequest | VaultRoutedRdpRequest;
type VaultRDPBase = VaultRdpBundle | VaultRoutedRdpBundle;
export type VaultRDPBitwardenBundle = VaultRDPBase & { bitwarden: VaultRdpBundle['bundle'] };
type RDPTicket = {
  binding: Omit<VaultRdpBundle['binding'], 'tunnelConfigId'> & { tunnelConfigId: string };
  ticket: VaultRdpBundle['bundle'];
};
export type VaultRDPBitwardenPlan =
  | { required: false }
  | { required: true; revision: string; release?: { ticket: RDPTicket; base: VaultRDPBase } };

const maxAccountsCiphertext = 32 + 2 * 2048 + 2 * 16384;
export const maxRDPBitwardenPlanFrame = 224 * 1024;

function parseEnvelope(
  value: unknown,
  min: number,
  max: number,
): VaultRdpBundle['bundle'] | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['formatVersion', 'suiteId', 'enc', 'ciphertext']) ||
    value.formatVersion !== 1 ||
    value.suiteId !== 2 ||
    !canonicalBase64(value.enc, 32, 32) ||
    !canonicalBase64(value.ciphertext, min, max)
  )
    return undefined;
  return { formatVersion: 1, suiteId: 2, enc: value.enc, ciphertext: value.ciphertext };
}

export function parseVaultRDPBitwardenPlan(
  value: unknown,
  request: VaultRDPBitwardenRequest,
  recipient?: VaultBitwardenRecipient,
): VaultRDPBitwardenPlan | undefined {
  if (!vaultRecord(value)) return undefined;
  if (value.required === false)
    return !recipient && vaultFields(value, ['required']) ? { required: false } : undefined;
  if (
    value.required !== true ||
    !validBitwardenRevision(value.revision) ||
    !vaultFields(value, ['required', 'revision', ...(recipient ? ['release', 'rdpBase'] : [])])
  )
    return undefined;
  const revision = value.revision;
  if (!recipient) return { required: true, revision };
  if (recipient.revision !== revision) return undefined;
  const release = value.release;
  if (
    !vaultRecord(release) ||
    !vaultFields(release, ['binding', 'ticket']) ||
    !vaultRecord(release.binding)
  )
    return undefined;
  const ticket = parseEnvelope(release.ticket, 17, 96 * 1024 + 16);
  const baseEnvelope = parseEnvelope(value.rdpBase, 76, 64 * 1024 + 16);
  if (!ticket || !baseEnvelope) return undefined;
  let base: VaultRDPBase | undefined;
  if ('route' in request) {
    const {
      fileId: _file,
      kind: _kind,
      rowVersion: _row,
      configurationVersion: _config,
      ...expected
    } = request.route;
    const binding = release.binding;
    if (
      !vaultFields(binding, Object.keys(expected)) ||
      Object.entries(expected).some(([name, part]) => binding[name] !== part)
    )
      return undefined;
    base = parseVaultRoutedRdpBundle(
      { binding: request.route, endpoint: request.endpoint, bundle: baseEnvelope },
      request,
    );
  } else {
    base = parseVaultRdpBundle({ binding: release.binding, bundle: baseEnvelope }, request);
  }
  return base
    ? {
        required: true,
        revision,
        release: { base, ticket: { binding: release.binding as RDPTicket['binding'], ticket } },
      }
    : undefined;
}

export function parseVaultRDPBitwardenBundle(
  value: unknown,
  request: VaultRDPBitwardenRequest,
): VaultRDPBitwardenBundle | undefined {
  if (!vaultRecord(value)) return undefined;
  const { bitwarden: raw, ...base } = value;
  const bitwarden = parseEnvelope(raw, 33, maxAccountsCiphertext);
  if (!bitwarden || !parseEnvelope(base.bundle, 76, 64 * 1024 + 16)) return undefined;
  const bundle =
    'route' in request
      ? parseVaultRoutedRdpBundle(base, request)
      : parseVaultRdpBundle(base, request);
  return bundle ? { ...bundle, bitwarden } : undefined;
}

export async function resolveVaultRDPBitwarden({
  executable,
  databasePath,
  request,
  prepare,
  signal,
  exchange = runVaultBitwardenExchange,
}: {
  executable: string;
  databasePath: string;
  request: VaultRDPBitwardenRequest;
  prepare: (recipient?: VaultBitwardenRecipient) => Promise<VaultRDPBitwardenPlan>;
  signal: AbortSignal;
  exchange?: typeof runVaultBitwardenExchange;
}): Promise<VaultRDPBitwardenBundle | undefined> {
  signal.throwIfAborted();
  const prior = await prepare();
  signal.throwIfAborted();
  if (!prior.required) return undefined;
  let base: VaultRDPBase | undefined;
  return exchange({
    executable,
    databasePath,
    signal,
    mode: 'rdp',
    otherRecipient: request.publicKey,
    prepare: async (publicKey) => {
      const plan = await prepare({ publicKey, revision: prior.revision });
      if (!plan.required || !plan.release) throw Error('Bitwarden credential is unavailable.');
      base = plan.release.base;
      return plan.release.ticket;
    },
    parse: (value) => {
      const bitwarden = parseEnvelope(value, 33, maxAccountsCiphertext);
      return bitwarden && base ? { ...base, bitwarden } : undefined;
    },
  });
}

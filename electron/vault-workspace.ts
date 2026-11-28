import {
  vaultRecord as record,
  vaultFields as fields,
  vaultID as id,
  vaultMetadataText as text,
  vaultRevision,
} from './vault-contract.ts';
import { parseWorkspaceRdpSettings } from './workspace-rdp-contract.ts';
import type { WorkspaceRdpSettings } from './workspace-rdp-contract.js';

export type VaultWorkspaceCredential = {
  rowVersion?: string;
  id: string;
  name: string;
  protocol: 'ssh' | 'rdp' | 'vnc';
  kind: 'password' | 'sshKey';
  username: string;
  provider: 'Local' | 'Bitwarden';
  canEdit: boolean;
  canDelete: boolean;
  domain?: string;
  bitwardenItemId?: string;
  bitwardenItemName?: string;
  privateKeyFileName?: string;
  hasCertificate?: boolean;
  certificateFileName?: string;
};
export type VaultWorkspaceNode = {
  id: string;
  rowVersion?: string;
  name: string;
  kind: 'folder' | 'connection';
  persisted: true;
  protocol?: 'ssh' | 'sftp' | 'rdp' | 'vnc' | 'http' | 'https' | 'serial';
  host?: string;
  port?: number;
  username?: string;
  hasInlineCredential?: boolean;
  rdp?: WorkspaceRdpSettings;
  children?: VaultWorkspaceNode[];
  serialBaudRate?: number;
  serialDataBits?: number;
  serialStopBits?: number;
  serialParity?: number;
  serialFlowControl?: number;
  httpIgnoreCertErrors?: boolean;
  httpPath?: string;
  sshAutoSudo?: boolean;
  tunnelEnabled?: boolean;
  tunnelConfigId?: string;
  credentialMode?: number;
  credentialId?: string;
};
export type VaultWorkspaceTunnel = { rowVersion?: string; id: string; name: string; kind: string };
export type VaultWorkspace = {
  tree: VaultWorkspaceNode[];
  credentials: VaultWorkspaceCredential[];
  credentialOptions: Record<'ssh' | 'rdp' | 'vnc', VaultWorkspaceCredential[]>;
  tunnels: VaultWorkspaceTunnel[];
};

const credentialRequired = [
  'id',
  'name',
  'protocol',
  'kind',
  'username',
  'provider',
  'canEdit',
  'canDelete',
];
const credentialOptional = [
  'rowVersion',
  'domain',
  'bitwardenItemId',
  'bitwardenItemName',
  'privateKeyFileName',
  'hasCertificate',
  'certificateFileName',
];
const nodeRequired = ['id', 'name', 'kind', 'persisted'];
const nodeOptional = [
  'rowVersion',
  'protocol',
  'host',
  'port',
  'username',
  'hasInlineCredential',
  'rdp',
  'children',
  'serialBaudRate',
  'serialDataBits',
  'serialStopBits',
  'serialParity',
  'serialFlowControl',
  'httpIgnoreCertErrors',
  'httpPath',
  'sshAutoSudo',
  'tunnelEnabled',
  'tunnelConfigId',
  'credentialMode',
  'credentialId',
];
const rdpFields = [
  'domain',
  'screenSize',
  'fullScreen',
  'colorDepth',
  'useAllMonitors',
  'audioMode',
  'audioCaptureMode',
  'keyboardHookMode',
  'redirectClipboard',
  'redirectPrinters',
  'redirectSmartCards',
  'redirectPorts',
  'redirectDevices',
  'redirectDrives',
  'connectionSpeed',
  'desktopBackground',
  'fontSmoothing',
  'desktopComposition',
  'windowDrag',
  'menuAnimation',
  'visualStyles',
  'bitmapCaching',
  'autoReconnect',
  'serverAuthentication',
  'gatewayUsageMethod',
  'gatewayHostname',
  'gatewayCredentialId',
  'gatewayBypassLocal',
  'gatewayUseSameCreds',
  'useExternalClient',
];
const tunnelKinds = [
  'WireGuard',
  'OpenVPN',
  'Fortinet',
  'Fortinet IPsec',
  'WatchGuard',
  'Stormshield',
  'Azure VPN',
  'Cisco Secure Client',
  'Forcepoint',
  'SSH tunnel (jump host)',
];
function shape(value: Record<string, unknown>, required: string[], optional: string[]): boolean {
  return (
    required.every((key) => Object.hasOwn(value, key)) &&
    Object.keys(value).every((key) => required.includes(key) || optional.includes(key))
  );
}
function optionalText(value: Record<string, unknown>, key: string, maximum: number): boolean {
  return !Object.hasOwn(value, key) || text(value[key], maximum);
}
function optionalInteger(
  value: Record<string, unknown>,
  key: string,
  minimum: number,
  maximum: number,
): boolean {
  const item = value[key];
  return (
    !Object.hasOwn(value, key) ||
    (typeof item === 'number' && Number.isSafeInteger(item) && item >= minimum && item <= maximum)
  );
}
function parseCredential(value: unknown): VaultWorkspaceCredential | undefined {
  if (
    !record(value) ||
    !shape(value, credentialRequired, credentialOptional) ||
    !id(value.id) ||
    (Object.hasOwn(value, 'rowVersion') && !vaultRevision(value.rowVersion)) ||
    !text(value.name, 1024, true) ||
    !text(value.username, 2048) ||
    !['ssh', 'rdp', 'vnc'].includes(value.protocol as string) ||
    !['password', 'sshKey'].includes(value.kind as string) ||
    !['Local', 'Bitwarden'].includes(value.provider as string) ||
    typeof value.canEdit !== 'boolean' ||
    typeof value.canDelete !== 'boolean' ||
    (value.kind === 'sshKey' && (value.protocol !== 'ssh' || value.provider !== 'Local')) ||
    !optionalText(value, 'domain', 2048) ||
    !optionalText(value, 'bitwardenItemId', 2048) ||
    !optionalText(value, 'bitwardenItemName', 4096) ||
    !optionalText(value, 'privateKeyFileName', 1024) ||
    !optionalText(value, 'certificateFileName', 1024) ||
    (Object.hasOwn(value, 'hasCertificate') && typeof value.hasCertificate !== 'boolean')
  )
    return undefined;
  return { ...value } as VaultWorkspaceCredential;
}

function parseRdpDisplay(value: unknown): WorkspaceRdpSettings | undefined {
  if (!record(value) || !fields(value, rdpFields)) return undefined;
  // Go bounds these display strings by Unicode runes. The editor parser uses
  // UTF-16 lengths and trims inputs, so validate a probe without changing the
  // authenticated display identity or rejecting supplementary Unicode letters.
  if (
    !text(value.domain, 2048) ||
    [...value.domain].length > 512 ||
    /[\r\n]/.test(value.domain) ||
    !text(value.gatewayHostname, 1012) ||
    [...value.gatewayHostname].length > 253 ||
    /[\p{Cc}\p{White_Space}]/u.test(value.gatewayHostname) ||
    !text(value.screenSize, 128) ||
    !text(value.redirectDrives, 128) ||
    !text(value.gatewayCredentialId, 128)
  )
    return undefined;
  try {
    parseWorkspaceRdpSettings({
      ...value,
      domain: '',
      gatewayHostname: value.gatewayHostname ? 'gateway.example' : '',
      screenSize: value.screenSize.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, ''),
    });
  } catch {
    return undefined;
  }
  return { ...value } as WorkspaceRdpSettings;
}

// This projection is display metadata. Stored/resolved values are produced in Go;
// validation here never resolves inheritance, authenticates or releases a secret.
export function parseVaultWorkspace(value: unknown): VaultWorkspace | undefined {
  if (
    !record(value) ||
    !fields(value, ['tree', 'credentials', 'credentialOptions', 'tunnels']) ||
    !Array.isArray(value.tree) ||
    !Array.isArray(value.credentials) ||
    !Array.isArray(value.tunnels) ||
    value.credentials.length + value.tunnels.length > 50_000 ||
    !record(value.credentialOptions) ||
    !fields(value.credentialOptions, ['ssh', 'rdp', 'vnc'])
  )
    return undefined;
  const credentials: VaultWorkspaceCredential[] = [];
  const credentialByID = new Map<string, VaultWorkspaceCredential>();
  for (const raw of value.credentials) {
    const c = parseCredential(raw);
    if (!c || credentialByID.has(c.id)) return undefined;
    credentials.push(c);
    credentialByID.set(c.id, c);
  }
  const credentialOptions: VaultWorkspace['credentialOptions'] = { ssh: [], rdp: [], vnc: [] };
  for (const protocol of ['ssh', 'rdp', 'vnc'] as const) {
    const raw = value.credentialOptions[protocol];
    if (!Array.isArray(raw) || raw.length > credentials.length) return undefined;
    const seen = new Set<string>();
    for (const entry of raw) {
      const c = parseCredential(entry),
        stored = c && credentialByID.get(c.id);
      if (
        !c ||
        !stored ||
        seen.has(c.id) ||
        c.protocol !== protocol ||
        [...credentialRequired, ...credentialOptional].some(
          (key) => (c as Record<string, unknown>)[key] !== (stored as Record<string, unknown>)[key],
        )
      )
        return undefined;
      seen.add(c.id);
      credentialOptions[protocol].push(c);
    }
    if (seen.size !== credentials.filter((c) => c.protocol === protocol).length) return undefined;
  }
  const tunnels: VaultWorkspaceTunnel[] = [],
    tunnelIDs = new Set<string>();
  for (const t of value.tunnels) {
    if (
      !record(t) ||
      !shape(t, ['id', 'name', 'kind'], ['rowVersion']) ||
      (Object.hasOwn(t, 'rowVersion') && !vaultRevision(t.rowVersion)) ||
      !id(t.id) ||
      tunnelIDs.has(t.id) ||
      !text(t.name, 512, true) ||
      [...t.name].length > 128 ||
      !tunnelKinds.includes(t.kind as string)
    )
      return undefined;
    tunnels.push({
      id: t.id,
      name: t.name,
      kind: t.kind as string,
      ...(Object.hasOwn(t, 'rowVersion') ? { rowVersion: t.rowVersion as string } : {}),
    });
    tunnelIDs.add(t.id);
  }
  const nodeIDs = new Set<string>();
  let remaining = 50_000 - credentials.length - tunnels.length;
  const parseNodes = (raw: unknown, depth: number): VaultWorkspaceNode[] | undefined => {
    if (!Array.isArray(raw) || raw.length > remaining || depth > 128) return undefined;
    const nodes: VaultWorkspaceNode[] = [];
    for (const n of raw) {
      if (
        !record(n) ||
        !shape(n, nodeRequired, nodeOptional) ||
        !id(n.id) ||
        nodeIDs.has(n.id) ||
        !text(n.name, 1024, true) ||
        [...n.name].length > 256 ||
        /\p{Cc}/u.test(n.name) ||
        (n.kind !== 'folder' && n.kind !== 'connection') ||
        n.persisted !== true ||
        (Object.hasOwn(n, 'protocol') &&
          !['ssh', 'sftp', 'rdp', 'vnc', 'http', 'https', 'serial'].includes(
            n.protocol as string,
          )) ||
        (Object.hasOwn(n, 'rowVersion') && !vaultRevision(n.rowVersion)) ||
        !optionalText(n, 'host', 16384) ||
        !optionalText(n, 'username', 2048) ||
        !optionalText(n, 'httpPath', 16384) ||
        !optionalInteger(n, 'port', 0, 65535) ||
        !optionalInteger(n, 'credentialMode', 0, 3) ||
        !optionalInteger(n, 'serialBaudRate', 1, 2147483647) ||
        !optionalInteger(n, 'serialDataBits', 5, 8) ||
        !optionalInteger(n, 'serialStopBits', 1, 3) ||
        !optionalInteger(n, 'serialParity', 0, 4) ||
        !optionalInteger(n, 'serialFlowControl', 0, 3) ||
        ['hasInlineCredential', 'httpIgnoreCertErrors', 'sshAutoSudo', 'tunnelEnabled'].some(
          (key) => Object.hasOwn(n, key) && typeof n[key] !== 'boolean',
        ) ||
        (Object.hasOwn(n, 'credentialId') &&
          (!id(n.credentialId) || !credentialByID.has(n.credentialId))) ||
        (Object.hasOwn(n, 'tunnelConfigId') &&
          (!id(n.tunnelConfigId) || !tunnelIDs.has(n.tunnelConfigId)))
      )
        return undefined;
      nodeIDs.add(n.id);
      if (--remaining < 0) return undefined;
      const node = { ...n } as VaultWorkspaceNode;
      if (Object.hasOwn(n, 'rdp')) {
        if (n.protocol !== 'rdp') return undefined;
        node.rdp = parseRdpDisplay(n.rdp);
        if (!node.rdp) return undefined;
        if (
          node.rdp.gatewayCredentialId &&
          (!id(node.rdp.gatewayCredentialId) || !credentialByID.has(node.rdp.gatewayCredentialId))
        )
          return undefined;
      }
      if (Object.hasOwn(n, 'children')) {
        if (n.kind !== 'folder') return undefined;
        const children = parseNodes(n.children, depth + 1);
        if (!children) return undefined;
        node.children = children;
      }
      nodes.push(node);
    }
    return nodes;
  };
  const tree = parseNodes(value.tree, 1);
  return tree && { tree, credentials, credentialOptions, tunnels };
}

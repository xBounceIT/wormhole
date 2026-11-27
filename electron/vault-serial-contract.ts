import { vaultFields, vaultID, vaultRecord } from './vault-contract.ts';
import { canonicalBase64 } from './vault-ssh.ts';
import type { SerialSettings } from './serial.ts';

type QuickSerial = { portName: string; settings: SerialSettings };

export type VaultSerialRequest = {
  workspaceId: string;
  nodeId: string;
  sessionId: string;
  requestId: string;
  epoch: number;
  publicKey: string;
  quick?: QuickSerial;
};

export type VaultSerialBundle = {
  binding: Omit<VaultSerialRequest, 'publicKey' | 'quick'> & {
    protocol: 'serial';
    host: string;
    port: 0;
    tunnelConfigId: '';
    useExternalClient: false;
  };
  bundle: { formatVersion: 1; suiteId: 2; enc: string; ciphertext: string };
};

export function parseSharedSerialUse(value: unknown, count: number): boolean[] | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['current']) ||
    !Array.isArray(value.current) ||
    value.current.length !== count ||
    !value.current.every((entry) => typeof entry === 'boolean')
  )
    return undefined;
  return value.current.slice();
}

export function validSerialPort(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    Buffer.byteLength(value) <= 256 &&
    value.trim() === value &&
    !/\p{Cc}/u.test(value)
  );
}

const settingNames = ['baudRate', 'dataBits', 'stopBits', 'parity', 'flowControl'] as const;

export function normalizeQuickSerial(
  portName: unknown,
  settings?: SerialSettings,
): QuickSerial | undefined {
  if (!validSerialPort(portName)) return undefined;
  return {
    portName,
    settings: {
      baudRate: settings?.baudRate || 9600,
      dataBits: settings?.dataBits && settings.dataBits >= 5 ? settings.dataBits : 8,
      stopBits: settings?.stopBits || 1,
      parity: settings?.parity ?? 0,
      flowControl: settings?.flowControl ?? 0,
    },
  };
}

export function parseVaultSerialRequest(value: unknown): VaultSerialRequest | undefined {
  const required = ['workspaceId', 'nodeId', 'sessionId', 'requestId', 'epoch', 'publicKey'];
  if (
    !vaultRecord(value) ||
    !vaultFields(value, 'quick' in value ? [...required, 'quick'] : required) ||
    ![value.workspaceId, value.nodeId, value.sessionId, value.requestId].every(vaultID) ||
    !Number.isSafeInteger(value.epoch) ||
    (value.epoch as number) < 1 ||
    !canonicalBase64(value.publicKey, 32, 32)
  )
    return undefined;
  if ('quick' in value) {
    const q = value.quick;
    if (
      !vaultRecord(q) ||
      !vaultFields(q, ['portName', 'settings']) ||
      !validSerialPort(q.portName) ||
      !vaultRecord(q.settings) ||
      !vaultFields(q.settings, [...settingNames])
    )
      return undefined;
    const { baudRate, dataBits, stopBits, parity, flowControl } = q.settings;
    if (
      ![baudRate, dataBits, stopBits, parity, flowControl].every(Number.isInteger) ||
      (baudRate as number) < 1 ||
      (baudRate as number) > 10_000_000 ||
      (dataBits as number) < 5 ||
      (dataBits as number) > 8 ||
      (stopBits as number) < 1 ||
      (stopBits as number) > 3 ||
      (parity as number) < 0 ||
      (parity as number) > 4 ||
      (flowControl as number) < 0 ||
      (flowControl as number) > 3
    )
      return undefined;
  }
  return value as VaultSerialRequest;
}

export function parseVaultSerialBundle(
  value: unknown,
  q: VaultSerialRequest,
): VaultSerialBundle | undefined {
  if (!vaultRecord(value) || !vaultFields(value, ['binding', 'bundle'])) return undefined;
  const { binding: b, bundle: s } = value;
  if (
    !vaultRecord(b) ||
    !vaultFields(b, [
      'workspaceId',
      'nodeId',
      'sessionId',
      'requestId',
      'epoch',
      'protocol',
      'host',
      'port',
      'tunnelConfigId',
      'useExternalClient',
    ]) ||
    b.workspaceId !== q.workspaceId ||
    b.nodeId !== q.nodeId ||
    b.sessionId !== q.sessionId ||
    b.requestId !== q.requestId ||
    b.epoch !== q.epoch ||
    b.protocol !== 'serial' ||
    !validSerialPort(b.host) ||
    (q.quick && b.host !== q.quick.portName) ||
    b.port !== 0 ||
    b.tunnelConfigId !== '' ||
    b.useExternalClient !== false ||
    !vaultRecord(s) ||
    !vaultFields(s, ['formatVersion', 'suiteId', 'enc', 'ciphertext']) ||
    s.formatVersion !== 1 ||
    s.suiteId !== 2 ||
    !canonicalBase64(s.enc, 32, 32) ||
    !canonicalBase64(s.ciphertext, 25, 25)
  )
    return undefined;
  return value as VaultSerialBundle;
}

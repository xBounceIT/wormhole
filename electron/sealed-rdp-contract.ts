import { vaultFields, vaultID, vaultMetadataText, vaultRecord } from './vault-contract.ts';
import { isRdpFrame, isRdpInput } from './rdp-framebuffer.ts';
import { isRdpSurfaceRectWithinNativeBounds } from './rdp-contract.ts';
import type { RdpBackendEvent, RdpSurfaceRect } from './rdp-contract.ts';

export type SealedRdpOpen = {
  sessionId: string;
  nodeId: string;
  credentialId?: string;
  manualCredentials?: true;
  ownerWindow: string;
  requireContentProtection?: true;
  visible?: boolean;
  bounds: RdpSurfaceRect;
};
export type SealedRdpControl =
  | { op: 'resize' | 'show'; bounds: RdpSurfaceRect }
  | { op: 'hide' | 'focus' }
  | { op: 'input'; input: import('./rdp-framebuffer.ts').RdpInput }
  | { op: 'certificate'; certificateAccepted: boolean };

export function parseSealedRdpBounds(value: unknown): RdpSurfaceRect | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, ['x', 'y', 'width', 'height']) ||
    !Object.values(value).every(Number.isInteger)
  )
    return undefined;
  const bounds = value as RdpSurfaceRect;
  return isRdpSurfaceRectWithinNativeBounds(bounds) ? { ...bounds } : undefined;
}

export function parseSealedRdpOpen(value: unknown): SealedRdpOpen | undefined {
  if (
    !vaultRecord(value) ||
    !vaultFields(value, [
      'sessionId',
      'nodeId',
      'ownerWindow',
      'bounds',
      ...(value.credentialId !== undefined ? ['credentialId'] : []),
      ...(value.manualCredentials !== undefined ? ['manualCredentials'] : []),
      ...(value.visible !== undefined ? ['visible'] : []),
      ...(value.requireContentProtection !== undefined ? ['requireContentProtection'] : []),
    ]) ||
    !vaultID(value.sessionId) ||
    !vaultID(value.nodeId) ||
    (value.credentialId !== undefined && !vaultID(value.credentialId)) ||
    (value.manualCredentials !== undefined &&
      (value.manualCredentials !== true || value.credentialId !== undefined)) ||
    (value.visible !== undefined && typeof value.visible !== 'boolean') ||
    (value.requireContentProtection !== undefined && value.requireContentProtection !== true) ||
    typeof value.ownerWindow !== 'string' ||
    (value.ownerWindow !== '' &&
      (!/^[1-9][0-9]{0,19}$/.test(value.ownerWindow) ||
        BigInt(value.ownerWindow) > 0xffffffffffffffffn))
  )
    return undefined;
  const bounds = parseSealedRdpBounds(value.bounds);
  return bounds
    ? {
        sessionId: value.sessionId,
        nodeId: value.nodeId,
        ownerWindow: value.ownerWindow,
        ...(value.requireContentProtection === true ? { requireContentProtection: true } : {}),
        ...(value.visible !== undefined ? { visible: value.visible as boolean } : {}),
        bounds,
        ...(value.credentialId !== undefined ? { credentialId: value.credentialId } : {}),
        ...(value.manualCredentials === true ? { manualCredentials: true } : {}),
      }
    : undefined;
}

export function parseSealedRdpControl(value: unknown): SealedRdpControl | undefined {
  if (!vaultRecord(value)) return undefined;
  switch (value.op) {
    case 'resize':
    case 'show': {
      if (!vaultFields(value, ['op', 'bounds'])) return undefined;
      const bounds = parseSealedRdpBounds(value.bounds);
      return bounds ? { op: value.op, bounds } : undefined;
    }
    case 'hide':
    case 'focus':
      return vaultFields(value, ['op']) ? { op: value.op } : undefined;
    case 'certificate':
      return vaultFields(value, ['op', 'certificateAccepted']) &&
        typeof value.certificateAccepted === 'boolean'
        ? { op: value.op, certificateAccepted: value.certificateAccepted }
        : undefined;
    case 'input': {
      if (
        !vaultFields(value, ['op', 'input']) ||
        !vaultRecord(value.input) ||
        !isRdpInput(value.input)
      )
        return undefined;
      const input = value.input;
      const fields =
        input.kind === 'release'
          ? ['kind']
          : input.kind === 'painted'
            ? ['kind', 'code']
            : input.kind === 'pointer'
              ? ['kind', 'x', 'y', 'flags']
              : ['kind', 'code', 'down'];
      return vaultFields(input, fields) ? { op: value.op, input: { ...input } } : undefined;
    }
    default:
      return undefined;
  }
}

const lifecycleTypes = new Set([
  'started',
  'ready',
  'connected',
  'loginComplete',
  'disconnected',
  'fatalError',
  'logonError',
  'autoReconnecting',
  'autoReconnected',
  'exited',
  'ack',
  'error',
]);
const integer = (value: unknown, min: number, max: number) =>
  Number.isInteger(value) && (value as number) >= min && (value as number) <= max;

/** Accept only public native output. Recipient keys and native COM references never pass here. */
export function parseSealedRdpEvent(
  value: unknown,
  sessionId: string,
): RdpBackendEvent | undefined {
  if (
    !vaultRecord(value) ||
    !vaultID(sessionId) ||
    value.sessionId !== sessionId ||
    value.lifecycleId !== sessionId ||
    value.external !== false ||
    (value.requestId !== undefined && !vaultID(value.requestId)) ||
    (value.backend !== undefined && value.backend !== 'activex' && value.backend !== 'freerdp')
  )
    return undefined;
  const common = [
    'type',
    'sessionId',
    'lifecycleId',
    'external',
    ...(value.requestId !== undefined ? ['requestId'] : []),
    ...(value.backend !== undefined ? ['backend'] : []),
  ];
  const type = value.type;
  if (
    value.requestId !== undefined &&
    !['started', 'ready', 'ack', 'error'].includes(type as string)
  )
    return undefined;
  if (type === 'frame') {
    if (
      !vaultFields(value, [...common, 'frame']) ||
      !vaultRecord(value.frame) ||
      !vaultFields(value.frame, [
        'desktopWidth',
        'desktopHeight',
        'x',
        'y',
        'width',
        'height',
        'rgba',
      ]) ||
      !isRdpFrame(value.frame)
    )
      return undefined;
    return {
      type,
      sessionId,
      lifecycleId: sessionId,
      external: false,
      backend: value.backend,
      frame: { ...value.frame },
    } as RdpBackendEvent;
  }
  if (type === 'frameEnd') {
    if (!vaultFields(value, [...common, 'paintId']) || !integer(value.paintId, 1, 0xffffffff))
      return undefined;
  } else if (type === 'certificate') {
    const c = value.certificate;
    if (
      !vaultFields(value, [...common, 'certificate']) ||
      !vaultRecord(c) ||
      !vaultFields(c, ['host', 'fingerprint']) ||
      !vaultMetadataText(c.host, 1024, true) ||
      !vaultMetadataText(c.fingerprint, 1024, true) ||
      !c.host ||
      !c.fingerprint
    )
      return undefined;
  } else {
    if (!lifecycleTypes.has(type as string)) return undefined;
    const optional = ['code', 'attempt', 'max', 'message', 'credentialFailure'].filter(
      (key) => value[key] !== undefined,
    );
    if (
      !vaultFields(value, [...common, ...optional]) ||
      (value.code !== undefined && !integer(value.code, -2147483648, 4294967295)) ||
      [value.attempt, value.max].some((n) => n !== undefined && !integer(n, 0, 65535)) ||
      (value.message !== undefined && !vaultMetadataText(value.message, 2048, true)) ||
      (value.credentialFailure !== undefined &&
        (type !== 'logonError' || typeof value.credentialFailure !== 'boolean'))
    )
      return undefined;
  }
  const event = {
    ...value,
    ...(type === 'certificate' ? { certificate: { ...(value.certificate as object) } } : {}),
  } as RdpBackendEvent;
  // Native diagnostics are never rendered verbatim, including a compromised helper's message.
  if (event.message !== undefined)
    event.message =
      type === 'error' || type === 'fatalError'
        ? 'RDP connection failed'
        : type === 'logonError'
          ? 'RDP authentication failed'
          : '';
  return event;
}

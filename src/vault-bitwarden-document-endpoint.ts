import {
  bitwardenDocumentTimeoutMs,
  bitwardenDocumentPacketBytes,
  parseBitwardenBridgeOwner,
  parseBitwardenBridgeReceipt,
  type BitwardenExtensionBridge,
} from '../electron/vault-bitwarden-bridge-contract.ts';
import {
  parseBrowserTransferRequest,
  parseBrowserTransferBegun,
  parseBrowserTransferCancelled,
  parseBrowserProfileClosed,
  type BrowserTransferRequest,
} from '../electron/vault-bitwarden-native.ts';
import {
  browserTransferChunkCount,
  parseBrowserTransferManifest,
  parseBrowserTransferPacket,
  type BrowserTransferContext,
} from '../electron/vault-bitwarden-transfer.ts';
import { vaultFields, vaultRecord } from '../electron/vault-contract.ts';

const unavailable = () => Error('Bitwarden document is unavailable.');

// This validator/serializer runs inside the owning extension, before any result
// crosses executeJavaScript. Never serialize an unvalidated storage/error object.
export function createBitwardenDocumentEndpoint(
  owner: unknown,
  bridge: BitwardenExtensionBridge,
  current: () => boolean,
) {
  const identity = parseBitwardenBridgeOwner(owner);
  if (!identity) throw unavailable();
  let lastCall = 0,
    generation = 0,
    disposed = false,
    active: object | undefined,
    request: BrowserTransferRequest | undefined,
    context: BrowserTransferContext | undefined;
  const check = (deadline: number) => {
    if (!current() || Date.now() >= deadline) throw unavailable();
  };
  const serialize = (value: unknown, limit: number) => {
    const raw = JSON.stringify(value);
    if (raw.length > limit) throw unavailable();
    return raw;
  };
  return async (
    callId: unknown,
    operation: unknown,
    input: unknown,
    deadline: unknown,
  ): Promise<string> => {
    let token: object | undefined;
    try {
      if (
        !Number.isSafeInteger(callId) ||
        (callId as number) <= lastCall ||
        !Number.isSafeInteger(deadline) ||
        (deadline as number) > Date.now() + bitwardenDocumentTimeoutMs ||
        !['prepare', 'bind', 'next', 'accept', 'cancel', 'dispose'].includes(operation as string)
      )
        throw unavailable();
      check(deadline as number);
      lastCall = callId as number;
      if (operation === 'cancel' || operation === 'dispose') {
        if (input !== null) throw unavailable();
        generation++;
        active = undefined;
        request = undefined;
        context = undefined;
        if (operation === 'dispose') disposed = true;
        const value =
          operation === 'dispose'
            ? parseBrowserProfileClosed(await bridge.dispose())
            : parseBrowserTransferCancelled(await bridge.cancel());
        check(deadline as number);
        if (!value) throw unavailable();
        return serialize(value, 64);
      }
      if (disposed || active) throw unavailable();
      token = {};
      active = token;
      const stamp = generation;
      let value: unknown,
        nextRequest = request,
        nextContext = context;
      if (operation === 'prepare') {
        if (input !== null || request || context) throw unavailable();
        const q = parseBrowserTransferRequest(await bridge.prepare());
        if (!q || Object.entries(identity).some(([k, v]) => q[k as keyof typeof q] !== v))
          throw unavailable();
        nextRequest = q;
        value = q;
      } else if (operation === 'bind') {
        const c = request && !context && parseBrowserTransferBegun(input, request);
        if (!c) throw unavailable();
        const captured = await bridge.bind(c);
        const manifest =
          vaultRecord(captured) && vaultFields(captured, ['chunks', 'manifest'])
            ? parseBrowserTransferManifest(captured.manifest, c, 'capture')
            : undefined;
        if (!manifest || captured.chunks !== browserTransferChunkCount(manifest))
          throw unavailable();
        nextContext = c;
        value = { chunks: captured.chunks, manifest };
      } else if (operation === 'next') {
        if (input !== null || !context) throw unavailable();
        value = parseBrowserTransferPacket(await bridge.next(), context, 'capture');
        if (!value) throw unavailable();
      } else {
        const packet = context && parseBrowserTransferPacket(input, context, 'restore');
        if (!packet) throw unavailable();
        const receipt = parseBitwardenBridgeReceipt(await bridge.accept(packet));
        if (!receipt) throw unavailable();
        if (receipt.complete) nextRequest = nextContext = undefined;
        value = receipt;
      }
      check(deadline as number);
      if (generation !== stamp || active !== token || disposed) throw unavailable();
      request = nextRequest;
      context = nextContext;
      return serialize(value, operation === 'next' ? bitwardenDocumentPacketBytes : 2048);
    } catch {
      throw unavailable();
    } finally {
      if (token && active === token) active = undefined;
    }
  };
}

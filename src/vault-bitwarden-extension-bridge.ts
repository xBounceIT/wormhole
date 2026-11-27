import {
  parseBitwardenBridgeOwner,
  type BitwardenExtensionBridge,
} from '../electron/vault-bitwarden-bridge-contract.ts';
import { parseBrowserTransferContext } from '../electron/vault-bitwarden-transfer.ts';
import type { BrowserTransferRequest } from '../electron/vault-bitwarden-native.ts';
import type {
  createBitwardenExtensionStorage,
  ExtensionStorageCapture,
} from './vault-bitwarden-extension-storage.ts';
import {
  createBitwardenTransferCapture,
  createBitwardenTransferRecipient,
} from './vault-bitwarden-transfer-recipient.ts';

type Stage = {
  controller: AbortController;
  timer?: ReturnType<typeof setTimeout>;
  busy: boolean;
  request?: BrowserTransferRequest;
  recipient?: Awaited<ReturnType<typeof createBitwardenTransferRecipient>>;
  sender?: Awaited<ReturnType<typeof createBitwardenTransferCapture>>;
  witness?: ExtensionStorageCapture;
  remaining?: number;
};
const unavailable = () => Error('Bitwarden extension transfer is unavailable.');
const lifetimeMs = 120000;

// Instantiate only in the exact owning extension background document. Public
// methods deliberately expose no storage values, byte arrays or private keys.
export function createBitwardenExtensionBridge(
  value: unknown,
  storage: ReturnType<typeof createBitwardenExtensionStorage>,
): BitwardenExtensionBridge {
  const owner = parseBitwardenBridgeOwner(value);
  if (!owner) throw unavailable();
  let active: Stage | undefined,
    disposed = false,
    needsHydrate = true,
    revision = '0';
  const check = (stage: Stage) => {
    if (disposed || active !== stage || stage.controller.signal.aborted) throw unavailable();
  };
  const retire = (stage: Stage, failed = true) => {
    stage.controller.abort();
    clearTimeout(stage.timer);
    stage.recipient?.dispose();
    stage.recipient = undefined;
    stage.sender?.dispose();
    stage.sender = undefined;
    stage.witness?.localJSON.fill(0);
    stage.witness?.sessionJSON.fill(0);
    stage.witness = undefined;
    if (active === stage) {
      active = undefined;
      if (failed) needsHydrate = true;
    }
  };
  const run = async <T>(
    stage: Stage | undefined,
    action: (s: Stage) => Promise<T>,
    commit?: (s: Stage, result: T) => void,
  ): Promise<T> => {
    if (!stage || stage.busy) throw unavailable();
    stage.busy = true;
    try {
      check(stage);
      const result = await action(stage);
      check(stage);
      commit?.(stage, result);
      return result;
    } catch {
      retire(stage);
      throw unavailable();
    } finally {
      stage.busy = false;
    }
  };
  return {
    prepare: async () => {
      if (disposed || active) throw unavailable();
      const stage: Stage = { controller: new AbortController(), busy: false };
      active = stage;
      stage.timer = setTimeout(() => retire(stage), lifetimeMs);
      return run(stage, async (s) => {
        const recipient = await createBitwardenTransferRecipient(async (state, receipt, signal) => {
          check(s);
          if (!s.witness) throw unavailable();
          if (receipt.restore) await storage.restore(state, s.witness, signal);
          check(s);
        }, s.controller.signal);
        if (active !== s || s.controller.signal.aborted || disposed) {
          recipient.dispose();
          throw unavailable();
        }
        s.recipient = recipient;
        const request: BrowserTransferRequest = {
          ...owner,
          requestId: crypto.randomUUID(),
          action: needsHydrate ? 'hydrate' : 'capture',
          sourceRevision: revision,
          restorePublicKey: recipient.publicKey,
        };
        s.request = request;
        return { ...request };
      });
    },
    bind: (context) =>
      run(active, async (s) => {
        const c = parseBrowserTransferContext(context),
          q = s.request;
        if (
          !c ||
          !q ||
          !s.recipient ||
          s.sender ||
          Object.entries(q).some(([key, v]) => c[key as keyof typeof c] !== v)
        )
          throw unavailable();
        s.recipient.bind(c);
        const captured = await storage.capture(s.controller.signal);
        try {
          check(s);
          s.witness = {
            localJSON: new Uint8Array(),
            sessionJSON: new Uint8Array(),
          };
          // Register ownership before allocating secret copies so partial failure
          // can clear every completed copy and both original capture buffers.
          s.witness.localJSON = captured.localJSON.slice();
          s.witness.sessionJSON = captured.sessionJSON.slice();
          const sender = await createBitwardenTransferCapture(
            c,
            captured.localJSON,
            captured.sessionJSON,
            s.controller.signal,
          );
          if (active !== s || s.controller.signal.aborted || disposed) {
            sender.dispose();
            throw unavailable();
          }
          s.sender = sender;
          s.remaining = sender.chunks;
          return { chunks: sender.chunks, manifest: { ...sender.manifest } };
        } finally {
          captured.localJSON.fill(0);
          captured.sessionJSON.fill(0);
        }
      }),
    next: () =>
      run(active, async (s) => {
        if (!s.sender || !s.remaining) throw unavailable();
        const packet = await s.sender.next();
        check(s);
        s.remaining--;
        return packet;
      }),
    accept: (packet) =>
      run(
        active,
        async (s) => {
          if (!s.sender || s.remaining !== 0 || !s.recipient) throw unavailable();
          const receipt = await s.recipient.accept(packet);
          return receipt ? { complete: true as const, ...receipt } : { complete: false as const };
        },
        (s, result) => {
          if (result.complete) {
            revision = result.revision;
            needsHydrate = false;
            retire(s, false);
          }
        },
      ),
    cancel: async () => {
      if (active) retire(active);
      return { cancelled: true };
    },
    dispose: async () => {
      disposed = true;
      if (active) retire(active);
      return { closed: true };
    },
  };
}

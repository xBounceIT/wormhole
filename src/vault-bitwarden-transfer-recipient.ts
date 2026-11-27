import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from '@hpke/core';
import { enrollmentBytes } from '../electron/vault-enrollment-contract.ts';
import {
  browserTransferChunkBytes,
  browserTransferChunkCount,
  browserTransferChunkSize,
  browserTransferInfo,
  decodeBrowserTransferFrame,
  encodeBrowserTransferFrame,
  parseBrowserTransferContext,
  parseBrowserTransferPacket,
  type BrowserTransferContext,
  type BrowserTransferManifest,
  type BrowserTransferPacket,
} from '../electron/vault-bitwarden-transfer.ts';

export type BrowserTransferReceipt = { revision: string; restore: boolean };
function suite() {
  return new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });
}
function base64(raw: Uint8Array): string {
  const parts: string[] = [];
  for (let i = 0; i < raw.length; i += 16384)
    parts.push(String.fromCharCode(...raw.subarray(i, i + 16384)));
  return btoa(parts.join(''));
}
// Import only in the owning isolated extension context. Input buffers are
// consumed before asynchronous crypto; next() returns one ciphertext packet.
export async function createBitwardenTransferCapture(
  value: unknown,
  localJSON: Uint8Array,
  sessionJSON: Uint8Array,
  signal?: AbortSignal,
) {
  let frame: Uint8Array | undefined,
    stopped = false,
    busy = false,
    index = 0;
  const stop = () => {
    stopped = true;
    frame?.fill(0);
    frame = undefined;
    signal?.removeEventListener('abort', stop);
  };
  try {
    const context = parseBrowserTransferContext(value);
    if (
      !context ||
      !(localJSON instanceof Uint8Array) ||
      !(sessionJSON instanceof Uint8Array) ||
      signal?.aborted
    )
      throw Error();
    frame = encodeBrowserTransferFrame(localJSON, sessionJSON);
    localJSON.fill(0);
    sessionJSON.fill(0);
    signal?.addEventListener('abort', stop, { once: true });
    const manifest: BrowserTransferManifest = {
      bytes: frame.length,
      revision: context.sourceRevision,
      restore: false,
    };
    const crypto = suite(),
      recipientPublicKey = await crypto.kem.deserializePublicKey(
        enrollmentBytes(context.capturePublicKey, 32)!,
      );
    if (stopped || signal?.aborted) throw Error();
    return {
      chunks: browserTransferChunkCount(manifest),
      manifest: { ...manifest },
      dispose: stop,
      async next(): Promise<BrowserTransferPacket> {
        if (stopped || busy || !frame || index >= browserTransferChunkCount(manifest)) {
          stop();
          throw Error('Browser storage capture is closed.');
        }
        busy = true;
        try {
          const current = index;
          const result = await crypto.seal(
            {
              recipientPublicKey,
              info: browserTransferInfo(context, 'capture', manifest, current),
            },
            frame.subarray(
              current * browserTransferChunkBytes,
              Math.min(frame.length, (current + 1) * browserTransferChunkBytes),
            ),
          );
          if (stopped || signal?.aborted) throw Error();
          const packet: BrowserTransferPacket = {
            context: { ...context },
            direction: 'capture',
            manifest: { ...manifest },
            index: current,
            bundle: {
              formatVersion: 1,
              suiteId: 2,
              enc: base64(new Uint8Array(result.enc)),
              ciphertext: base64(new Uint8Array(result.ct)),
            },
          };
          index++;
          if (index === browserTransferChunkCount(manifest)) stop();
          return packet;
        } catch {
          stop();
          throw Error('Browser storage capture could not be encrypted.');
        } finally {
          busy = false;
        }
      },
    };
  } catch {
    stop();
    throw Error('Browser storage capture could not be prepared.');
  } finally {
    if (localJSON instanceof Uint8Array) localJSON.fill(0);
    if (sessionJSON instanceof Uint8Array) sessionJSON.fill(0);
  }
}
// A restore key belongs to one transfer. Plaintext is borrowed only by the
// extension-local callback; accept() returns a public receipt, never the data.
export async function createBitwardenTransferRecipient(
  apply: (
    state: { localJSON: Uint8Array; sessionJSON: Uint8Array },
    receipt: BrowserTransferReceipt,
    signal: AbortSignal,
  ) => Promise<void> | void,
  signal?: AbortSignal,
) {
  if (typeof apply !== 'function' || signal?.aborted)
    throw Error('Browser storage recipient is unavailable.');
  let pair: CryptoKeyPair | undefined = (await crypto.subtle.generateKey(
    { name: 'X25519' },
    false,
    ['deriveBits'],
  )) as CryptoKeyPair;
  if (signal?.aborted) {
    pair = undefined;
    throw Error('Browser storage recipient is unavailable.');
  }
  const publicKey = base64(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)));
  let context: BrowserTransferContext | undefined, manifest: BrowserTransferManifest | undefined;
  let index = 0,
    busy = false,
    disposed = false;
  let parts: Uint8Array[] = [];
  let activeFrame: Uint8Array | undefined;
  const controller = new AbortController(),
    cryptoSuite = suite();
  const retire = (cancel = true) => {
    disposed = true;
    pair = undefined;
    for (const p of parts) p.fill(0);
    parts = [];
    activeFrame?.fill(0);
    activeFrame = undefined;
    signal?.removeEventListener('abort', abort);
    if (cancel) controller.abort();
  };
  const abort = () => retire();
  if (signal?.aborted) {
    retire();
    throw Error('Browser storage recipient is unavailable.');
  }
  signal?.addEventListener('abort', abort, { once: true });
  return {
    publicKey,
    bind(value: unknown) {
      const candidate = parseBrowserTransferContext(value);
      if (disposed || context || !candidate || candidate.restorePublicKey !== publicKey) {
        retire();
        throw Error('Invalid browser storage recipient context.');
      }
      context = candidate;
    },
    dispose: abort,
    async accept(value: unknown): Promise<BrowserTransferReceipt | undefined> {
      if (disposed || busy || !context || !pair) {
        retire();
        throw Error('Browser storage recipient is closed.');
      }
      busy = true;
      let opened: Uint8Array | undefined, frame: Uint8Array | undefined;
      try {
        const packet = parseBrowserTransferPacket(value, context, 'restore');
        if (
          !packet ||
          packet.index !== index ||
          (manifest &&
            (packet.manifest.bytes !== manifest.bytes ||
              packet.manifest.revision !== manifest.revision ||
              packet.manifest.restore !== manifest.restore))
        )
          throw Error();
        manifest = packet.manifest;
        opened = new Uint8Array(
          await cryptoSuite.open(
            {
              recipientKey: pair,
              enc: enrollmentBytes(packet.bundle.enc, 32)!,
              info: browserTransferInfo(context, 'restore', manifest, index),
            },
            enrollmentBytes(
              packet.bundle.ciphertext,
              browserTransferChunkSize(packet.manifest, index) + 16,
            )!,
          ),
        );
        if (disposed || signal?.aborted) throw Error();
        parts.push(opened);
        opened = undefined;
        index++;
        if (index < browserTransferChunkCount(manifest)) return undefined;
        frame = new Uint8Array(manifest.bytes);
        activeFrame = frame;
        let offset = 0;
        for (const p of parts) {
          frame.set(p, offset);
          offset += p.length;
          p.fill(0);
        }
        parts = [];
        const state = decodeBrowserTransferFrame(frame),
          receipt = { revision: manifest.revision, restore: manifest.restore };
        await apply(state, { ...receipt }, controller.signal);
        if (disposed || signal?.aborted) throw Error();
        retire(false);
        return receipt;
      } catch {
        retire();
        throw Error('Browser storage restore could not be completed.');
      } finally {
        opened?.fill(0);
        frame?.fill(0);
        busy = false;
      }
    },
  };
}

import type { BitwardenExtensionBridge } from '../electron/vault-bitwarden-bridge-contract.ts';
import { createBitwardenExtensionBridge } from './vault-bitwarden-extension-bridge.ts';
import { webcrypto } from './vault-bitwarden-extension-crypto.ts';
import { createBitwardenDocumentEndpoint } from './vault-bitwarden-document-endpoint.ts';
import { vaultID } from '../electron/vault-contract.ts';
import {
  createBitwardenExtensionStorage,
  type BitwardenBackgroundMemory,
  type ExtensionStorageArea,
} from './vault-bitwarden-extension-storage.ts';

export const version = 1;
const documentProperty = '__wormhole_vault_bitwarden_document_v1__';
type DocumentEndpoint = {
  token: string;
  invoke: ReturnType<typeof createBitwardenDocumentEndpoint>;
};
// The packaged IIFE is loaded only by the main-owned, exact background document.
// It reads browser APIs here; it never accepts storage values from main.
export function create(owner: unknown): BitwardenExtensionBridge {
  try {
    const world = globalThis as typeof globalThis & {
      chrome?: {
        runtime?: {
          id?: string;
          getManifest(): { manifest_version?: number };
          lastError?: unknown;
        };
        storage?: { local: ExtensionStorageArea; session?: ExtensionStorageArea };
      };
      bitwardenMain?: { memoryStorageForStateProviders?: BitwardenBackgroundMemory };
    };
    const runtime = world.chrome?.runtime,
      areas = world.chrome?.storage;
    if (
      !world.isSecureContext ||
      !webcrypto?.subtle ||
      world.location?.protocol !== 'chrome-extension:' ||
      !runtime ||
      !/^[a-p]{32}$/.test(runtime.id ?? '') ||
      runtime.id !== world.location.hostname ||
      !areas?.local
    )
      throw Error();
    const manifest = runtime.getManifest().manifest_version;
    if (manifest !== 2 && manifest !== 3) throw Error();
    return createBitwardenExtensionBridge(
      owner,
      createBitwardenExtensionStorage({
        manifestVersion: manifest,
        local: areas.local,
        session: areas.session,
        memory: world.bitwardenMain?.memoryStorageForStateProviders,
        lastError: () => runtime.lastError,
      }),
    );
  } catch {
    throw Error('Bitwarden background is unavailable.');
  }
}

// Only a main-owned exact background document installs this endpoint. The
// non-enumerable slot survives reinjection, preventing duplicate live owners.
export function install(owner: unknown, token: unknown, url: unknown): string {
  try {
    const world = globalThis as unknown as Record<string, unknown>;
    if (
      world.process !== undefined ||
      world.require !== undefined ||
      world.wormhole !== undefined ||
      !vaultID(token) ||
      typeof url !== 'string' ||
      globalThis.location.href !== url ||
      !globalThis.document ||
      Object.hasOwn(globalThis, documentProperty)
    )
      throw Error();
    const document = globalThis.document;
    const entry: DocumentEndpoint = {
      token,
      invoke: createBitwardenDocumentEndpoint(
        owner,
        create(owner),
        () => globalThis.document === document && globalThis.location.href === url,
      ),
    };
    Object.defineProperty(globalThis, documentProperty, { value: entry, configurable: true });
    return '{"ready":true,"version":1}';
  } catch {
    throw Error('Bitwarden document is unavailable.');
  }
}

export async function invoke(
  token: unknown,
  callId: unknown,
  operation: unknown,
  input: unknown,
  deadline: unknown,
): Promise<string> {
  try {
    const entry = (globalThis as unknown as Record<string, DocumentEndpoint>)[documentProperty];
    if (!entry || !vaultID(token) || entry.token !== token) throw Error();
    // Keep the retired slot for this document: a new owner needs a new
    // document, so pending Chrome writes can never cross that ownership change.
    return await entry.invoke(callId, operation, input, deadline);
  } catch {
    throw Error('Bitwarden document is unavailable.');
  }
}

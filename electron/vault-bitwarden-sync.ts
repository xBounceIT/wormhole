import {
  beginNativeBrowserTransfer,
  parseBrowserTransferRequest,
  parseBrowserTransferCancelled,
  parseBrowserProfileClosed,
  type BrowserTransferClient,
} from './vault-bitwarden-native.ts';
import {
  parseBitwardenBridgeOwner,
  parseBitwardenBridgeReceipt,
  type BitwardenBridgeOwner,
  type BitwardenExtensionBridge,
} from './vault-bitwarden-bridge-contract.ts';
import {
  browserTransferChunkCount,
  parseBrowserTransferManifest,
  parseBrowserTransferPacket,
} from './vault-bitwarden-transfer.ts';
import { vaultFields, vaultRecord } from './vault-contract.ts';

type NativeStage = Awaited<ReturnType<typeof beginNativeBrowserTransfer>>;
type Options = {
  owner: BitwardenBridgeOwner;
  client: BrowserTransferClient;
  bridge: BitwardenExtensionBridge;
  current(): boolean;
};
export type BitwardenSyncResult = { rounds: number; checkpointPending: boolean };

// One exact native process and extension document own this coordinator. Main
// never receives storage values, merge witnesses, or private transport keys.
export class VaultBitwardenSynchronizer {
  private readonly owner: BitwardenBridgeOwner;
  private readonly options: Options;
  private running: Promise<BitwardenSyncResult> | undefined;
  private closing: Promise<void> | undefined;
  private stage: NativeStage | undefined;
  private identity: { fileId: string; policySequence: string } | undefined;
  private closed = false;
  private cleaned = false;
  private uncertain = false;

  constructor(options: Options) {
    const owner = parseBitwardenBridgeOwner(options.owner);
    if (!owner) throw Error('Invalid Bitwarden owner.');
    this.owner = owner;
    this.options = { ...options, owner };
  }

  synchronize(): Promise<BitwardenSyncResult> {
    if (this.closed || this.uncertain)
      return Promise.reject(Error('Bitwarden synchronization is unavailable.'));
    if (this.running) return this.running;
    this.running = Promise.resolve()
      .then(async () => {
        // A requested restore is not an acknowledgement. Capture the actual
        // resulting extension state, while bounding concurrent-refresh retries.
        for (let rounds = 1; rounds <= 3; rounds++) {
          const restored = await this.exchange();
          if (!restored) return { rounds, checkpointPending: false };
        }
        return { rounds: 3, checkpointPending: true };
      })
      .catch(async (error: unknown) => {
        // A late native begin can lose authority before returning its capability.
        // Its AggregateError means the original cancellation was not confirmed.
        if (error instanceof AggregateError) this.uncertain = true;
        const results = await Promise.allSettled([
          Promise.resolve().then(async () => {
            if (!parseBrowserTransferCancelled(await this.options.bridge.cancel()))
              throw Error('Bitwarden cancellation is unconfirmed.');
          }),
          Promise.resolve().then(() => this.stage?.cancel()),
        ]);
        if (results.some((result) => result.status === 'rejected')) this.uncertain = true;
        else this.stage = undefined;
        throw Error(
          this.uncertain
            ? 'Bitwarden synchronization cleanup is unconfirmed.'
            : 'Bitwarden synchronization failed.',
        );
      })
      .finally(() => {
        this.running = undefined;
      });
    return this.running;
  }

  close(): Promise<void> {
    if (this.cleaned) return Promise.resolve();
    if (this.closing) return this.closing;
    this.closed = true;
    const running = this.running;
    this.closing = Promise.resolve()
      .then(async () => {
        const results = await Promise.allSettled([
          Promise.resolve().then(async () => {
            if (!parseBrowserProfileClosed(await this.options.bridge.dispose()))
              throw Error('Bitwarden disposal is unconfirmed.');
          }),
          Promise.resolve().then(() => this.stage?.cancel()),
        ]);
        // A late begin/reply must finish its original-owner cancellation before
        // profile close. Never select a replacement client for this cleanup.
        await running?.catch(() => undefined);
        const profile = await Promise.allSettled([
          Promise.resolve().then(async () => {
            if (
              !parseBrowserProfileClosed(
                await this.options.client.closeBitwardenProfile(this.owner.profileId),
              )
            )
              throw Error('Bitwarden profile cleanup is unconfirmed.');
          }),
        ]);
        if ([...results, ...profile].some((result) => result.status === 'rejected'))
          throw Error('Bitwarden profile cleanup is unconfirmed.');
        this.stage = undefined;
        this.cleaned = true;
      })
      .finally(() => {
        this.closing = undefined;
      });
    return this.closing;
  }

  private current(): boolean {
    return !this.closed && !this.uncertain && this.options.current();
  }

  private check(): void {
    if (!this.current()) throw Error('Bitwarden owner is unavailable.');
  }

  private async exchange(): Promise<boolean> {
    this.check();
    const q = parseBrowserTransferRequest(await this.options.bridge.prepare());
    this.check();
    if (!q || Object.entries(this.owner).some(([key, value]) => q[key as keyof typeof q] !== value))
      throw Error('Invalid Bitwarden transfer.');
    const stage = await beginNativeBrowserTransfer(this.options.client, q, () => this.current());
    this.stage = stage;
    const c = stage.context;
    if (
      this.identity &&
      (c.fileId !== this.identity.fileId || c.policySequence !== this.identity.policySequence)
    )
      throw Error('Bitwarden native owner changed.');
    this.identity ??= { fileId: c.fileId, policySequence: c.policySequence };
    const capture = await this.options.bridge.bind(c);
    this.check();
    const manifest =
      vaultRecord(capture) && vaultFields(capture, ['chunks', 'manifest'])
        ? parseBrowserTransferManifest(capture.manifest, c, 'capture')
        : undefined;
    if (!manifest || capture.chunks !== browserTransferChunkCount(manifest))
      throw Error('Invalid Bitwarden capture.');
    for (let index = 0; index < capture.chunks; index++) {
      const packet = parseBrowserTransferPacket(await this.options.bridge.next(), c, 'capture');
      this.check();
      if (
        !packet ||
        packet.index !== index ||
        Object.entries(manifest).some(
          ([key, value]) => packet.manifest[key as keyof typeof manifest] !== value,
        )
      )
        throw Error('Invalid Bitwarden capture packet.');
      await stage.push(packet);
    }
    const restore = parseBrowserTransferManifest(await stage.commit(), c, 'restore');
    if (!restore) throw Error('Invalid Bitwarden restore.');
    const count = browserTransferChunkCount(restore);
    for (let index = 0; index < count; index++) {
      const packet = parseBrowserTransferPacket(await stage.take(index), c, 'restore');
      if (
        !packet ||
        packet.index !== index ||
        Object.entries(restore).some(
          ([key, value]) => packet.manifest[key as keyof typeof restore] !== value,
        )
      )
        throw Error('Invalid Bitwarden restore packet.');
      const receipt = parseBitwardenBridgeReceipt(await this.options.bridge.accept(packet));
      this.check();
      if (
        !receipt ||
        (index < count - 1
          ? receipt.complete
          : !receipt.complete ||
            receipt.revision !== restore.revision ||
            receipt.restore !== restore.restore)
      )
        throw Error('Invalid Bitwarden receipt.');
    }
    // Native Take retires the stage after its last ciphertext packet.
    this.stage = undefined;
    return restore.restore;
  }
}

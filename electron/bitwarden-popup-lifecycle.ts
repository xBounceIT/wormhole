export type BitwardenBrowserStage =
  | 'prepare'
  | 'profile'
  | 'migrations'
  | 'read'
  | 'capture'
  | 'restore'
  | 'commit'
  | 'flush'
  | 'marker'
  | 'background'
  | 'bridge'
  | 'checkpoint'
  | 'popup';

type BitwardenBrowserReason = 'failed' | 'timeout' | 'closed' | 'unavailable' | 'conflict';

// Raw Chromium/extension/backend errors can contain account or vault data. Only these
// fixed classifications may leave the native extension flow or reach persistent logs.
export class BitwardenBrowserFailure extends Error {
  readonly stage: BitwardenBrowserStage;
  readonly reason: BitwardenBrowserReason;

  constructor(stage: BitwardenBrowserStage, reason: BitwardenBrowserReason) {
    super(`Bitwarden browser operation failed (${stage}/${reason}).`);
    this.name = 'BitwardenBrowserFailure';
    this.stage = stage;
    this.reason = reason;
  }

  get code(): string {
    return `${this.stage}/${this.reason}`;
  }
}

export function describeBitwardenBrowserFailure(
  error: unknown,
  stage: BitwardenBrowserStage,
): BitwardenBrowserFailure {
  if (error instanceof BitwardenBrowserFailure) return error;
  const message = error instanceof Error ? error.message : '';
  const reason = /timed out/i.test(message)
    ? 'timeout'
    : /closed|destroyed/i.test(message)
      ? 'closed'
      : /unavailable|not ready/i.test(message)
        ? 'unavailable'
        : /changed during synchronization/i.test(message)
          ? 'conflict'
          : 'failed';
  return new BitwardenBrowserFailure(stage, reason);
}

type ClosableWebContents = {
  isDestroyed(): boolean;
  close(): void;
};

type PopupContentsHost<TContents extends ClosableWebContents> = {
  readonly webContents?: TContents;
};

export async function prepareBitwardenPopupStorage(
  synchronize: () => Promise<void>,
  canUseLiveStorage: (error: unknown) => boolean,
): Promise<void> {
  try {
    await synchronize();
  } catch (error) {
    // Only a failed checkpoint of reconciled live state is recoverable. Hydration or merge
    // failures must still block editing, even if the background was initialized earlier.
    if (!canUseLiveStorage(error)) {
      throw describeBitwardenBrowserFailure(error, 'prepare');
    }
  }
}

export async function afterBitwardenPopupInputEvent<TResult>(
  operation: () => Promise<TResult>,
): Promise<TResult> {
  // Destroying a WebContentsView from its own before-mouse-event path can leave Chromium sending
  // the rest of that input sequence to an invalid WidgetHost. The next main-loop turn is late
  // enough for Blink to finish dispatching the click while remaining imperceptible to the user.
  await new Promise<void>((resolve) => setImmediate(resolve));
  return operation();
}

export function closeBitwardenPopupContents<TContents extends ClosableWebContents>(
  popup: PopupContentsHost<TContents> | undefined,
): void {
  try {
    const contents = popup?.webContents;
    if (contents && !contents.isDestroyed()) contents.close();
  } catch {
    // Electron clears WebContentsView.webContents when an extension calls window.close().
    // Closing an already-destroyed browser popup is therefore an expected no-op.
  }
}

export async function flushAndCloseBitwardenPopupContents<TContents extends ClosableWebContents>(
  popup: PopupContentsHost<TContents> | undefined,
  flush: (contents: TContents) => Promise<void>,
): Promise<boolean> {
  let contents: TContents | undefined;
  try {
    contents = popup?.webContents;
    if (!contents || contents.isDestroyed()) return false;
  } catch {
    return false;
  }

  try {
    await flush(contents);
    return true;
  } finally {
    // Bitwarden persists its authenticated state from the popup page. Keep that page alive until
    // the storage transaction completes, then tear it down even when the transaction fails.
    closeBitwardenPopupContents(popup);
  }
}

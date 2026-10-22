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
      throw new Error('Bitwarden could not restore its saved browser session. Please try again.');
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

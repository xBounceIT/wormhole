export type NativeAuthenticationWindow = {
  isDestroyed(): boolean;
  isEnabled(): boolean;
  setEnabled(enabled: boolean): void;
  focus(): void;
};

function attemptWindowAction(action: () => void): void {
  try {
    action();
  } catch {
    // The window can be destroyed while native authentication is settling.
  }
}

export function restoreNativeAuthenticationWindow(window: NativeAuthenticationWindow): void {
  let destroyed = true;
  attemptWindowAction(() => {
    destroyed = window.isDestroyed();
  });
  if (destroyed) return;

  attemptWindowAction(() => {
    if (!window.isEnabled()) window.setEnabled(true);
  });
  attemptWindowAction(() => window.focus());
}

export async function runWithNativeAuthenticationWindow<TResult>(
  window: NativeAuthenticationWindow,
  operation: () => Promise<TResult>,
): Promise<TResult> {
  try {
    return await operation();
  } finally {
    // Windows Hello owns and temporarily disables the Electron HWND. Some failure and
    // cancellation paths do not re-enable that cross-process owner, so recover it explicitly.
    restoreNativeAuthenticationWindow(window);
  }
}

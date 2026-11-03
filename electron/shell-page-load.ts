// A document load can fail before any renderer code (including its error UI) can run.
// Report it through a native dialog and dispose the unusable window. Never include raw
// load errors: Chromium errors can contain full URLs and authentication parameters.
export async function loadShellPage(options: {
  load: () => Promise<unknown>;
  isDestroyed: () => boolean;
  reportFailure: () => void;
  close: () => void;
}): Promise<void> {
  try {
    await options.load();
  } catch (error) {
    if (options.isDestroyed()) return;
    // A reload/redirect supersedes the original navigation; its rejection is not a failure.
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ERR_ABORTED')
      return;
    try {
      options.reportFailure();
    } catch {
      // Native reporting is best effort; a failed dialog must not become an unhandled rejection.
    } finally {
      if (!options.isDestroyed()) options.close();
    }
  }
}

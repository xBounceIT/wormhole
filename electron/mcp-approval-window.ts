export type McpApprovalWindow = {
  isDestroyed(): boolean;
  isMinimized(): boolean;
  isVisible(): boolean;
  restore(): void;
  show(): void;
  moveTop(): void;
  focus(): void;
};

function isUsableWindow(window: McpApprovalWindow): boolean {
  try {
    return !window.isDestroyed();
  } catch {
    return false;
  }
}

export function selectMcpApprovalWindow<TWindow extends McpApprovalWindow>(
  windows: readonly TWindow[],
  focusedWindow: TWindow | null | undefined,
  isMainWindow: (window: TWindow) => boolean,
): TWindow | undefined {
  if (focusedWindow && isUsableWindow(focusedWindow) && isMainWindow(focusedWindow)) {
    return focusedWindow;
  }
  return windows.find((window) => isUsableWindow(window) && isMainWindow(window));
}

function attemptWindowAction(action: () => void): void {
  try {
    action();
  } catch {
    // Foregrounding is best-effort and must never block delivery of the approval event.
  }
}

export function bringMcpApprovalWindowToFront(window: McpApprovalWindow): void {
  if (!isUsableWindow(window)) return;
  attemptWindowAction(() => {
    if (window.isMinimized()) window.restore();
  });
  attemptWindowAction(() => {
    if (!window.isVisible()) window.show();
  });
  attemptWindowAction(() => window.moveTop());
  attemptWindowAction(() => window.focus());
}

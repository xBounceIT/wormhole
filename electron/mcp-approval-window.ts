export type McpApprovalWindow = {
  isDestroyed(): boolean;
  isMinimized(): boolean;
  isVisible(): boolean;
  restore(): void;
  show(): void;
  moveTop(): void;
  focus(): void;
};

export type McpApprovalBlockingWindow = McpApprovalWindow & {
  destroy(): void;
  hide(): void;
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

export class McpApprovalWindowCoordinator<TWindow extends McpApprovalBlockingWindow> {
  private readonly pendingApprovalIds = new Set<string>();
  private readonly tunnelAuthWindows = new Set<TWindow>();

  get hasPendingApprovals(): boolean {
    return this.pendingApprovalIds.size > 0;
  }

  presentTunnelAuthWindow(window: TWindow): void {
    if (!isUsableWindow(window)) return;
    this.tunnelAuthWindows.add(window);
    if (this.pendingApprovalIds.size === 0) attemptWindowAction(() => window.show());
  }

  forgetTunnelAuthWindow(window: TWindow): void {
    this.tunnelAuthWindows.delete(window);
  }

  beginApproval(approvalId: string): void {
    this.pendingApprovalIds.add(approvalId);
    for (const window of this.tunnelAuthWindows) {
      if (isUsableWindow(window)) attemptWindowAction(() => window.hide());
    }
  }

  finishApproval(approvalId: string): void {
    if (!this.pendingApprovalIds.delete(approvalId) || this.pendingApprovalIds.size > 0) return;
    for (const window of this.tunnelAuthWindows) {
      if (!isUsableWindow(window)) {
        this.tunnelAuthWindows.delete(window);
        continue;
      }
      attemptWindowAction(() => window.show());
      attemptWindowAction(() => window.focus());
    }
  }

  reset(): void {
    this.pendingApprovalIds.clear();
    for (const window of this.tunnelAuthWindows) {
      if (isUsableWindow(window)) attemptWindowAction(() => window.destroy());
    }
    this.tunnelAuthWindows.clear();
  }
}

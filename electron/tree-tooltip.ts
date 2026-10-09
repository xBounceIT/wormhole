import type { BrowserWindow, BrowserWindowConstructorOptions } from 'electron';

export type TreeTooltipRequest = {
  text: string;
  anchor: { x: number; y: number; width: number; height: number };
  width: number;
};

type TreeTooltipRecord = {
  window: BrowserWindow;
  ready: Promise<void>;
  revision: number;
  detach: () => void;
};

// Leave transparent room around the original 28px bubble for Windows' native minimum height.
const tooltipWindowHeight = 40;

const tooltipHtml = `<!doctype html>
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<style>
  * { box-sizing: border-box; }
  html, body { width: 100%; height: 100%; margin: 0; overflow: hidden; background: transparent; }
  body { position: relative; display: flex; align-items: center; padding-left: 5px; font: 12px/16px system-ui, sans-serif; }
  body::before { position: absolute; z-index: 1; top: 50%; left: 1px; width: 10px; height: 10px; content: ''; transform: translateY(-50%) rotate(45deg); border-radius: 2px; background: #fafafa; }
  .tooltip { position: relative; width: calc(100% - 5px); overflow: hidden; padding: 6px 12px; border-radius: 6px; background: #fafafa; color: #0a0a0a; white-space: nowrap; text-overflow: ellipsis; }
  #tooltip-text { position: relative; z-index: 2; }
</style>
<div class="tooltip"><span id="tooltip-text"></span></div>`;

export class TreeTooltipManager {
  private readonly records = new Map<number, TreeTooltipRecord>();
  private readonly createWindow: (options: BrowserWindowConstructorOptions) => BrowserWindow;

  constructor(createWindow: (options: BrowserWindowConstructorOptions) => BrowserWindow) {
    this.createWindow = createWindow;
  }

  show(owner: BrowserWindow, request: TreeTooltipRequest): void {
    if (owner.isDestroyed()) return;
    const record = this.getOrCreate(owner);
    const revision = ++record.revision;
    const isCurrent = () =>
      this.records.get(owner.id) === record &&
      record.revision === revision &&
      !owner.isDestroyed() &&
      !record.window.isDestroyed();
    void record.ready
      .then(async () => {
        if (!isCurrent()) return;
        await record.window.webContents.executeJavaScript(
          `document.getElementById('tooltip-text').textContent = ${JSON.stringify(request.text)}`,
        );
        if (!isCurrent() || !owner.isVisible() || owner.isMinimized()) return;

        const content = owner.getContentBounds();
        const width = Math.round(request.width);
        const height = tooltipWindowHeight;
        const x = Math.min(
          Math.max(0, Math.round(request.anchor.x + request.anchor.width)),
          Math.max(0, content.width - width),
        );
        const y = Math.min(
          Math.max(0, Math.round(request.anchor.y + (request.anchor.height - height) / 2)),
          Math.max(0, content.height - height),
        );

        // RDP is an owned top-level HWND. Raise this native sibling above it;
        // re-raising a Chromium view cannot change the native stacking order.
        record.window.setBounds({ x: content.x + x, y: content.y + y, width, height });
        record.window.showInactive();
        this.raiseForWindow(owner);
      })
      .catch(() => {
        if (isCurrent()) this.closeForWindow(owner);
      });
  }

  hide(owner: BrowserWindow): void {
    const record = this.records.get(owner.id);
    if (!record) return;
    record.revision += 1;
    if (!record.window.isDestroyed()) record.window.hide();
  }

  raiseForWindow(owner: BrowserWindow): void {
    const record = this.records.get(owner.id);
    if (
      !record ||
      owner.isDestroyed() ||
      !owner.isVisible() ||
      owner.isMinimized() ||
      record.window.isDestroyed() ||
      !record.window.isVisible()
    )
      return;
    try {
      record.window.moveTop();
    } catch {
      // An auxiliary-window failure must not interrupt native RDP event delivery.
      this.closeForWindow(owner);
    }
  }

  closeForWindow(owner: BrowserWindow): void {
    const record = this.records.get(owner.id);
    if (!record) return;
    this.records.delete(owner.id);
    record.detach();
    if (!record.window.isDestroyed()) record.window.destroy();
  }

  private getOrCreate(owner: BrowserWindow): TreeTooltipRecord {
    const existing = this.records.get(owner.id);
    if (existing) return existing;

    const window = this.createWindow({
      parent: owner,
      width: 48,
      height: tooltipWindowHeight,
      show: false,
      frame: false,
      thickFrame: false,
      transparent: true,
      backgroundColor: '#00000000',
      hasShadow: false,
      focusable: false,
      skipTaskbar: true,
      resizable: false,
      movable: false,
      minimizable: false,
      maximizable: false,
      fullscreenable: false,
      webPreferences: {
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true,
        devTools: false,
      },
    });
    window.setMenu(null);
    window.setIgnoreMouseEvents(true, { forward: true });
    const ready = window.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(tooltipHtml)}`);
    const hide = () => this.hide(owner);
    const close = () => this.closeForWindow(owner);
    owner.on('blur', hide);
    owner.on('hide', hide);
    owner.on('minimize', hide);
    owner.on('move', hide);
    owner.on('resize', hide);
    owner.on('closed', close);
    window.on('closed', close);
    const detach = () => {
      owner.removeListener('blur', hide);
      owner.removeListener('hide', hide);
      owner.removeListener('minimize', hide);
      owner.removeListener('move', hide);
      owner.removeListener('resize', hide);
      owner.removeListener('closed', close);
      window.removeListener('closed', close);
    };
    const record = { window, ready, revision: 0, detach };
    this.records.set(owner.id, record);
    void ready.catch(() => {
      // Page loading belongs to the window, not to an individual hover revision.
      if (this.records.get(owner.id) === record) this.closeForWindow(owner);
    });
    return record;
  }
}

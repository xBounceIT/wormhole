import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebglAddon } from '@xterm/addon-webgl';
import { Unicode11Addon } from '@xterm/addon-unicode11';
import '@xterm/xterm/css/xterm.css';

export type TerminalOutput = Extract<WormholeSshEvent, { type: 'terminal-output' }>;

export interface TerminalActions {
  input: (data: string, paste?: boolean) => void;
  resize: (columns: number, rows: number) => void;
  copy: (text: string) => void;
  paste: () => Promise<boolean>;
  active: boolean;
  autoCopy: boolean;
}

const terminals = new Map<string, XtermSession>();

export function sshTerminal(sessionId: string): XtermSession {
  let session = terminals.get(sessionId);
  if (!session) {
    session = new XtermSession(sessionId);
    terminals.set(sessionId, session);
  }
  return session;
}

export function retainSshTerminals(sessionIds: ReadonlySet<string>): void {
  for (const [id, terminal] of terminals) {
    if (!sessionIds.has(id)) {
      terminal.dispose();
      terminals.delete(id);
    }
  }
}

// Presentation state lives outside React. Mounted surfaces attach the same terminal
// across page/tab switches; output continues to parse while its DOM is detached.
export class XtermSession {
  readonly terminal = new Terminal({
    cols: 80,
    rows: 24,
    scrollback: 5000,
    fontFamily: '"Cascadia Mono", "Consolas", monospace',
    fontSize: 13,
    lineHeight: 18 / 13,
    cursorBlink: true,
    cursorStyle: 'block',
    allowProposedApi: true,
    theme: {
      background: '#090909',
      foreground: '#e5e7eb',
      cursor: '#e5e7eb',
      black: '#1d2021',
      red: '#cc241d',
      green: '#98971a',
      yellow: '#d79921',
      blue: '#458588',
      magenta: '#b16286',
      cyan: '#689d6a',
      white: '#a89984',
      brightBlack: '#928374',
      brightRed: '#fb4934',
      brightGreen: '#b8bb26',
      brightYellow: '#fabd2f',
      brightBlue: '#83a598',
      brightMagenta: '#d3869b',
      brightCyan: '#8ec07c',
      brightWhite: '#ebdbb2',
    },
  });
  private fitAddon = new FitAddon();
  private host = document.createElement('div');
  private opened = false;
  private disposed = false;
  private parsing = false;
  private queue: TerminalOutput[] = [];
  private pending = new Set<number>();
  private processed = 0;
  private actions?: TerminalActions;
  private copyChord = false;

  constructor(
    private sessionId: string,
    private createWebgl = () => new WebglAddon(),
  ) {
    this.host.style.cssText = 'width:100%;height:100%;overflow:hidden';
    this.terminal.loadAddon(this.fitAddon);
    this.terminal.loadAddon(new Unicode11Addon());
    this.terminal.unicode.activeVersion = '11';
    this.terminal.onData((data) => {
      if (this.actions) this.actions.input(data);
      else {
        // DSR/DA replies can arrive before React mounts the surface.
        const bytes = new TextEncoder().encode(data);
        void window.wormhole
          ?.sendSshInput(this.sessionId, btoa(String.fromCharCode(...bytes)))
          .catch(() => undefined);
      }
    });
    this.terminal.onBinary((data) => {
      // Legacy mouse reports contain byte values which must not be UTF-8 encoded.
      void window.wormhole?.sendSshInput(this.sessionId, btoa(data)).catch(() => undefined);
    });
    this.terminal.onResize(({ cols, rows }) => {
      if (this.actions?.active) this.actions.resize(cols, rows);
    });
    this.terminal.attachCustomKeyEventHandler((event) => this.key(event));
    this.host.addEventListener(
      'blur',
      () => {
        this.copyChord = false;
      },
      true,
    );
    this.host.addEventListener('mouseup', (event) => {
      if (event.button === 0 && this.actions?.active && this.actions.autoCopy) this.copy();
    });
    this.host.addEventListener('contextmenu', (event) => {
      event.preventDefault();
      if (this.actions?.active) this.paste();
    });
    this.host.addEventListener(
      'paste',
      (event) => {
        event.preventDefault();
        event.stopPropagation();
        // Native menu/primary-selection paste must use Go's size bounds and
        // escape sanitization, rather than xterm's unsanitized paste envelope.
        if (this.actions?.active && event.clipboardData)
          this.actions.input(event.clipboardData.getData('text/plain'), true);
      },
      true,
    );
  }

  configure(actions: TerminalActions): void {
    this.actions = actions;
    if (!actions.active) this.copyChord = false;
    // disableStdin also suppresses protocol replies (DSR/DA) from hidden tabs.
    // Make the input element read-only and guard user gestures instead.
    if (this.terminal.textarea) this.terminal.textarea.readOnly = !actions.active;
  }

  attach(surface: HTMLElement): void {
    surface.append(this.host);
    if (!this.opened) {
      this.terminal.open(this.host);
      this.opened = true;
      this.terminal.textarea!.readOnly = !this.actions?.active;
      // Chromium's DOM renderer remains usable on software GPUs and context loss.
      try {
        const addon = this.createWebgl();
        this.terminal.loadAddon(addon);
        addon.onContextLoss(() => {
          addon.dispose();
        });
      } catch {
        // The default renderer remains available if the addon cannot initialize.
      }
    }
    this.fit();
  }

  detach(): void {
    if (this.actions) this.actions = { ...this.actions, active: false };
    this.copyChord = false;
    if (this.terminal.textarea) this.terminal.textarea.readOnly = true;
    this.host.remove();
  }

  fit(): void {
    if (
      !this.opened ||
      !this.actions?.active ||
      this.host.clientWidth < 20 ||
      this.host.clientHeight < 20
    )
      return;
    const dimensions = this.fitAddon.proposeDimensions();
    if (!dimensions) return;
    this.terminal.resize(
      Math.min(500, Math.max(2, dimensions.cols)),
      Math.min(500, Math.max(1, dimensions.rows)),
    );
  }

  focus(): void {
    if (this.actions?.active) this.terminal.focus();
  }

  receive(packet: TerminalOutput): void {
    if (this.disposed) return;
    if (packet.sequence <= this.processed) {
      this.acknowledge(packet.sequence);
      return;
    }
    if (this.pending.has(packet.sequence)) return;
    this.pending.add(packet.sequence);
    this.queue.push(packet);
    this.drain();
  }

  private acknowledge(sequence: number): void {
    window.wormhole?.acknowledgeSshTerminal(this.sessionId, sequence);
  }

  private drain(): void {
    if (this.parsing || this.disposed) return;
    const packet = this.queue.shift();
    if (!packet) return;
    if (packet.reset) {
      this.terminal.reset();
      this.terminal.resize(packet.columns, packet.rows);
      this.fit();
      if (this.opened && this.actions?.active)
        this.actions.resize(this.terminal.cols, this.terminal.rows);
    }
    const batch = [packet];
    let encoded = packet.data;
    let bytes = Uint8Array.from(atob(encoded), (char) => char.charCodeAt(0));
    // Parse queued chunks together, without delaying a keystroke-sized first packet.
    while (
      this.queue.length &&
      !this.queue[0].reset &&
      bytes.length + (this.queue[0].data.length * 3) / 4 <= 65536
    ) {
      const next = this.queue.shift()!;
      batch.push(next);
      encoded = next.data;
      const added = Uint8Array.from(atob(encoded), (char) => char.charCodeAt(0));
      const merged = new Uint8Array(bytes.length + added.length);
      merged.set(bytes);
      merged.set(added, bytes.length);
      bytes = merged;
    }
    this.parsing = true;
    this.terminal.write(bytes, () => {
      this.parsing = false;
      if (this.disposed) return;
      for (const item of batch) {
        this.processed = item.sequence;
        this.pending.delete(item.sequence);
        this.acknowledge(item.sequence);
      }
      this.drain();
    });
  }

  private copy(): void {
    const text = this.terminal.getSelection();
    if (text) this.actions?.copy(text);
  }

  private paste(): void {
    const selection = this.terminal.getSelection();
    void this.actions
      ?.paste()
      .then((pasted) => {
        if (pasted && this.terminal.getSelection() === selection) this.terminal.clearSelection();
      })
      .catch(() => undefined);
  }

  private key(event: KeyboardEvent): boolean {
    if (!this.actions?.active) return false;
    const key = event.key.toLowerCase();
    if (event.type === 'keyup') {
      if (key === 'c') this.copyChord = false;
      return !((event.ctrlKey || event.metaKey) && (key === 'c' || key === 'v'));
    }
    if (this.copyChord && key === 'c') return false;
    if (!event.altKey && (event.ctrlKey || event.metaKey)) {
      if (key === 'c' && (this.terminal.hasSelection() || event.shiftKey)) {
        event.preventDefault();
        this.copyChord = true;
        this.copy();
        return false;
      }
      if (key === 'v') {
        event.preventDefault();
        this.paste();
        return false;
      }
    }
    return true;
  }

  dispose(): void {
    this.disposed = true;
    this.queue = [];
    this.pending.clear();
    this.detach();
    this.terminal.dispose();
  }
}

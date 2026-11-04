import { isRdpFrame, type RdpFrame, type RdpInput } from '../electron/rdp-framebuffer.ts';

// RDP set-1 scancodes describe physical keys, preserving modifier combinations
// and the remote keyboard layout. Unicode is reserved for composed text.
const scanCodes: Record<string, number> = {
  Escape: 0x01,
  Backspace: 0x0e,
  Tab: 0x0f,
  Enter: 0x1c,
  ControlLeft: 0x1d,
  ShiftLeft: 0x2a,
  ShiftRight: 0x36,
  AltLeft: 0x38,
  Space: 0x39,
  CapsLock: 0x3a,
  NumLock: 0x45,
  ScrollLock: 0x46,
  Semicolon: 0x27,
  Quote: 0x28,
  Backquote: 0x29,
  Backslash: 0x2b,
  Comma: 0x33,
  Period: 0x34,
  Slash: 0x35,
  Minus: 0x0c,
  Equal: 0x0d,
  BracketLeft: 0x1a,
  BracketRight: 0x1b,
  IntlBackslash: 0x56,
  ControlRight: 0x11d,
  AltRight: 0x138,
  MetaLeft: 0x15b,
  MetaRight: 0x15c,
  ContextMenu: 0x15d,
  Home: 0x147,
  ArrowUp: 0x148,
  PageUp: 0x149,
  ArrowLeft: 0x14b,
  ArrowRight: 0x14d,
  End: 0x14f,
  ArrowDown: 0x150,
  PageDown: 0x151,
  Insert: 0x152,
  Delete: 0x153,
  PrintScreen: 0x137,
  NumpadEnter: 0x11c,
  NumpadDivide: 0x135,
  NumpadMultiply: 0x37,
  NumpadSubtract: 0x4a,
  NumpadAdd: 0x4e,
  NumpadDecimal: 0x53,
};
for (const [letters, start] of [
  ['QWERTYUIOP', 0x10],
  ['ASDFGHJKL', 0x1e],
  ['ZXCVBNM', 0x2c],
] as const) {
  [...letters].forEach((letter, index) => {
    scanCodes[`Key${letter}`] = start + index;
  });
}
for (let index = 0; index < 10; index++) scanCodes[`Digit${(index + 1) % 10}`] = 2 + index;
for (let index = 1; index <= 12; index++)
  scanCodes[`F${index}`] = index <= 10 ? 0x3a + index : 0x57 + index - 11;
[0x52, 0x4f, 0x50, 0x51, 0x4b, 0x4c, 0x4d, 0x47, 0x48, 0x49].forEach((code, index) => {
  scanCodes[`Numpad${index}`] = code;
});

export function rdpKeyInput(code: string, down: boolean): RdpInput | undefined {
  const scanCode = scanCodes[code];
  return scanCode ? { kind: 'key', code: scanCode, down } : undefined;
}

export function rdpPointerInput(
  rect: { left: number; top: number; width: number; height: number },
  desktop: { width: number; height: number },
  x: number,
  y: number,
  flags: number,
): RdpInput | undefined {
  if (rect.width <= 0 || rect.height <= 0 || desktop.width < 1 || desktop.height < 1) return;
  return {
    kind: 'pointer',
    flags,
    x: Math.max(
      0,
      Math.min(desktop.width - 1, Math.floor(((x - rect.left) * desktop.width) / rect.width)),
    ),
    y: Math.max(
      0,
      Math.min(desktop.height - 1, Math.floor(((y - rect.top) * desktop.height) / rect.height)),
    ),
  };
}

export function decodeRdpTile(frame: RdpFrame): Uint8ClampedArray<ArrayBuffer> | undefined {
  if (!isRdpFrame(frame)) return;
  const decoded = atob(frame.rgba);
  if (decoded.length !== frame.width * frame.height * 4) return;
  return Uint8ClampedArray.from(decoded, (byte) => byte.charCodeAt(0));
}

/** Serialize inputs without allowing pointer motion to grow an unbounded IPC queue. */
export function createRdpInputQueue(
  send: (input: RdpInput, lifecycleId: string) => Promise<void>,
  lifecycle: () => string = () => '',
) {
  let pending: { input: RdpInput; lifecycleId: string }[] = [];
  let running = false;
  let closed = false;
  const drain = async () => {
    running = true;
    while (pending.length && !closed) {
      const item = pending.shift()!;
      try {
        await send(item.input, item.lifecycleId);
      } catch {
        pending = [];
        // A lost key-up must not leave held input behind. One best-effort release,
        // bound to the failed lifecycle, avoids recursive retries on a closed pipe.
        if (item.input.kind !== 'release')
          await send({ kind: 'release' }, item.lifecycleId).catch(() => undefined);
      }
    }
    running = false;
  };
  return {
    push(input: RdpInput) {
      if (closed) return;
      const lifecycleId = lifecycle();
      const item = { input, lifecycleId };
      const last = pending.at(-1);
      if (
        input.kind === 'pointer' &&
        input.flags === 0x0800 &&
        last?.input.kind === 'pointer' &&
        last.input.flags === 0x0800 &&
        last.lifecycleId === lifecycleId
      ) {
        pending[pending.length - 1] = item;
      } else if (input.kind === 'release' || pending.length >= 256) {
        // Release remote held keys/buttons after overload instead of dropping key-up.
        pending = [{ input: { kind: 'release' }, lifecycleId }];
      } else {
        pending.push(item);
      }
      if (!running) void drain();
    },
    close() {
      pending = [];
      closed = true;
    },
  };
}

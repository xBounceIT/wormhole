import { mergeTerminalScrollback, nextTerminalViewportResetSequence } from './terminal-frame.ts';

const terminalMaxScrollbackLines = 5000;

export type RenderedTerminalFrame = WormholeSshTerminalFrame & {
  viewportResetSequence?: number;
  scrollbackStart?: number;
};

export function encodeTerminalData(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function createBlankTerminalCells(columns: number, rows: number): WormholeSshTerminalCell[] {
  return Array.from({ length: columns * rows }, () => ({
    character: ' ',
    foreground: 0xff80,
    background: 0xff81,
  }));
}

export function applySshTerminalFrame(
  previous: RenderedTerminalFrame | undefined,
  incoming: WormholeSshTerminalFrame,
): RenderedTerminalFrame {
  const cellCount = incoming.columns * incoming.rows;
  const hasMatchingPrevious =
    previous &&
    previous.columns === incoming.columns &&
    previous.rows === incoming.rows &&
    previous.cells?.length === cellCount;
  const cells =
    incoming.full && incoming.cells?.length === cellCount
      ? incoming.cells.slice()
      : hasMatchingPrevious
        ? incoming.changes.length > 0
          ? previous.cells!.slice()
          : previous.cells!
        : createBlankTerminalCells(incoming.columns, incoming.rows);

  for (const change of incoming.changes) {
    if (change.index < 0 || change.index >= cells.length) continue;
    // Frames with cell changes always get a fresh buffer above, so this never mutates
    // the previous frame. React Doctor mistakes that local buffer for React state.
    // react-doctor-disable-next-line react-doctor/no-side-effect-in-state-updater-function
    cells[change.index] = {
      character: change.character,
      foreground: change.foreground,
      background: change.background,
    };
  }

  return {
    ...incoming,
    full: true,
    cells,
    ...mergeTerminalScrollback(previous, incoming, terminalMaxScrollbackLines),
    viewportResetSequence: nextTerminalViewportResetSequence(
      previous?.viewportResetSequence,
      incoming,
    ),
  };
}

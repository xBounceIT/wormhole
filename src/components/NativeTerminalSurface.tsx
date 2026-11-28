import { memo, useEffect, useLayoutEffect, useRef, type ReactNode } from 'react';
import { copyTextToClipboard } from '../clipboard';
import {
  clearTerminalSelectionIfUnchanged,
  copyTerminalSelection,
  normalizeTerminalPasteText,
  shouldAutoCopyTerminalSelection,
  shouldUseTerminalClipboardShortcut,
  terminalCopyChordAfterKeyDown,
  terminalCopyChordAfterKeyUp,
} from '../terminal-clipboard';
import { terminalControlKeyData } from '../terminal-keyboard';
import { selectTerminalDoubleClick } from '../terminal-selection';
import {
  sameTerminalScrollbackChunk,
  sameTerminalViewport,
  terminalScrollbackChunks,
  scrollTerminalToBottom,
  terminalScrollEventKeepsBottomPin,
  terminalVisibleScrollback,
} from '../terminal-frame';
import type { RenderedTerminalFrame } from '../native-terminal-frame';

const terminalFontSize = 13;
const terminalFontFamily = '"Cascadia Mono", "Consolas", monospace';
const terminalFallbackCellWidth = 8;
const terminalLineHeight = 18;
const terminalScrollbackChunkSize = 128;
const terminalDefaultForeground = 0xff80;
const terminalDefaultBackground = 0xff81;
const terminalAnsiPalette = [
  '#1d2021',
  '#cc241d',
  '#98971a',
  '#d79921',
  '#458588',
  '#b16286',
  '#689d6a',
  '#a89984',
  '#928374',
  '#fb4934',
  '#b8bb26',
  '#fabd2f',
  '#83a598',
  '#d3869b',
  '#8ec07c',
  '#ebdbb2',
];

function terminalColor(value: number, fallback: string): string {
  if (value === terminalDefaultForeground || value === terminalDefaultBackground) return fallback;
  if (value < 16) return terminalAnsiPalette[value] ?? fallback;
  if (value < 232) {
    const color = value - 16;
    const red = Math.floor(color / 36);
    const green = Math.floor((color % 36) / 6);
    const blue = color % 6;
    const channel = (component: number) => (component === 0 ? 0 : 55 + component * 40);
    return `rgb(${channel(red)} ${channel(green)} ${channel(blue)})`;
  }
  if (value < 256) {
    const gray = 8 + (value - 232) * 10;
    return `rgb(${gray} ${gray} ${gray})`;
  }
  return fallback;
}

function measureTerminalCellWidth(): number {
  if (typeof document === 'undefined') return terminalFallbackCellWidth;
  const canvas = document.createElement('canvas');
  const context = canvas.getContext('2d');
  if (!context) return terminalFallbackCellWidth;
  context.font = `${terminalFontSize}px ${terminalFontFamily}`;
  const width = context.measureText('0').width;
  return Number.isFinite(width) && width > 0 ? width : terminalFallbackCellWidth;
}

function terminalWheelDelta(
  surface: HTMLElement,
  value: number,
  deltaMode: number,
  axis: 'x' | 'y',
): number {
  if (deltaMode === 1)
    return value * (axis === 'y' ? terminalLineHeight : terminalFallbackCellWidth);
  if (deltaMode === 2) return value * (axis === 'y' ? surface.clientHeight : surface.clientWidth);
  return value;
}

function terminalIsAtBottom(surface: HTMLElement): boolean {
  return surface.scrollHeight - surface.scrollTop - surface.clientHeight <= terminalLineHeight;
}

type TerminalTextRun = {
  text: string;
  foreground: string;
  background: string;
  cursor: boolean;
  cellCount: number;
};

function terminalTextRuns(frame: WormholeSshTerminalFrame, row: number): TerminalTextRun[] {
  const runs: TerminalTextRun[] = [];
  const offset = row * frame.columns;
  for (let column = 0; column < frame.columns; column++) {
    const cell = frame.cells?.[offset + column];
    if (!cell) continue;
    const cursor = frame.cursorVisible && frame.cursorX === column && frame.cursorY === row;
    const foreground = cursor
      ? terminalColor(cell.background, '#090909')
      : terminalColor(cell.foreground, '#e5e7eb');
    const background = cursor ? '#e5e7eb' : terminalColor(cell.background, '#090909');
    const previous = runs[runs.length - 1];
    if (
      previous &&
      previous.foreground === foreground &&
      previous.background === background &&
      previous.cursor === cursor
    ) {
      previous.text += cell.character || ' ';
      previous.cellCount += 1;
    } else {
      runs.push({
        text: cell.character || ' ',
        foreground,
        background,
        cursor,
        cellCount: 1,
      });
    }
  }
  return runs;
}

const TerminalScrollbackChunk = memo(function TerminalScrollbackChunk({
  lines,
  start,
}: {
  lines: WormholeSshTerminalScrollbackLine[];
  start: number;
}) {
  return (
    <div
      className="terminal-scrollback-chunk"
      style={{ height: `${lines.length * terminalLineHeight}px` }}
    >
      {lines.map((line, index) => {
        const runs = line.runs.length
          ? line.runs
          : [
              {
                text: ' ',
                cells: 1,
                foreground: terminalDefaultForeground,
                background: terminalDefaultBackground,
              },
            ];
        return (
          <div data-terminal-row className="h-[18px] min-w-max whitespace-pre" key={start + index}>
            {runs.map((run, runIndex) => (
              <span
                className="inline-block overflow-hidden align-top"
                key={`${start + index}-${runIndex}`}
                style={{
                  backgroundColor: terminalColor(run.background, '#090909'),
                  color: terminalColor(run.foreground, '#e5e7eb'),
                  height: `${terminalLineHeight}px`,
                  width: `${run.cells}ch`,
                }}
              >
                {run.text}
              </span>
            ))}
          </div>
        );
      })}
    </div>
  );
}, sameTerminalScrollbackChunk);

const TerminalScrollback = memo(function TerminalScrollback({
  lines,
  start = 0,
}: {
  lines?: WormholeSshTerminalScrollbackLine[];
  start?: number;
}) {
  if (!lines?.length) return null;

  return (
    <div aria-label="SSH terminal scrollback" className="terminal-scrollback">
      {terminalScrollbackChunks(lines, start, terminalScrollbackChunkSize).map((chunk) => (
        <TerminalScrollbackChunk
          key={Math.floor(chunk.start / terminalScrollbackChunkSize)}
          start={chunk.start}
          lines={chunk.lines}
        />
      ))}
    </div>
  );
});

const TerminalTextGrid = memo(function TerminalTextGrid({
  frame,
}: {
  frame?: RenderedTerminalFrame;
}) {
  if (!frame?.cells) return null;
  return (
    <div
      className="min-h-full min-w-max select-text"
      style={{
        fontFamily: terminalFontFamily,
        fontSize: `${terminalFontSize}px`,
        fontSynthesis: 'none',
        lineHeight: `${terminalLineHeight}px`,
        textRendering: 'geometricPrecision',
        fontVariantLigatures: 'none',
      }}
    >
      <TerminalScrollback lines={terminalVisibleScrollback(frame)} start={frame.scrollbackStart} />
      <TerminalViewport frame={frame} />
    </div>
  );
});

const TerminalViewport = memo(
  function TerminalViewport({ frame }: { frame: WormholeSshTerminalFrame }) {
    return (
      <>
        {Array.from({ length: frame.rows }, (_, row) => (
          <div data-terminal-row className="h-[18px] min-w-max whitespace-pre" key={row}>
            {terminalTextRuns(frame, row).map((run, index) => (
              <span
                className={`inline-block overflow-hidden align-top ${run.cursor ? 'terminal-cursor' : ''}`}
                key={`${row}-${index}`}
                style={{
                  backgroundColor: run.background,
                  color: run.foreground,
                  height: `${terminalLineHeight}px`,
                  width: `${run.cellCount}ch`,
                }}
              >
                {run.text}
              </span>
            ))}
          </div>
        ))}
      </>
    );
  },
  (previous, incoming) => sameTerminalViewport(previous.frame, incoming.frame),
);

function terminalCsiWithModifier(final: string, event: React.KeyboardEvent, appCursor: boolean) {
  const modifier = 1 + (event.shiftKey ? 1 : 0) + (event.altKey ? 2 : 0) + (event.ctrlKey ? 4 : 0);
  if (modifier === 1 && appCursor) return `\u001bO${final}`;
  if (modifier === 1) return `\u001b[${final}`;
  return `\u001b[1;${modifier}${final}`;
}

function terminalKeyData(event: React.KeyboardEvent, appCursor: boolean): string | undefined {
  if (event.nativeEvent.isComposing || event.metaKey) return undefined;
  const key = event.key;
  if (event.ctrlKey && !event.altKey) {
    const controlData = terminalControlKeyData(key);
    if (controlData !== undefined) return controlData;
  }

  if (key === 'Enter') return '\r';
  if (key === 'Backspace') return '\u007f';
  if (key === 'Tab') return event.shiftKey ? '\u001b[Z' : '\t';
  if (key === 'Escape') return '\u001b';
  if (key === 'ArrowUp') return terminalCsiWithModifier('A', event, appCursor);
  if (key === 'ArrowDown') return terminalCsiWithModifier('B', event, appCursor);
  if (key === 'ArrowRight') return terminalCsiWithModifier('C', event, appCursor);
  if (key === 'ArrowLeft') return terminalCsiWithModifier('D', event, appCursor);
  if (key === 'Home') return terminalCsiWithModifier('H', event, appCursor);
  if (key === 'End') return terminalCsiWithModifier('F', event, appCursor);
  if (key === 'Insert') return '\u001b[2~';
  if (key === 'Delete') return '\u001b[3~';
  if (key === 'PageUp') return '\u001b[5~';
  if (key === 'PageDown') return '\u001b[6~';
  if (key === 'F1') return '\u001bOP';
  if (key === 'F2') return '\u001bOQ';
  if (key === 'F3') return '\u001bOR';
  if (key === 'F4') return '\u001bOS';
  if (key === 'F5') return '\u001b[15~';
  if (key === 'F6') return '\u001b[17~';
  if (key === 'F7') return '\u001b[18~';
  if (key === 'F8') return '\u001b[19~';
  if (key === 'F9') return '\u001b[20~';
  if (key === 'F10') return '\u001b[21~';
  if (key === 'F11') return '\u001b[23~';
  if (key === 'F12') return '\u001b[24~';
  if (key.length === 1) return event.altKey ? `\u001b${key}` : key;
  return undefined;
}

function terminalSelection(surface: HTMLElement): Selection | undefined {
  const selection = window.getSelection();
  if (
    !selection ||
    selection.isCollapsed ||
    !selection.anchorNode ||
    !selection.focusNode ||
    !surface.contains(selection.anchorNode) ||
    !surface.contains(selection.focusNode)
  ) {
    return undefined;
  }
  return selection;
}

function terminalSelectionText(surface: HTMLElement): string {
  return terminalSelection(surface)?.toString() ?? '';
}

export function NativeTerminalSurface({
  session,
  isActive,
  autoCopyOnSelect,
  onInput,
  isSerial = false,
  onResize,
  fallback,
}: {
  session: {
    id: string;
    backendSessionId?: string;
    status: string;
    terminalFrame?: RenderedTerminalFrame;
  };
  isActive: boolean;
  autoCopyOnSelect: boolean;
  onInput: (sessionId: string, value: string, paste?: boolean) => void;
  isSerial?: boolean;
  onResize?: (sessionId: string, columns: number, rows: number) => Promise<void>;
  fallback?: ReactNode;
}) {
  const surfaceRef = useRef<HTMLDivElement>(null);
  const resizeSignatureRef = useRef('');
  const stickToBottomRef = useRef(true);
  const automaticScrollTopRef = useRef<number | undefined>(undefined);
  const handledViewportResetSequenceRef = useRef<number | undefined>(undefined);
  const terminalCopyChordActiveRef = useRef(false);

  useEffect(() => {
    const surface = surfaceRef.current;
    const backendSessionId = session.backendSessionId;
    if (
      !isActive ||
      !surface ||
      !backendSessionId ||
      session.status !== 'connected' ||
      typeof ResizeObserver === 'undefined'
    )
      return;

    resizeSignatureRef.current = '';
    const resize = () => {
      if (stickToBottomRef.current) {
        automaticScrollTopRef.current = scrollTerminalToBottom(surface);
      }
      const cellWidth = measureTerminalCellWidth();
      if (surface.clientWidth < cellWidth || surface.clientHeight < terminalLineHeight) return;
      const columns = Math.min(500, Math.max(1, Math.floor(surface.clientWidth / cellWidth)));
      const rows = Math.min(
        500,
        Math.max(1, Math.floor(surface.clientHeight / terminalLineHeight)),
      );
      const signature = `${columns}x${rows}`;
      if (signature === resizeSignatureRef.current) return;
      resizeSignatureRef.current = signature;
      const resizeRequest = onResize
        ? onResize(backendSessionId, columns, rows)
        : isSerial
          ? window.wormhole?.resizeSerialSession(backendSessionId, columns, rows)
          : window.wormhole?.resizeSshSession(backendSessionId, columns, rows);
      void resizeRequest?.catch(() => {
        // A resize can race with a close; the closed event owns the visible session state.
      });
    };
    const observer = new ResizeObserver(resize);
    observer.observe(surface);
    resize();
    return () => observer.disconnect();
  }, [isActive, isSerial, onResize, session.backendSessionId, session.status]);

  useLayoutEffect(() => {
    stickToBottomRef.current = true;
    automaticScrollTopRef.current = undefined;
    handledViewportResetSequenceRef.current = undefined;
    terminalCopyChordActiveRef.current = false;
  }, [session.backendSessionId, session.status]);

  useLayoutEffect(() => {
    if (!isActive || session.status !== 'connected') return;
    const surface = surfaceRef.current;
    if (!surface) return;
    const viewportResetSequence = session.terminalFrame?.viewportResetSequence;
    if (
      viewportResetSequence !== undefined &&
      viewportResetSequence !== handledViewportResetSequenceRef.current
    ) {
      stickToBottomRef.current = true;
      handledViewportResetSequenceRef.current = viewportResetSequence;
    }
    if (!stickToBottomRef.current) return;
    automaticScrollTopRef.current = scrollTerminalToBottom(surface);
  }, [
    isActive,
    session.backendSessionId,
    session.status,
    session.terminalFrame?.viewportResetSequence,
    session.terminalFrame?.sequence,
  ]);

  useEffect(() => {
    if (!isActive || session.status !== 'connected') return;
    const surface = surfaceRef.current;
    if (!surface) return;

    const handleWheel = (event: WheelEvent) => {
      const maxScrollTop = Math.max(0, surface.scrollHeight - surface.clientHeight);
      const maxScrollLeft = Math.max(0, surface.scrollWidth - surface.clientWidth);
      const rawDeltaX = terminalWheelDelta(surface, event.deltaX, event.deltaMode, 'x');
      const rawDeltaY = terminalWheelDelta(surface, event.deltaY, event.deltaMode, 'y');
      const deltaX = Number.isFinite(rawDeltaX) ? rawDeltaX : 0;
      const deltaY = Number.isFinite(rawDeltaY) ? rawDeltaY : 0;
      if ((maxScrollTop <= 0 && maxScrollLeft <= 0) || (deltaX === 0 && deltaY === 0)) return;

      const nextScrollLeft = Math.min(maxScrollLeft, Math.max(0, surface.scrollLeft + deltaX));
      const nextScrollTop = Math.min(maxScrollTop, Math.max(0, surface.scrollTop + deltaY));

      // Keep the terminal as the scroll owner. This is deliberately a native,
      // non-passive listener because Chromium can make delegated React wheel
      // listeners passive, which lets the surrounding layout consume the wheel.
      event.preventDefault();
      event.stopPropagation();

      surface.scrollLeft = nextScrollLeft;
      if (deltaY !== 0) {
        automaticScrollTopRef.current = undefined;
        surface.scrollTop = nextScrollTop;
        stickToBottomRef.current = terminalIsAtBottom(surface);
      }
    };

    surface.addEventListener('wheel', handleWheel, { passive: false });
    return () => surface.removeEventListener('wheel', handleWheel);
  }, [isActive, session.status]);

  useEffect(() => {
    if (!isActive || session.status !== 'connected') return;
    const surface = surfaceRef.current;
    if (!surface) return;
    const focus = () => surface.focus({ preventScroll: true });
    const frame = requestAnimationFrame(focus);
    return () => cancelAnimationFrame(frame);
  }, [isActive, session.backendSessionId, session.status]);

  useEffect(() => {
    if (!isActive || session.status !== 'connected') {
      terminalCopyChordActiveRef.current = false;
      return;
    }

    const resetCopyChord = () => {
      terminalCopyChordActiveRef.current = false;
    };
    const resetCopyChordWhenHidden = () => {
      if (document.visibilityState !== 'visible') resetCopyChord();
    };
    window.addEventListener('blur', resetCopyChord);
    document.addEventListener('visibilitychange', resetCopyChordWhenHidden);
    return () => {
      window.removeEventListener('blur', resetCopyChord);
      document.removeEventListener('visibilitychange', resetCopyChordWhenHidden);
      resetCopyChord();
    };
  }, [isActive, session.status]);

  useEffect(() => {
    const surface = surfaceRef.current;
    if (!isActive || session.status !== 'connected' || !surface) return;
    const clearOnOutsidePointer = (event: PointerEvent) => {
      if (event.target instanceof Node && !surface.contains(event.target)) {
        terminalSelection(surface)?.removeAllRanges();
      }
    };
    document.addEventListener('pointerdown', clearOnOutsidePointer, true);
    return () => document.removeEventListener('pointerdown', clearOnOutsidePointer, true);
  }, [isActive, session.status]);

  if (session.status !== 'connected') {
    return (
      <div
        aria-label={isSerial ? 'Serial connection state' : 'SSH connection state'}
        className="flex h-full min-h-0 min-w-0 flex-1 items-center justify-center overflow-auto bg-[#090909] px-6 py-10 text-zinc-100"
        ref={surfaceRef}
      >
        {fallback}
      </div>
    );
  }

  return (
    <div
      aria-label={isSerial ? 'Live serial terminal' : 'Live SSH terminal'}
      className="terminal-scrollbar h-full min-h-0 min-w-0 flex-1 cursor-text overflow-x-auto overflow-y-auto overscroll-contain bg-[#090909] text-[#e5e7eb] outline-none"
      onClick={(event) => event.currentTarget.focus({ preventScroll: true })}
      onMouseDown={selectTerminalDoubleClick}
      onKeyDown={(event) => {
        const hasSelection = Boolean(terminalSelectionText(event.currentTarget));
        const useClipboard = shouldUseTerminalClipboardShortcut(
          event,
          hasSelection,
          terminalCopyChordActiveRef.current,
        );
        terminalCopyChordActiveRef.current = terminalCopyChordAfterKeyDown(
          event,
          hasSelection,
          terminalCopyChordActiveRef.current,
        );
        if (useClipboard) return;
        const data = terminalKeyData(event, session.terminalFrame?.applicationCursor ?? false);
        if (data === undefined) return;
        event.preventDefault();
        terminalSelection(event.currentTarget)?.removeAllRanges();
        onInput(session.id, data);
      }}
      onKeyUp={(event) => {
        terminalCopyChordActiveRef.current = terminalCopyChordAfterKeyUp(
          event,
          terminalCopyChordActiveRef.current,
        );
      }}
      onBlur={() => {
        terminalCopyChordActiveRef.current = false;
      }}
      onCopy={(event) => {
        const copied = copyTerminalSelection(
          terminalSelectionText(event.currentTarget),
          event.clipboardData,
        );
        if (copied) event.preventDefault();
      }}
      onPaste={(event) => {
        const text = event.clipboardData.getData('text');
        if (!text) return;
        event.preventDefault();
        terminalSelection(event.currentTarget)?.removeAllRanges();
        onInput(session.id, isSerial ? normalizeTerminalPasteText(text) : text, !isSerial);
      }}
      onMouseUp={(event) => {
        if (!shouldAutoCopyTerminalSelection(autoCopyOnSelect, event.button)) return;
        const surface = event.currentTarget;
        const selection = terminalSelection(surface);
        const text = selection?.toString() ?? '';
        if (!selection || !text) return;
        void copyTextToClipboard(text).catch(() => undefined);
      }}
      onContextMenu={(event) => {
        if (isSerial || !session.backendSessionId) return;
        event.preventDefault();
        const surface = event.currentTarget;
        const selection = terminalSelection(surface);
        const previousSelection = selection && {
          anchorNode: selection.anchorNode,
          anchorOffset: selection.anchorOffset,
          focusNode: selection.focusNode,
          focusOffset: selection.focusOffset,
        };
        void window.wormhole
          ?.pasteClipboardToSsh(session.backendSessionId)
          .then(({ pasted }) => {
            if (pasted && previousSelection) {
              clearTerminalSelectionIfUnchanged(terminalSelection(surface), previousSelection);
            }
          })
          .catch(() => undefined);
      }}
      onCompositionEnd={(event) => {
        if (!event.data) return;
        terminalSelection(event.currentTarget)?.removeAllRanges();
        onInput(session.id, event.data);
      }}
      onScroll={(event) => {
        const surface = event.currentTarget;
        const isAutomaticScroll = terminalScrollEventKeepsBottomPin(
          surface.scrollTop,
          false,
          automaticScrollTopRef.current,
        );
        stickToBottomRef.current = isAutomaticScroll || terminalIsAtBottom(surface);
        // Output may have grown since Chromium queued this event. Catch up now,
        // including the final frame, and retain the marker for subsequent events.
        automaticScrollTopRef.current = isAutomaticScroll
          ? scrollTerminalToBottom(surface)
          : undefined;
      }}
      ref={surfaceRef}
      role="application"
      style={{ overflowAnchor: 'none', scrollbarGutter: 'stable' }}
      tabIndex={0}
    >
      <TerminalTextGrid frame={session.terminalFrame} />
    </div>
  );
}

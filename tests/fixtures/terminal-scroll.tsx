// Runs the production terminal surface and text grid with real React and Chromium.
declare const React: typeof import('react');
declare const createRoot: typeof import('react-dom/client').createRoot;
declare const assert: typeof import('node:assert/strict');
declare function NativeTerminalSurface(
  props: Record<string, unknown>,
): import('react').ReactElement;

async function runTerminalScrollTests() {
  const root = createRoot(document.getElementById('root'));
  let sequence = 0;
  const line = {
    runs: [{ text: 'output', cells: 6, foreground: 7, background: 0 }],
  };
  let session = {
    id: 'terminal-scroll',
    backendSessionId: 'backend-1',
    status: 'connected',
    terminalFrame: {},
  };
  let isActive = true;
  let autoCopy = false;
  const sentInput: string[] = [];
  const renderSession = async () => {
    await React.act(async () => {
      root.render(
        <React.StrictMode>
          <NativeTerminalSurface
            isSerial={true}
            session={session}
            isActive={isActive}
            autoCopyOnSelect={autoCopy}
            onInput={(_id: string, data: string) => sentInput.push(data)}
            onReconnect={() => {}}
          />
        </React.StrictMode>,
      );
    });
  };
  const render = async (lines: number, overrides = {}) => {
    session = {
      ...session,
      terminalFrame: {
        sequence: ++sequence,
        columns: 1,
        rows: 10,
        cells: Array.from({ length: 10 }, () => ({ character: 'x', foreground: 7, background: 0 })),
        scrollback: Array.from({ length: lines }, () => line),
        ...overrides,
      },
    };
    await renderSession();
  };
  const receiveFrame = async (overrides = {}) => {
    session = {
      ...session,
      terminalFrame: applySshTerminalFrame(session.terminalFrame, {
        columns: 80,
        rows: 10,
        full: false,
        changes: [],
        scrollbackReset: false,
        viewportReset: false,
        alternateScreen: false,
        cursorX: 0,
        cursorY: 0,
        cursorVisible: false,
        applicationCursor: false,
        sequence: ++sequence,
        ...overrides,
      }),
    };
    await renderSession();
  };
  const settle = () =>
    new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  const surface = () => document.querySelector<HTMLElement>('[role="application"]');
  const gap = () => surface().scrollHeight - surface().clientHeight - surface().scrollTop;
  const atBottom = () =>
    assert.ok(Math.abs(gap()) <= 1, `terminal stopped ${gap()}px before the end`);
  const wheel = async (deltaY: number, deltaX = 0, deltaMode = 0) => {
    surface().dispatchEvent(
      new WheelEvent('wheel', { deltaY, deltaX, deltaMode, cancelable: true }),
    );
    await settle();
  };

  const sizes: Array<{ id: string; columns: number; rows: number }> = [];
  window.wormhole = {
    resizeSerialSession: async (id: string, columns: number, rows: number) => {
      sizes.push({ id, columns, rows });
    },
  } as unknown as Window['wormhole'];
  const selection = document.getSelection();
  try {
    await render(1, {
      columns: 12,
      rows: 1,
      cells: [...'split  right'].map((character, index) => ({
        character,
        foreground: index < 2 ? 1 : 7,
        background: 0,
      })),
      scrollback: [
        {
          runs: [
            { text: 'sp', cells: 2, foreground: 1, background: 0 },
            { text: 'lit  right', cells: 10, foreground: 7, background: 0 },
          ],
        },
      ],
    });
    const renderedRows = surface().querySelectorAll<HTMLElement>('[data-terminal-row]');
    assert.equal(renderedRows.length, 2, 'the fixture must mount a live row and a scrollback row');
    for (const row of renderedRows) {
      assert.equal(row.innerText, 'split  right');
      const firstRun = row.firstElementChild;
      const range = document.createRange();
      range.setStart(firstRun.firstChild, 0);
      range.setEnd(firstRun.firstChild, 1);
      const glyph = range.getBoundingClientRect();
      firstRun.dispatchEvent(
        new MouseEvent('mousedown', {
          bubbles: true,
          cancelable: true,
          button: 0,
          detail: 2,
          clientX: (glyph.left + glyph.right) / 2,
        }),
      );
      assert.equal(selection.toString(), 'split', 'a double click must select across styled runs');

      range.selectNodeContents(row);
      selection.removeAllRanges();
      selection.addRange(range);
      const clipboardData = new DataTransfer();
      row.dispatchEvent(
        new ClipboardEvent('copy', { clipboardData, bubbles: true, cancelable: true }),
      );
      assert.equal(clipboardData.getData('text/plain'), 'split  right');
      assert.equal(selection.toString(), 'split  right');
      selection.removeAllRanges();
    }
    const writes: string[] = [];
    let denyWrites = false;
    Object.defineProperty(navigator, 'clipboard', {
      value: {
        writeText: async (value: string) => {
          writes.push(value);
          if (denyWrites) throw new Error('Clipboard unavailable');
        },
      },
    });
    document.execCommand = () => false;
    const releaseMouse = (button: number) =>
      React.act(async () =>
        surface().dispatchEvent(new MouseEvent('mouseup', { bubbles: true, button })),
      );
    selection.selectAllChildren(renderedRows[0]);
    await releaseMouse(0);
    autoCopy = true;
    await renderSession();
    await releaseMouse(1);
    await releaseMouse(2);
    assert.deepEqual(writes, []);
    for (const denied of [false, true]) {
      denyWrites = denied;
      await releaseMouse(0);
      assert.deepEqual(writes.splice(0), ['split  right']);
      assert.equal(selection.toString(), 'split  right');
    }

    const copyKey = (type: string, repeat = false) =>
      surface().dispatchEvent(
        new KeyboardEvent(type, {
          key: 'c',
          ctrlKey: true,
          repeat,
          bubbles: true,
          cancelable: true,
        }),
      );
    for (const release of [
      () => copyKey('keyup'),
      () => surface().dispatchEvent(new FocusEvent('focusout', { bubbles: true })),
      () => window.dispatchEvent(new Event('blur')),
      () => {
        Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' });
        try {
          document.dispatchEvent(new Event('visibilitychange'));
        } finally {
          Reflect.deleteProperty(document, 'visibilityState');
        }
      },
    ]) {
      selection.selectAllChildren(renderedRows[0]);
      copyKey('keydown');
      selection.removeAllRanges();
      copyKey('keydown', true);
      assert.deepEqual(sentInput, []);
      release();
      copyKey('keydown');
      assert.deepEqual(sentInput.splice(0), ['\x03']);
    }
    const paste = (text: string) => {
      const clipboardData = new DataTransfer();
      clipboardData.setData('text/plain', text);
      return surface().dispatchEvent(
        new ClipboardEvent('paste', { clipboardData, bubbles: true, cancelable: true }),
      );
    };
    selection.selectAllChildren(renderedRows[0]);
    assert.equal(paste(''), true);
    assert.equal(selection.toString(), 'split  right');
    assert.equal(paste('first\r\nsecond\nthird'), false);
    assert.equal(selection.isCollapsed, true);
    assert.deepEqual(sentInput.splice(0), ['first\rsecond\rthird']);

    for (const data of ['', '字']) {
      selection.selectAllChildren(renderedRows[0]);
      surface().dispatchEvent(new CompositionEvent('compositionend', { data, bubbles: true }));
      assert.equal(selection.isCollapsed, Boolean(data));
      assert.deepEqual(sentInput.splice(0), data ? [data] : []);
    }
    selection.removeAllRanges();
    session.backendSessionId = 'new-serial';
    for (const lines of [0, 1, 128, 129, 5000, 5000, 256]) {
      await render(lines);
      await settle();
      atBottom();
    }
    assert.equal(document.activeElement, surface());
    assert.equal(sizes.at(-1)?.id, 'new-serial');
    const terminal = surface();
    terminal.style.width = '6400px';
    terminal.style.height = '10000px';
    await settle();
    assert.deepEqual(sizes.at(-1), { id: 'new-serial', columns: 500, rows: 500 });
    const wideResizes = sizes.length;
    terminal.style.width = '7000px';
    await settle();
    assert.equal(sizes.length, wideResizes, 'unchanged grid dimensions must not trigger IPC');
    terminal.style.height = '0px';
    await settle();
    const originalFrame = window.requestAnimationFrame;
    const nextFrame = originalFrame.bind(window);
    let pendingFrameRequests = 0;
    window.requestAnimationFrame = (callback) => {
      pendingFrameRequests++;
      return nextFrame(callback);
    };
    try {
      await new Promise<void>((done) => nextFrame(() => nextFrame(() => done())));
      assert.equal(pendingFrameRequests, 0, 'a hidden terminal must stay idle until resized');
    } finally {
      window.requestAnimationFrame = originalFrame;
    }
    terminal.style.width = '';
    terminal.style.height = '';
    await settle();
    assert.ok(sizes.at(-1)!.columns < 500 && sizes.at(-1)!.rows < 500);
    // Precision touchpads can send sub-line deltas. They must accumulate.
    for (let step = 0; step < 6; step++) await wheel(-4);
    assert.ok(gap() >= 24, 'small upward wheel deltas were snapped back to the bottom');
    const manualPosition = surface().scrollTop;
    await render(256);
    await settle();
    assert.equal(surface().scrollTop, manualPosition, 'output must not steal manual scroll');
    const previousRows = sizes.at(-1)!.rows;
    surface().style.height = '90px';
    await settle();
    assert.ok(sizes.at(-1)!.rows < previousRows);
    assert.equal(surface().scrollTop, manualPosition, 'resize must preserve manual scroll');
    surface().style.height = '180px';
    await wheel(100000);
    atBottom();

    surface().firstElementChild.style.minWidth = '1000px';
    await wheel(0, 100);
    assert.equal(surface().scrollLeft, 100);
    await render(256);
    await settle();
    atBottom();
    surface().firstElementChild.style.minWidth = '';
    await settle();

    // A scrollbar drag bypasses the wheel listener.
    surface().scrollTop -= 180;
    await settle();
    const draggedPosition = surface().scrollTop;
    await render(256);
    await settle();
    assert.equal(surface().scrollTop, draggedPosition);
    await wheel(100000);

    surface().style.height = '90px';
    await settle();
    atBottom();
    surface().style.height = '180px';
    await settle();
    atBottom();

    await wheel(-180);
    await render(256, { alternateScreen: true, viewportResetSequence: sequence + 1 });
    await settle();
    assert.equal(surface().querySelector('.terminal-scrollback'), null);
    atBottom();
    await render(256, { viewportResetSequence: sequence + 1 });
    await settle();
    atBottom();

    isActive = false;
    await render(256);
    document.getElementById('root').style.display = 'none';
    await settle();
    await render(256);
    document.getElementById('root').style.display = '';
    isActive = true;
    await render(256);
    await settle();
    atBottom();

    await wheel(-180);
    const beforeHide = surface().scrollTop;
    isActive = false;
    await render(256);
    document.getElementById('root').style.display = 'none';
    await settle();
    document.getElementById('root').style.display = '';
    isActive = true;
    await render(256);
    await settle();
    assert.equal(surface().scrollTop, beforeHide, 'switching tabs must preserve manual scroll');

    session.backendSessionId += '-reconnected';
    await render(256);
    await settle();
    atBottom();

    // At capacity, new output must reuse retained DOM/text nodes and selection.
    let viewportReads = 0;
    await receiveFrame({
      full: true,
      cells: Array.from({ length: 800 }, () => ({
        get character() {
          viewportReads++;
          return 'x';
        },
        foreground: 7,
        background: 0,
      })),
      scrollbackReset: true,
      scrollback: Array.from({ length: 5000 }, (_, index) => ({
        runs: [{ text: `history-${index}`, cells: 12, foreground: 7, background: 0 }],
      })),
    });
    await settle();
    assert.ok(viewportReads > 0, 'viewport instrumentation must observe the initial paint');
    const previousCells = session.terminalFrame.cells;
    Object.freeze(previousCells);
    viewportReads = 0;
    const scrollback = surface().querySelector('.terminal-scrollback');
    const retained = scrollback.querySelectorAll('[data-terminal-row]')[2000];
    const range = document.createRange();
    range.selectNodeContents(retained);
    selection.removeAllRanges();
    selection.addRange(range);
    let mutations = 0;
    const observer = new MutationObserver((records) => {
      mutations += records.length;
    });
    observer.observe(scrollback, {
      subtree: true,
      childList: true,
      characterData: true,
      attributes: true,
    });
    try {
      for (let batch = 0; batch < 20; batch++) {
        mutations = 0;
        await receiveFrame({
          scrollback: Array.from({ length: 50 }, (_, index) => ({
            runs: [{ text: `new-${batch}-${index}`, cells: 12, foreground: 7, background: 0 }],
          })),
        });
        await settle();
        assert.equal(viewportReads, 0, 'history delta rescanned the unchanged viewport');
        assert.ok(mutations < 300, `output rebuilt history: ${mutations} DOM mutations`);
        const rows = scrollback.querySelectorAll('[data-terminal-row]');
        assert.equal(rows.length, 5000);
        assert.equal(rows[0].textContent, `history-${(batch + 1) * 50}`);
        assert.equal(rows[4999].textContent, `new-${batch}-49`);
        assert.ok(retained.isConnected, 'retained history node was replaced');
        assert.equal(selection.toString(), 'history-2000', 'output changed the selected text');
        atBottom();
      }
    } finally {
      observer.disconnect();
      selection.removeAllRanges();
    }

    // A history-only delta must retain the viewport, while an explicit cell
    // change and a full reset must still reach the mounted grid.
    assert.equal(
      surface().querySelectorAll('[data-terminal-row]')[5000].textContent,
      'x'.repeat(80),
    );
    await receiveFrame({ changes: [{ index: 0, character: 'Z', foreground: 1, background: 0 }] });
    assert.equal(previousCells[0].character, 'x', 'cell delta mutated the previous frame');
    assert.equal(
      surface().querySelectorAll('[data-terminal-row]')[5000].textContent,
      'Z' + 'x'.repeat(79),
    );
    await receiveFrame({ cursorVisible: true, cursorX: 1 });
    assert.equal(surface().querySelectorAll('.terminal-cursor').length, 1);
    assert.equal(surface().querySelector('.terminal-cursor').textContent, 'x');
    await receiveFrame({ scrollbackReset: true, viewportReset: true });
    await settle();
    assert.equal(surface().querySelector('.terminal-scrollback'), null);
    assert.equal(surface().querySelectorAll('[data-terminal-row]').length, 10);
    assert.equal(surface().querySelector('[data-terminal-row]').textContent, 'Z' + 'x'.repeat(79));
    atBottom();
  } finally {
    await React.act(async () => root.unmount());
  }
}

runTerminalScrollTests();

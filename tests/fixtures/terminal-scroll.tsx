// Runs the production terminal surface and text grid with real React and Chromium.
declare const React: typeof import('react');
declare const createRoot: typeof import('react-dom/client').createRoot;
declare const assert: typeof import('node:assert/strict');
declare function SshTerminalSurface(props: Record<string, unknown>): import('react').ReactElement;

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
  let isSerial = false;
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
    await React.act(async () => {
      root.render(
        <React.StrictMode>
          <SshTerminalSurface
            session={session}
            isActive={isActive}
            isSerial={isSerial}
            autoCopyOnSelect={false}
            onInput={() => {}}
            onReconnect={() => {}}
          />
        </React.StrictMode>,
      );
    });
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

  try {
    for (isSerial of [false, true]) {
      session.backendSessionId = `backend-${isSerial}`;
      for (const lines of [0, 1, 128, 129, 5000, 5000, 256]) {
        await render(lines);
        await settle();
        atBottom();
      }
      // Precision touchpads can send sub-line deltas. They must accumulate.
      for (let step = 0; step < 6; step++) await wheel(-4);
      assert.ok(gap() >= 24, 'small upward wheel deltas were snapped back to the bottom');
      const manualPosition = surface().scrollTop;
      await render(256);
      await settle();
      assert.equal(surface().scrollTop, manualPosition, 'output must not steal manual scroll');
      surface().style.height = '90px';
      await settle();
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
    }
  } finally {
    await React.act(async () => root.unmount());
  }
}

runTerminalScrollTests();

import assert from 'node:assert/strict';
import test from 'node:test';
import {
  mergeTerminalScrollback,
  sameTerminalScrollbackChunk,
  terminalScrollbackChunks,
} from '../src/terminal-frame.ts';

const viewport = { columns: 80, rows: 24, scrollbackReset: false };

test('scrollback deltas preserve retained identities and track eviction without mutating frames', () => {
  const lines = Array.from({ length: 5000 }, (_, index) => ({ text: `line-${index}` }));
  const previous = { ...viewport, scrollback: lines, scrollbackStart: 0 };
  Object.freeze(lines);
  const added = [{ text: 'new-1' }, { text: 'new-2' }];
  const result = mergeTerminalScrollback(previous, { ...viewport, scrollback: added }, 5000);
  assert.equal(result.scrollbackStart, 2);
  assert.equal(result.scrollback.length, 5000);
  assert.equal(result.scrollback[0], lines[2]);
  assert.equal(result.scrollback[4998], added[0]);
  assert.equal(lines[0].text, 'line-0');
  const unchanged = mergeTerminalScrollback({ ...viewport, ...result }, viewport, 5000);
  assert.equal(unchanged.scrollback, result.scrollback);
  assert.equal(unchanged.scrollbackStart, 2);
});

test('snapshots, resize, empty history and oversized batches remain bounded', () => {
  const previous = { ...viewport, scrollback: [1, 2, 3], scrollbackStart: 10 };
  for (const incoming of [
    { ...viewport, scrollbackReset: true },
    { ...viewport, columns: 90 },
    { ...viewport, rows: 30 },
  ]) {
    assert.deepEqual(mergeTerminalScrollback(previous, incoming, 3), {
      scrollback: [],
      scrollbackStart: 0,
    });
    assert.deepEqual(
      mergeTerminalScrollback(previous, { ...incoming, scrollback: [4, 5, 6, 7] }, 3),
      { scrollback: [5, 6, 7], scrollbackStart: 0 },
    );
  }
  assert.deepEqual(mergeTerminalScrollback(undefined, viewport, 3), {
    scrollback: [],
    scrollbackStart: 0,
  });
  assert.deepEqual(mergeTerminalScrollback(undefined, { ...viewport, scrollback: [1] }, 3), {
    scrollback: [1],
    scrollbackStart: 0,
  });
  assert.deepEqual(mergeTerminalScrollback(viewport, viewport, 3), {
    scrollback: [],
    scrollbackStart: 0,
  });
  assert.deepEqual(mergeTerminalScrollback(viewport, { ...viewport, scrollback: [1] }, 3), {
    scrollback: [1],
    scrollbackStart: 0,
  });
  assert.deepEqual(
    mergeTerminalScrollback(previous, { ...viewport, scrollback: [4, 5, 6, 7] }, 3),
    { scrollback: [5, 6, 7], scrollbackStart: 14 },
  );
});

test('sustained output changes only the boundary chunks, with stable row positions', () => {
  let history = {
    ...viewport,
    scrollback: Array.from({ length: 5000 }, (_, i) => ({ text: `${i}` })),
    scrollbackStart: 0,
  };
  for (let batch = 0; batch < 200; batch++) {
    const before = terminalScrollbackChunks(history.scrollback, history.scrollbackStart, 128);
    const added = Array.from({ length: 50 }, (_, i) => ({ text: `batch-${batch}-${i}` }));
    history = {
      ...viewport,
      ...mergeTerminalScrollback(history, { ...viewport, scrollback: added }, 5000),
    };
    const after = terminalScrollbackChunks(history.scrollback, history.scrollbackStart, 128);
    assert.deepEqual(
      after.flatMap((chunk) => chunk.lines),
      history.scrollback,
    );
    const changed = after.filter((chunk) => {
      const old = before.find(
        (item) => Math.floor(item.start / 128) === Math.floor(chunk.start / 128),
      );
      return !old || !sameTerminalScrollbackChunk(old, chunk);
    });
    assert.ok(changed.length <= 3, `rebuilt ${changed.length} chunks`);
    assert.ok(changed.reduce((sum, chunk) => sum + chunk.lines.length, 0) <= 306);
  }
  assert.deepEqual(terminalScrollbackChunks([], 0, 128), []);
  assert.equal(
    sameTerminalScrollbackChunk({ start: 0, lines: [1] }, { start: 0, lines: [2] }),
    false,
  );
});

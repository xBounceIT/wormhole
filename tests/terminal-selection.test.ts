import assert from 'node:assert/strict';
import test from 'node:test';
import { selectTerminalDoubleClick } from '../src/terminal-selection.ts';

function fixture(parts = ['log: ti', 'me   ']) {
  const nodes = parts.map((data) => ({ data, length: data.length }));
  let start = 0;
  let end = 0;
  let selected = '';
  let prevented = false;
  const position = (node: (typeof nodes)[number], offset: number) =>
    nodes.slice(0, nodes.indexOf(node)).reduce((sum, item) => sum + item.length, offset);
  const range = {
    setStart(node: (typeof nodes)[number], offset: number) {
      start = position(node, offset);
    },
    setEnd(node: (typeof nodes)[number], offset: number) {
      end = position(node, offset);
    },
    getBoundingClientRect() {
      return { left: start * 10, right: end * 10, top: 2, bottom: 16 };
    },
    selectNodeContents() {
      start = 0;
      end = parts.join('').length;
    },
  };
  const selection = {
    removeAllRanges() {
      selected = '';
    },
    addRange() {
      selected = parts.join('').slice(start, end);
    },
  };
  const document = {
    getSelection: (): typeof selection | null => selection,
    createRange: () => range,
    createTreeWalker() {
      let index = -1;
      return {
        nextNode: () => ++index < nodes.length,
        get currentNode() {
          return nodes[index];
        },
      };
    },
  };
  const row = { ownerDocument: document };
  const event = {
    button: 0,
    detail: 2,
    target: { closest: () => row },
    currentTarget: { contains: () => true },
    clientX: 65,
    clientY: 9,
    preventDefault() {
      prevented = true;
    },
  };
  return {
    event,
    document,
    run() {
      selectTerminalDoubleClick(
        event as unknown as Parameters<typeof selectTerminalDoubleClick>[0],
      );
      return { selected, prevented };
    },
  };
}

test('double click selects a word across styled runs without trailing spaces', () => {
  for (const clientX of [50, 59, 65, 79, 89]) {
    const f = fixture();
    f.event.clientX = clientX;
    assert.deepEqual(f.run(), { selected: 'time', prevented: true });
  }
});

test('empty space selects the row without trailing ASCII padding', () => {
  for (const clientX of [45, 90, 115, 200]) {
    const f = fixture();
    f.event.clientX = clientX;
    assert.deepEqual(f.run(), { selected: 'log: time', prevented: true });
  }
  assert.deepEqual(fixture(['   ']).run(), { selected: '', prevented: true });
  assert.deepEqual(fixture([]).run(), { selected: '', prevented: true });
});

test('row selection preserves indentation and inner spaces across styled runs', () => {
  for (const parts of [
    ['  log: ', 'time', '   ', '  '],
    ['', '  log: time', '', '   '],
    ['  log: time'],
  ]) {
    const f = fixture(parts);
    f.event.clientX = 400;
    assert.deepEqual(f.run(), { selected: '  log: time', prevented: true });
  }
});

test('row selection preserves Unicode at the end and clears padding-only rows', () => {
  for (const [parts, expected] of [
    [['caffè 😀', '   '], 'caffè 😀'],
    [['e\u0301', '  '], 'e\u0301'],
    [['', '  ', ' '], ''],
  ] as const) {
    const f = fixture([...parts]);
    f.event.clientX = 400;
    assert.deepEqual(f.run(), { selected: expected, prevented: true });
  }
});

test('row selection preserves non-padding whitespace before trailing blank cells', () => {
  for (const whitespace of ['\u00a0', '\u2003', '\u202f', '\u3000', '\t']) {
    for (const parts of [
      ['value', whitespace, '   '],
      [whitespace, '   '],
    ]) {
      const f = fixture(parts);
      f.event.clientX = 400;
      assert.deepEqual(f.run(), { selected: parts.slice(0, -1).join(''), prevented: true });
    }
  }
});

test('Unicode words and punctuation do not absorb adjacent whitespace', () => {
  for (const [parts, x, expected] of [
    [['caffè  '], 25, 'caffè'],
    [['😀  '], 5, '😀'],
    [['log:  '], 35, ':'],
  ] as const) {
    const f = fixture([...parts]);
    f.event.clientX = x;
    assert.equal(f.run().selected, expected);
  }
});

test('ordinary clicks, other buttons and clicks outside rows keep native selection', () => {
  for (const overrides of [
    { detail: 1 },
    { detail: 3 },
    { button: 2 },
    { target: null },
    { target: { closest: () => null } },
    { currentTarget: { contains: () => false } },
  ]) {
    const f = fixture();
    Object.assign(f.event, overrides);
    assert.deepEqual(f.run(), { selected: '', prevented: false });
  }
  const f = fixture();
  f.document.getSelection = () => null;
  assert.deepEqual(f.run(), { selected: '', prevented: false });
});

test('word selection includes the leading above and below the glyph', () => {
  for (const clientY of [0, 1, 16, 17]) {
    const f = fixture();
    f.event.clientY = clientY;
    assert.deepEqual(f.run(), { selected: 'time', prevented: true });
  }
});

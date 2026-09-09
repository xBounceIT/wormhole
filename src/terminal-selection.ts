// Resolve the actual glyph under the pointer instead of Chromium's nearest caret,
// which can map empty space to the last word of an inline-block run.
export function selectTerminalDoubleClick(event: {
  button: number;
  detail: number;
  target: EventTarget | null;
  currentTarget: HTMLElement;
  clientX: number;
  preventDefault(): void;
}): void {
  if (event.button !== 0 || event.detail !== 2) return;
  const row = (event.target as Element | null)?.closest('[data-terminal-row]');
  if (!row || !event.currentTarget.contains(row)) return;
  const document = row.ownerDocument;
  const selection = document.getSelection();
  if (!selection) return;
  const walker = document.createTreeWalker(row, 4 /* SHOW_TEXT */);
  const nodes: Text[] = [];
  while (walker.nextNode()) nodes.push(walker.currentNode as Text);
  const text = nodes.map((node) => node.data).join('');
  const range = document.createRange();
  let hit = -1;
  let base = 0;
  for (const node of nodes) {
    for (let offset = 0; offset < node.length;) {
      const length = String.fromCodePoint(node.data.codePointAt(offset)!).length;
      range.setStart(node, offset);
      range.setEnd(node, offset + length);
      const rect = range.getBoundingClientRect();
      // The event target already identifies the row. Its cell height includes
      // leading above and below the glyph, which must still select the word.
      if (event.clientX >= rect.left && event.clientX < rect.right) {
        hit = base + offset;
        break;
      }
      offset += length;
    }
    if (hit >= 0) break;
    base += node.length;
  }
  range.selectNodeContents(row);
  let start = 0;
  let end = text.trimEnd().length;
  if (hit >= 0 && !/\s/u.test(text[hit])) {
    const segments = new Intl.Segmenter(undefined, { granularity: 'word' }).segment(text);
    const segment = segments.containing(hit)!;
    start = segment.index;
    end = start + segment.segment.length;
  }
  base = 0;
  for (const node of nodes) {
    if (start >= base && start < base + node.length) range.setStart(node, start - base);
    if (end >= base && end <= base + node.length) {
      // End inside the final text run so the highlight excludes blank cells too.
      range.setEnd(node, end - base);
      break;
    }
    base += node.length;
  }
  event.preventDefault();
  selection.removeAllRanges();
  selection.addRange(range);
}

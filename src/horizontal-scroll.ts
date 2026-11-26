export function revealHorizontalItem(viewport: HTMLElement, item: HTMLElement): void {
  const viewportBounds = viewport.getBoundingClientRect();
  const itemBounds = item.getBoundingClientRect();
  const { scrollPaddingLeft, scrollPaddingRight } = getComputedStyle(viewport);
  const left = viewportBounds.left + (parseFloat(scrollPaddingLeft) || 0);
  const right = viewportBounds.right - (parseFloat(scrollPaddingRight) || 0);
  if (itemBounds.left < left) {
    viewport.scrollLeft += itemBounds.left - left;
  } else if (itemBounds.right > right) {
    viewport.scrollLeft += Math.min(itemBounds.right - right, itemBounds.left - left);
  }
}

export function keepHorizontalItemVisible(viewport: HTMLElement, item: HTMLElement): () => void {
  let viewportWidth = viewport.getBoundingClientRect().width;
  let itemWidth = item.getBoundingClientRect().width;
  revealHorizontalItem(viewport, item);
  const observer = new ResizeObserver(() => {
    const nextViewportWidth = viewport.getBoundingClientRect().width;
    const nextItemWidth = item.getBoundingClientRect().width;
    // The observer's initial notification must not undo scrolling after the first reveal.
    if (viewportWidth === nextViewportWidth && itemWidth === nextItemWidth) return;
    viewportWidth = nextViewportWidth;
    itemWidth = nextItemWidth;
    revealHorizontalItem(viewport, item);
  });
  observer.observe(viewport);
  observer.observe(item);
  return () => observer.disconnect();
}

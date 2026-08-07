export type BitwardenPopupAnchor = {
  x: number;
  y: number;
  width: number;
  height: number;
};

export type BitwardenPopupBounds = {
  x: number;
  y: number;
  width: number;
  height: number;
};

const margin = 8;
const anchorGap = 4;
const preferredWidth = 380;
const preferredHeight = 560;
const minimumHeight = 320;

export function positionBitwardenPopup(
  anchor: BitwardenPopupAnchor,
  contentSize: readonly [number, number],
): BitwardenPopupBounds {
  const [contentWidth, contentHeight] = contentSize;
  const width = Math.max(1, Math.min(preferredWidth, contentWidth - margin * 2));
  const x = clamp(Math.round(anchor.x), margin, Math.max(margin, contentWidth - width - margin));
  const belowY = Math.round(anchor.y + anchor.height + anchorGap);
  const availableBelow = contentHeight - belowY - margin;
  if (availableBelow >= minimumHeight) {
    return {
      x,
      y: belowY,
      width,
      height: Math.min(preferredHeight, availableBelow),
    };
  }

  const availableAbove = Math.round(anchor.y - anchorGap - margin);
  if (availableAbove >= minimumHeight) {
    const height = Math.min(preferredHeight, availableAbove);
    return { x, y: Math.round(anchor.y - anchorGap - height), width, height };
  }

  return {
    x,
    y: margin,
    width,
    height: Math.max(1, contentHeight - margin * 2),
  };
}

export function isPointInsideBitwardenAnchor(
  point: { x: number; y: number },
  anchor: BitwardenPopupAnchor,
): boolean {
  return (
    point.x >= anchor.x &&
    point.x <= anchor.x + anchor.width &&
    point.y >= anchor.y &&
    point.y <= anchor.y + anchor.height
  );
}

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(maximum, Math.max(minimum, value));
}

const wormholeShortcutSuppressionSelector = '[data-wormhole-shortcuts-disabled]';

type ShortcutEventTarget = EventTarget & {
  closest: (selector: string) => unknown;
};

function supportsClosest(target: EventTarget | null): target is ShortcutEventTarget {
  return target !== null && typeof (target as Partial<ShortcutEventTarget>).closest === 'function';
}

export function isWormholeShortcutSuppressed(target: EventTarget | null): boolean {
  return supportsClosest(target) && Boolean(target.closest(wormholeShortcutSuppressionSelector));
}

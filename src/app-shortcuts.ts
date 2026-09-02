const wormholeShortcutSuppressionSelector = '[data-wormhole-shortcuts-disabled]';
const wormholeShortcutSuppressedEvents = new WeakSet<Event>();

type ShortcutEventTarget = EventTarget & {
  closest: (selector: string) => unknown;
};

function supportsClosest(target: EventTarget | null): target is ShortcutEventTarget {
  return target !== null && typeof (target as Partial<ShortcutEventTarget>).closest === 'function';
}

export function markWormholeShortcutSuppressed(event: Event): void {
  wormholeShortcutSuppressedEvents.add(event);
}

export function isWormholeShortcutSuppressed(event: Event): boolean {
  if (wormholeShortcutSuppressedEvents.has(event)) return true;

  const target = event.target;
  return supportsClosest(target) && Boolean(target.closest(wormholeShortcutSuppressionSelector));
}

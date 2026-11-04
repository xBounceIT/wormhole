/** Pixel and input contracts shared by the isolated renderer and the Go bridge. */
export type RdpFrame = {
  desktopWidth: number;
  desktopHeight: number;
  x: number;
  y: number;
  width: number;
  height: number;
  rgba: string;
};

export type RdpInput =
  | { kind: 'pointer'; x: number; y: number; flags: number }
  | { kind: 'key' | 'unicode'; code: number; down: boolean }
  | { kind: 'release' }
  | { kind: 'painted'; code: number };

const integer = (value: unknown, min: number, max: number): value is number =>
  typeof value === 'number' && Number.isInteger(value) && value >= min && value <= max;

export function assertRdpSurfaceOwner<T>(owner: T, existing: T | undefined): void {
  if (existing !== undefined && existing !== owner)
    throw new Error('RDP session belongs to another window.');
}

export function isRdpInput(value: unknown): value is RdpInput {
  if (!value || typeof value !== 'object') return false;
  const input = value as Record<string, unknown>;
  if (input.kind === 'release') return true;
  if (input.kind === 'painted') return integer(input.code, 1, 0xffffffff);
  if (input.kind === 'pointer') {
    return (
      integer(input.x, 0, 16383) &&
      integer(input.y, 0, 16383) &&
      typeof input.flags === 'number' &&
      [0x0800, 0x1000, 0x2000, 0x4000, 0x9000, 0xa000, 0xc000, 0x0278, 0x0388].includes(input.flags)
    );
  }
  return (
    (input.kind === 'key' || input.kind === 'unicode') &&
    integer(input.code, 1, input.kind === 'key' ? 0x1ff : 0xffff) &&
    typeof input.down === 'boolean'
  );
}

export function isRdpFrame(value: unknown): value is RdpFrame {
  if (!value || typeof value !== 'object') return false;
  const frame = value as Record<string, unknown>;
  return (
    integer(frame.desktopWidth, 1, 16384) &&
    integer(frame.desktopHeight, 1, 16384) &&
    frame.desktopWidth * frame.desktopHeight <= 64 * 1024 * 1024 &&
    integer(frame.width, 1, 128) &&
    integer(frame.height, 1, 128) &&
    integer(frame.x, 0, frame.desktopWidth - frame.width) &&
    integer(frame.y, 0, frame.desktopHeight - frame.height) &&
    typeof frame.rgba === 'string' &&
    frame.rgba.length === 4 * Math.ceil((frame.width * frame.height * 4) / 3) &&
    /^[A-Za-z0-9+/]+={0,2}$/.test(frame.rgba)
  );
}

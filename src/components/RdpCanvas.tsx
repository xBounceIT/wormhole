import { useEffect, useRef } from 'react';
import { createRdpInputQueue, decodeRdpTile, rdpKeyInput, rdpPointerInput } from '../rdp-canvas';
import type { RdpInput } from '../../electron/rdp-framebuffer';

export function RdpCanvas({ sessionId, enabled }: { sessionId: string; enabled: boolean }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const lifecycle = useRef('');
  useEffect(() => {
    const canvas = canvasRef.current;
    const api = window.wormhole;
    const context = canvas?.getContext('2d', { alpha: false });
    if (!canvas || !context || !api) return;
    const unsubscribe = api.onRdpEvent((event) => {
      if (event.sessionId !== sessionId) return;
      if (event.type === 'frameEnd' && event.lifecycleId && event.paintId) {
        void api
          .sendRdpInput({
            sessionId,
            lifecycleId: event.lifecycleId,
            input: { kind: 'painted', code: event.paintId },
          })
          .catch(() => undefined);
        return;
      }
      if (event.type === 'started' || event.type === 'connected') {
        if (lifecycle.current !== event.lifecycleId)
          context.clearRect(0, 0, canvas.width, canvas.height);
        lifecycle.current = event.lifecycleId ?? '';
      }
      if (event.type !== 'frame' || !event.frame || !enabled) return;
      // On remount the first frame supplies the current lifecycle. Main/Go discard stale events.
      if (!lifecycle.current) lifecycle.current = event.lifecycleId ?? '';
      if (!lifecycle.current || lifecycle.current !== event.lifecycleId) return;
      const tile = decodeRdpTile(event.frame);
      if (!tile) return;
      if (
        canvas.width !== event.frame.desktopWidth ||
        canvas.height !== event.frame.desktopHeight
      ) {
        canvas.width = event.frame.desktopWidth;
        canvas.height = event.frame.desktopHeight;
      }
      context.putImageData(
        new ImageData(tile, event.frame.width, event.frame.height),
        event.frame.x,
        event.frame.y,
      );
    });
    return unsubscribe;
  }, [sessionId, enabled]);

  useEffect(() => {
    const canvas = canvasRef.current;
    const api = window.wormhole;
    if (!canvas || !api || !enabled) return;
    const queue = createRdpInputQueue(
      async (input, lifecycleId) => {
        if (lifecycleId) await api.sendRdpInput({ sessionId, lifecycleId, input });
      },
      () => lifecycle.current,
    );
    const send = (input?: RdpInput) => {
      if (input) queue.push(input);
    };
    const pointer = (event: PointerEvent) => {
      let flags = 0x0800;
      if (event.type !== 'pointermove') {
        const button = [0x1000, 0x4000, 0x2000][event.button];
        if (!button) return;
        flags = button | (event.type === 'pointerdown' ? 0x8000 : 0);
      }
      event.preventDefault();
      if (event.type === 'pointerdown') {
        canvas.focus();
        canvas.setPointerCapture(event.pointerId);
      }
      send(
        rdpPointerInput(
          canvas.getBoundingClientRect(),
          canvas,
          event.clientX,
          event.clientY,
          flags,
        ),
      );
    };
    const key = (event: KeyboardEvent) => {
      if (event.isComposing) return;
      const input = rdpKeyInput(event.code, event.type === 'keydown');
      if (input) {
        event.preventDefault();
        event.stopPropagation();
        send(input);
      }
    };
    const wheel = (event: WheelEvent) => {
      event.preventDefault();
      if (event.deltaY)
        send(
          rdpPointerInput(
            canvas.getBoundingClientRect(),
            canvas,
            event.clientX,
            event.clientY,
            event.deltaY < 0 ? 0x0278 : 0x0388,
          ),
        );
    };
    const release = () => send({ kind: 'release' });
    const menu = (event: Event) => event.preventDefault();
    const composition = (event: CompositionEvent) => {
      for (let index = 0; index < Math.min(event.data.length, 128); index++) {
        const code = event.data.charCodeAt(index);
        send({ kind: 'unicode', code, down: true });
        send({ kind: 'unicode', code, down: false });
      }
    };
    canvas.addEventListener('pointerdown', pointer);
    canvas.addEventListener('pointerup', pointer);
    canvas.addEventListener('pointermove', pointer);
    canvas.addEventListener('pointercancel', release);
    canvas.addEventListener('keydown', key);
    canvas.addEventListener('keyup', key);
    canvas.addEventListener('wheel', wheel, { passive: false });
    canvas.addEventListener('blur', release);
    canvas.addEventListener('contextmenu', menu);
    canvas.addEventListener('compositionend', composition);
    return () => {
      queue.close();
      if (lifecycle.current)
        void api
          .sendRdpInput({ sessionId, lifecycleId: lifecycle.current, input: { kind: 'release' } })
          .catch(() => undefined);
      canvas.removeEventListener('pointerdown', pointer);
      canvas.removeEventListener('pointerup', pointer);
      canvas.removeEventListener('pointermove', pointer);
      canvas.removeEventListener('pointercancel', release);
      canvas.removeEventListener('keydown', key);
      canvas.removeEventListener('keyup', key);
      canvas.removeEventListener('wheel', wheel);
      canvas.removeEventListener('blur', release);
      canvas.removeEventListener('contextmenu', menu);
      canvas.removeEventListener('compositionend', composition);
    };
  }, [sessionId, enabled]);
  return (
    <canvas
      ref={canvasRef}
      tabIndex={enabled ? 0 : -1}
      aria-label="Remote desktop"
      className="absolute inset-0 h-full w-full outline-none"
      style={{ visibility: enabled ? 'visible' : 'hidden' }}
    />
  );
}

import { useEffect, useId, useRef, useState } from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useOtherModalOverlayOpen } from '@/components/ui/context-menu';
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog';
import { getVisualChangelog, type VisualChangelogRelease } from '../changelog/latest-release';

function SlideMedia({ media }: { media: VisualChangelogRelease['slides'][number]['media'] }) {
  const [failed, setFailed] = useState(false);
  const mediaClassName = 'block size-full object-contain';

  return (
    <div className="grid aspect-video max-h-[32dvh] w-full grid-cols-1 grid-rows-1 place-items-center overflow-hidden rounded-lg bg-[#14171d] ring-1 ring-foreground/10 sm:max-h-[42dvh]">
      {failed ? (
        <p className="px-4 text-center text-sm text-zinc-300">Preview unavailable</p>
      ) : media.kind === 'video' ? (
        <video
          aria-label={media.label}
          className={mediaClassName}
          controls
          onError={() => setFailed(true)}
          playsInline
          poster={media.poster}
          preload="metadata"
          src={media.src}
        >
          {media.captions && (
            <track kind="captions" label="English" srcLang="en" src={media.captions} />
          )}
        </video>
      ) : (
        <picture className="block size-full">
          {media.kind === 'gif' && (
            <source media="(prefers-reduced-motion: reduce)" srcSet={media.poster} />
          )}
          <img
            alt={media.alt}
            className={mediaClassName}
            onError={() => setFailed(true)}
            src={media.src}
          />
        </picture>
      )}
    </div>
  );
}

export function VisualChangelogCarousel({
  release,
  open,
  onClose,
  overlayId,
}: {
  release: VisualChangelogRelease;
  open: boolean;
  onClose: () => void;
  overlayId?: string;
}) {
  const [index, setIndex] = useState(0);
  const slide = release.slides[index]!;
  const count = release.slides.length;
  const last = index === count - 1;

  function move(offset: number) {
    setIndex((current) => Math.max(0, Math.min(count - 1, current + offset)));
  }

  return (
    <Dialog open={open} onOpenChange={(nextOpen) => !nextOpen && onClose()} overlayId={overlayId}>
      <DialogContent
        data-visual-changelog=""
        className="max-h-[calc(100dvh-2rem)] grid-rows-[auto_minmax(0,1fr)_auto] gap-0 overflow-hidden bg-card p-0 text-card-foreground sm:max-w-[42rem]"
        onKeyDown={(event) => {
          if (event.target instanceof HTMLVideoElement) return;
          if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
          event.preventDefault();
          move(event.key === 'ArrowLeft' ? -1 : 1);
        }}
        onPointerDownOutside={(event) => event.preventDefault()}
      >
        <div className="flex items-center gap-3 px-5 py-4 pr-14">
          <DialogTitle>What’s new</DialogTitle>
          <span className="font-mono text-xs text-muted-foreground">v{release.version}</span>
        </div>

        <div className="min-h-0 overflow-y-auto px-5 pt-1 pb-5">
          <SlideMedia key={index} media={slide.media} />
          <div aria-live="polite" aria-atomic="true" className="mt-4 space-y-1.5">
            <span className="sr-only">
              {index + 1} of {count}
            </span>
            <h3 className="text-xl leading-tight font-semibold tracking-tight">{slide.title}</h3>
            <DialogDescription className="leading-relaxed">{slide.subtitle}</DialogDescription>
          </div>
        </div>

        <div className="flex items-center justify-between gap-3 border-t px-5 py-3.5">
          <Button
            variant="outline"
            aria-disabled={index === 0}
            tabIndex={index === 0 ? -1 : undefined}
            className="aria-disabled:pointer-events-none aria-disabled:opacity-50"
            onClick={() => move(-1)}
          >
            <ChevronLeft aria-hidden="true" />
            Back
          </Button>
          {count > 1 && (
            <div
              aria-hidden="true"
              className="flex max-w-40 flex-1 items-center justify-center gap-1"
            >
              {release.slides.map(({ title }, position) => (
                <span
                  key={title}
                  className="h-1 w-4 rounded-full bg-muted-foreground/25 data-[current=true]:bg-primary"
                  data-current={position === index}
                />
              ))}
            </div>
          )}
          <Button className="min-w-20" onClick={() => (last ? onClose() : move(1))}>
            {last ? 'Done' : 'Next'}
            {!last && <ChevronRight aria-hidden="true" />}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export function VisualChangelog({
  currentVersion,
  enabled,
}: {
  currentVersion: string;
  enabled: boolean;
}) {
  const release = getVisualChangelog(currentVersion);
  const overlayId = useId();
  const otherModalOpen = useOtherModalOverlayOpen(overlayId);
  const canPresent = enabled && !otherModalOpen;
  const canCheck = release ? canPresent : enabled;
  const claim = useRef<Promise<{ claimed: boolean }> | null>(null);
  const [claimed, setClaimed] = useState(false);
  const [dismissed, setDismissed] = useState(false);

  useEffect(() => {
    const api = window.wormhole;
    if (!canCheck || !currentVersion || !api?.claimVisualChangelog) return;

    // Reuse a pending claim when StrictMode or a temporary overlay re-runs the effect.
    claim.current ??= api.claimVisualChangelog(Boolean(release)).catch(() => {
      claim.current = null;
      return { claimed: false };
    });
    let active = true;
    void claim.current.then(({ claimed }) => {
      if (active && claimed) setClaimed(true);
    });
    return () => {
      active = false;
    };
  }, [canCheck, currentVersion, release]);

  if (!release) return null;
  return (
    <VisualChangelogCarousel
      release={release}
      open={canPresent && claimed && !dismissed}
      overlayId={overlayId}
      onClose={() => setDismissed(true)}
    />
  );
}

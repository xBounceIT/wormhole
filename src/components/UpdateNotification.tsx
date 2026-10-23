import { Download, X } from 'lucide-react';
import { Button } from './ui/button';
import { Card } from './ui/card';
import { useNativeSurfaceOverlay } from './ui/context-menu';

export function UpdateNotification({
  version,
  busy,
  status,
  downloadProgress,
  onUpdate,
  onDismiss,
  onViewChanges,
}: {
  version: string;
  busy: boolean;
  status: string;
  downloadProgress: number | null;
  onUpdate: () => void;
  onDismiss: () => void;
  onViewChanges: () => void;
}) {
  useNativeSurfaceOverlay(true);

  return (
    <Card
      aria-labelledby="update-notification-title"
      className="fixed right-4 bottom-4 z-40 max-h-[calc(100dvh-2rem)] w-[calc(100vw-2rem)] max-w-sm gap-4 overflow-y-auto border-border/70 bg-card p-4 text-card-foreground shadow-lg"
      role="region"
    >
      <Button
        aria-label="Close update notification"
        className="absolute top-3 right-3 text-muted-foreground"
        onClick={onDismiss}
        size="icon-xs"
        type="button"
        variant="ghost"
      >
        <X aria-hidden="true" className="size-3.5" />
      </Button>
      <div className="flex shrink-0 items-start gap-3 pr-6" aria-atomic="true" aria-live="polite">
        <div className="grid size-9 shrink-0 place-items-center rounded-lg bg-primary/10 text-primary">
          <Download aria-hidden="true" className="size-4" />
        </div>
        <div className="min-w-0 space-y-1">
          <h3 className="text-sm leading-snug font-semibold" id="update-notification-title">
            Wormhole v{version} is now available
          </h3>
          <p className="text-xs leading-relaxed text-muted-foreground">
            Update to use the best version of Wormhole
          </p>
        </div>
      </div>
      {status ? (
        <p
          className="min-h-0 max-h-24 overflow-y-auto text-xs break-words text-muted-foreground"
          role="status"
        >
          {status}
        </p>
      ) : null}
      {downloadProgress !== null ? (
        <div
          aria-label="Update download progress"
          aria-valuemax={100}
          aria-valuemin={0}
          aria-valuenow={Math.round(downloadProgress * 100)}
          className="h-1.5 shrink-0 overflow-hidden rounded-full bg-muted"
          role="progressbar"
        >
          <div
            className="h-full rounded-full bg-primary transition-[width]"
            style={{ width: `${Math.round(downloadProgress * 100)}%` }}
          />
        </div>
      ) : null}
      <div className="flex shrink-0 flex-wrap items-center gap-2">
        <Button disabled={busy} onClick={onUpdate} size="sm">
          Update now
        </Button>
        <Button onClick={onViewChanges} size="sm" variant="ghost">
          View changes
        </Button>
      </div>
    </Card>
  );
}

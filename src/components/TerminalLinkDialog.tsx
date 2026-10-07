import { useEffect, useRef, useState } from 'react';
import { Button } from './ui/button';
import { useNativeSurfaceOverlay } from './ui/context-menu';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from './ui/dialog';

export function TerminalLinkDialog({
  url,
  onClose,
  onRestoreFocus,
}: {
  url: string;
  onClose: () => void;
  onRestoreFocus: () => void;
}) {
  const opening = useRef(false);
  const mounted = useRef(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  useNativeSurfaceOverlay(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  async function openLink() {
    if (opening.current) return;
    opening.current = true;
    setBusy(true);
    setError('');
    try {
      if (!window.wormhole) throw new Error('Desktop bridge unavailable');
      await window.wormhole.openTerminalLink(url);
      if (mounted.current) onClose();
    } catch {
      setError("Wormhole couldn't open this link. Try again.");
    } finally {
      opening.current = false;
      setBusy(false);
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent
        className="border-border/70 bg-card text-card-foreground sm:max-w-md"
        onCloseAutoFocus={(event) => {
          event.preventDefault();
          onRestoreFocus();
        }}
      >
        <DialogHeader>
          <DialogTitle>Open terminal link?</DialogTitle>
          <DialogDescription>
            This link comes from the remote terminal and could be unsafe. Only open it if you trust
            its destination.
          </DialogDescription>
        </DialogHeader>
        <p className="max-h-40 overflow-auto rounded-md border bg-muted/50 p-3 font-mono text-xs break-all">
          {url}
        </p>
        {error ? (
          <p className="text-sm text-destructive" role="alert">
            {error}
          </p>
        ) : null}
        <DialogFooter>
          <Button onClick={onClose} variant="outline">
            {busy ? 'Close' : 'Cancel'}
          </Button>
          <Button disabled={busy} onClick={() => void openLink()}>
            {busy ? 'Opening…' : 'Open in browser'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

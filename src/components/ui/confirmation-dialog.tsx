import { useCallback, useLayoutEffect, useRef, useState } from 'react';
import { Button } from './button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from './dialog';

type Confirmation = {
  title: string;
  description: string;
  confirmLabel: string;
  destructive?: boolean;
};

export function useConfirmationDialog(enabled = true, scope?: string) {
  const [pending, setPending] = useState<Confirmation | null>(null);
  const resolve = useRef<((accepted: boolean) => void) | null>(null);
  const current = useRef<{ enabled: boolean; scope?: string } | null>(null);
  const trigger = useRef<HTMLElement | null>(null);
  const cancelButton = useRef<HTMLButtonElement>(null);

  const finish = useCallback((accepted: boolean) => {
    const complete = resolve.current;
    resolve.current = null;
    setPending(null);
    complete?.(accepted);
  }, []);

  useLayoutEffect(() => {
    if (resolve.current && (!enabled || current.current?.scope !== scope)) finish(false);
    current.current = { enabled, scope };
  }, [enabled, finish, scope]);

  useLayoutEffect(
    () => () => {
      const complete = resolve.current;
      resolve.current = null;
      current.current = null;
      complete?.(false);
    },
    [],
  );

  const confirm = useCallback(
    (options: Confirmation) => {
      if (!current.current?.enabled || current.current.scope !== scope || resolve.current) {
        return Promise.resolve(false);
      }
      trigger.current =
        document.activeElement instanceof HTMLElement ? document.activeElement : null;
      return new Promise<boolean>((complete) => {
        resolve.current = complete;
        setPending(options);
      });
    },
    [scope],
  );

  const confirmationDialog = (
    <Dialog
      open={enabled && pending !== null}
      onOpenChange={(open) => {
        if (!open) finish(false);
      }}
    >
      <DialogContent
        onOpenAutoFocus={(event) => {
          event.preventDefault();
          cancelButton.current?.focus();
        }}
        onCloseAutoFocus={(event) => {
          event.preventDefault();
          if (trigger.current?.isConnected) trigger.current.focus();
        }}
        onPointerDownOutside={(event) => event.preventDefault()}
        role="alertdialog"
        showCloseButton={false}
      >
        <DialogHeader>
          <DialogTitle>{pending?.title}</DialogTitle>
          <DialogDescription>{pending?.description}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button ref={cancelButton} type="button" variant="outline" onClick={() => finish(false)}>
            Cancel
          </Button>
          <Button
            type="button"
            variant={pending?.destructive ? 'destructive' : 'default'}
            onClick={() => finish(true)}
          >
            {pending?.confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );

  return { confirm, confirmationDialog };
}

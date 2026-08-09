import { useMemo, useRef } from 'react';
import { LoaderCircle } from 'lucide-react';

import { Button } from '@/components/ui/button';
import {
  Combobox,
  ComboboxContent,
  ComboboxEmpty,
  ComboboxInput,
  ComboboxItem,
  ComboboxList,
  ComboboxTrigger,
} from '@/components/ui/combobox';
import { cn } from '@/lib/utils';

export type SearchableComboboxOption = {
  value: string;
  label: string;
  disabled?: boolean;
};

type SearchableComboboxProps = {
  id: string;
  value: string;
  options: SearchableComboboxOption[];
  onValueChange: (value: string) => void;
  placeholder: string;
  searchPlaceholder: string;
  emptyMessage: string;
  className?: string;
  disabled?: boolean;
  loading?: boolean;
};

function findScrollableAncestor(element: HTMLElement | null): HTMLElement | null {
  let ancestor = element?.parentElement ?? null;
  while (ancestor) {
    const overflowY = window.getComputedStyle(ancestor).overflowY;
    if (
      /^(auto|scroll|overlay)$/.test(overflowY) &&
      ancestor.scrollHeight > ancestor.clientHeight
    ) {
      return ancestor;
    }
    ancestor = ancestor.parentElement;
  }
  return null;
}

export function SearchableCombobox({
  id,
  value,
  options,
  onValueChange,
  placeholder,
  searchPlaceholder,
  emptyMessage,
  className,
  disabled = false,
  loading = false,
}: SearchableComboboxProps) {
  const portalContainer = useRef<HTMLElement | null>(null);
  const scrollContainer = useRef<HTMLElement | null>(null);
  const scrollTopBeforeOpen = useRef(0);
  const searchInput = useRef<HTMLInputElement | null>(null);
  const triggerElement = useRef<HTMLButtonElement | null>(null);
  const selectedOption = useMemo(
    () => options.find((option) => option.value === value) ?? null,
    [options, value],
  );

  function rememberScrollPosition() {
    const container = findScrollableAncestor(triggerElement.current);
    scrollContainer.current = container;
    scrollTopBeforeOpen.current = container?.scrollTop ?? 0;
  }

  return (
    <Combobox
      items={options}
      value={selectedOption}
      isItemEqualToValue={(option, selected) => option.value === selected.value}
      onValueChange={(option) => {
        if (option) onValueChange(option.value);
      }}
      onOpenChange={(open) => {
        if (!open || !scrollContainer.current) return;
        const container = scrollContainer.current;
        const scrollTop = scrollTopBeforeOpen.current;
        queueMicrotask(() => {
          container.scrollTop = scrollTop;
          searchInput.current?.focus({ preventScroll: true });
        });
      }}
      onOpenChangeComplete={(open) => {
        if (open) searchInput.current?.focus({ preventScroll: true });
      }}
    >
      <ComboboxTrigger
        ref={(element: HTMLButtonElement | null) => {
          triggerElement.current = element;
          portalContainer.current =
            element
              ?.closest<HTMLElement>('[data-slot="dialog-content"]')
              ?.querySelector<HTMLElement>('[data-slot="dialog-popover-layer"]') ?? null;
        }}
        onKeyDownCapture={rememberScrollPosition}
        onPointerDown={rememberScrollPosition}
        id={id}
        disabled={disabled}
        render={
          <Button
            aria-busy={loading || undefined}
            className={cn(
              'w-full justify-between overflow-hidden px-2.5 font-normal',
              !selectedOption && 'text-muted-foreground',
              className,
            )}
            type="button"
            variant="outline"
          />
        }
      >
        <span className="min-w-0 flex-1 truncate text-left">
          {selectedOption?.label ?? (loading ? 'Loading options…' : placeholder)}
        </span>
        {loading ? <LoaderCircle className="size-3.5 animate-spin text-muted-foreground" /> : null}
      </ComboboxTrigger>
      <ComboboxContent
        className="flex h-[calc(var(--available-height)*0.6)] flex-col"
        container={portalContainer}
        initialFocus={false}
      >
        <ComboboxInput
          ref={searchInput}
          placeholder={searchPlaceholder}
          showTrigger={false}
          aria-label={searchPlaceholder}
        />
        <ComboboxEmpty>{emptyMessage}</ComboboxEmpty>
        <ComboboxList className="min-h-0 flex-1 max-h-none">
          {(option: SearchableComboboxOption) => (
            <ComboboxItem key={option.value} value={option} disabled={option.disabled}>
              <span className="truncate">{option.label}</span>
            </ComboboxItem>
          )}
        </ComboboxList>
      </ComboboxContent>
    </Combobox>
  );
}

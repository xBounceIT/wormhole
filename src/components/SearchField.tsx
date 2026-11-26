import { Search, X } from 'lucide-react';
import type { ComponentProps, ReactElement, ReactNode } from 'react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';

export function SearchField({
  className,
  value,
  onClear,
  clearLabel = 'Clear search',
  renderInput,
  ...props
}: Omit<ComponentProps<'input'>, 'value' | 'className'> & {
  className?: string;
  value?: string;
  onClear?: () => void;
  clearLabel?: string;
  renderInput?: (input: ReactElement) => ReactNode;
}) {
  const input = (
    <Input
      className={cn(
        'h-8 rounded-full border-border/70 bg-background/60 pr-8 pl-8 text-sm! font-normal! shadow-none transition-shadow placeholder:text-muted-foreground/80 dark:bg-input/40 dark:placeholder:text-foreground',
        onClear && '[&::-webkit-search-cancel-button]:hidden',
      )}
      value={value}
      {...props}
    />
  );

  return (
    <div className={cn('relative min-w-0', className)} data-slot="search-field">
      <Search
        aria-hidden="true"
        className="pointer-events-none absolute top-1/2 left-3 size-3.5 -translate-y-1/2 text-muted-foreground"
      />
      {renderInput ? renderInput(input) : input}
      {value && onClear ? (
        <Button
          aria-label={clearLabel}
          className="absolute top-1/2 right-1 size-6 -translate-y-1/2 rounded-full text-muted-foreground hover:text-foreground"
          disabled={props.disabled || props.readOnly}
          onClick={(event) => {
            onClear();
            event.currentTarget.parentElement
              ?.querySelector('input')
              ?.focus({ preventScroll: true });
          }}
          size="icon-xs"
          type="button"
          variant="ghost"
        >
          <X aria-hidden="true" className="size-3" />
        </Button>
      ) : null}
    </div>
  );
}

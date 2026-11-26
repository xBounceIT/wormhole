import type { ComponentProps, ComponentType } from 'react';

import { cn } from '@/lib/utils';

export function NavigationItem({
  icon: Icon,
  label,
  className,
  children,
  ...props
}: ComponentProps<'button'> & {
  icon: ComponentType<{ 'aria-hidden'?: boolean; className?: string }>;
  label: string;
}) {
  return (
    <button
      type="button"
      data-navigation-item=""
      className={cn(
        'relative flex h-8 w-full flex-none items-center justify-start gap-2.5 rounded-lg px-2.5 py-1.5 text-left !text-xs font-normal text-foreground/75 whitespace-nowrap outline-none hover:bg-foreground/[0.05] hover:text-foreground focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-1 focus-visible:outline-ring active:bg-foreground/[0.09] disabled:pointer-events-none disabled:opacity-50 dark:text-muted-foreground dark:hover:bg-foreground/[0.06] dark:hover:text-foreground dark:active:bg-foreground/[0.1]',
        className,
      )}
      {...props}
    >
      <Icon
        aria-hidden
        className="pointer-events-none size-4 shrink-0 opacity-80 dark:opacity-100"
      />
      <span className="truncate">{label}</span>
      {children}
    </button>
  );
}

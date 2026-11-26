import * as React from 'react';
import { Tooltip as TooltipPrimitive } from 'radix-ui';

import { cn } from '@/lib/utils';
import { tooltipDarkColor, tooltipLightColor } from '../../../electron/tree-tooltip';

// An absent provider gets a default portal. Native modal content opts into inline rendering.
const TooltipProviderContext = React.createContext<boolean | undefined>(undefined);
const TooltipFocusSuppressionContext = React.createContext<React.RefObject<boolean> | null>(null);

function TooltipProvider({
  delayDuration = 0,
  portalled = true,
  ...props
}: React.ComponentProps<typeof TooltipPrimitive.Provider> & { portalled?: boolean }) {
  return (
    <TooltipProviderContext.Provider value={portalled}>
      <TooltipPrimitive.Provider
        data-slot="tooltip-provider"
        delayDuration={delayDuration}
        {...props}
      />
    </TooltipProviderContext.Provider>
  );
}

function Tooltip({ ...props }: React.ComponentProps<typeof TooltipPrimitive.Root>) {
  return <TooltipPrimitive.Root data-slot="tooltip" {...props} />;
}

function useTooltipTriggerFocus(onFocus?: React.FocusEventHandler<HTMLButtonElement>) {
  const suppressFocus = React.useContext(TooltipFocusSuppressionContext);
  return (event: React.FocusEvent<HTMLButtonElement>) => {
    onFocus?.(event);
    if (suppressFocus?.current) event.preventDefault();
  };
}

function TooltipTrigger({
  onFocus,
  ...props
}: React.ComponentProps<typeof TooltipPrimitive.Trigger>) {
  const handleFocus = useTooltipTriggerFocus(onFocus);
  return <TooltipPrimitive.Trigger data-slot="tooltip-trigger" onFocus={handleFocus} {...props} />;
}

function TooltipContent({
  className,
  sideOffset = 0,
  children,
  style,
  ...props
}: React.ComponentProps<typeof TooltipPrimitive.Content>) {
  const portalled = React.useContext(TooltipProviderContext) ?? true;
  const content = (
    <TooltipPrimitive.Content
      data-slot="tooltip-content"
      sideOffset={sideOffset}
      className={cn(
        'z-50 inline-flex w-fit max-w-xs origin-(--radix-tooltip-content-transform-origin) items-center gap-1.5 rounded-md bg-(--tooltip-background) px-3 py-1.5 text-xs text-(color:--tooltip-foreground) [--tooltip-background:var(--tooltip-dark)] [--tooltip-foreground:var(--tooltip-light)] dark:[--tooltip-background:var(--tooltip-light)] dark:[--tooltip-foreground:var(--tooltip-dark)] has-data-[slot=kbd]:pr-1.5 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 **:data-[slot=kbd]:relative **:data-[slot=kbd]:isolate **:data-[slot=kbd]:z-50 **:data-[slot=kbd]:rounded-sm data-[state=delayed-open]:animate-in data-[state=delayed-open]:fade-in-0 data-[state=delayed-open]:zoom-in-95 data-open:animate-in data-open:fade-in-0 data-open:zoom-in-95 data-closed:animate-out data-closed:fade-out-0 data-closed:zoom-out-95',
        className,
      )}
      style={
        {
          '--tooltip-dark': tooltipDarkColor,
          '--tooltip-light': tooltipLightColor,
          ...style,
        } as React.CSSProperties
      }
      {...props}
    >
      {children}
      <TooltipPrimitive.Arrow className="z-50 size-2.5 translate-y-[calc(-50%_-_2px)] rotate-45 rounded-[2px] bg-(--tooltip-background) fill-[var(--tooltip-background)]" />
    </TooltipPrimitive.Content>
  );
  return portalled ? <TooltipPrimitive.Portal>{content}</TooltipPrimitive.Portal> : content;
}

function TextTooltip({ children, text }: { children: React.ReactElement; text?: string }) {
  const hasProvider = React.useContext(TooltipProviderContext) !== undefined;
  const handleFocus = useTooltipTriggerFocus();
  if (!text) return children;

  const tooltip = (
    <Tooltip disableHoverableContent>
      <TooltipPrimitive.Trigger asChild onFocus={handleFocus}>
        {children}
      </TooltipPrimitive.Trigger>
      <TooltipContent
        className="pointer-events-none wrap-anywhere whitespace-pre-line"
        side="top"
        sideOffset={4}
      >
        {text}
      </TooltipContent>
    </Tooltip>
  );
  return hasProvider ? tooltip : <TooltipProvider delayDuration={300}>{tooltip}</TooltipProvider>;
}

export {
  TextTooltip,
  Tooltip,
  TooltipContent,
  TooltipFocusSuppressionContext,
  TooltipProvider,
  TooltipTrigger,
};

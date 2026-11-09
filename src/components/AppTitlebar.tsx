import { SidebarPinButton } from './SidebarLayout';

export function AppTitlebar({ platform }: { platform?: string }) {
  return (
    <header
      className="relative flex h-12 shrink-0 items-center border-b border-border bg-background px-1 text-foreground data-[platform=darwin]:h-[76px] data-[platform=darwin]:pt-7 [-webkit-app-region:drag]"
      data-platform={platform}
    >
      {/* Reserve the top 28px for macOS traffic lights; keep the app toolbar below them. */}
      <div className="flex min-w-0 items-center gap-2.5 [-webkit-app-region:no-drag]">
        <SidebarPinButton />
        <span className="select-none text-sm font-semibold tracking-tight">Wormhole</span>
      </div>
    </header>
  );
}

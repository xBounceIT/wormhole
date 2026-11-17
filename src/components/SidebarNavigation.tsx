import { KeyRound, Network, Settings, Terminal } from 'lucide-react';

import { Button } from '@/components/ui/button';
import {
  SidebarGroup,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuItem,
} from '@/components/ui/sidebar';

export const sidebarNavigationItems = [
  { id: 'sessions', label: 'Sessions', hint: 'Open connections', icon: Terminal },
  { id: 'credentials', label: 'Credentials', hint: 'Stored access profiles', icon: KeyRound },
  { id: 'tunnels', label: 'Tunnels', hint: 'VPN and network routes', icon: Network },
  { id: 'settings', label: 'Settings', hint: 'Application preferences', icon: Settings },
] as const;

export type SidebarPage = (typeof sidebarNavigationItems)[number]['id'];

export function SidebarNavigation({
  activePage,
  onNavigate,
  sessionCount,
}: {
  activePage: SidebarPage;
  onNavigate: (page: SidebarPage) => void;
  sessionCount: number;
}) {
  return (
    <nav aria-label="Main navigation">
      <SidebarGroup className="p-0">
        <SidebarMenu>
          {sidebarNavigationItems.map(({ id, label, icon: Icon }) => (
            <SidebarMenuItem key={id}>
              <Button
                aria-current={activePage === id ? 'page' : undefined}
                aria-label={label}
                className="h-8 w-full justify-start gap-2 rounded-md border-0 px-2 !text-xs data-active:bg-sidebar-accent data-active:text-sidebar-accent-foreground"
                data-active={activePage === id}
                onClick={() => onNavigate(id)}
                size="sm"
                variant="ghost"
              >
                <Icon />
                <span className="truncate">{label}</span>
              </Button>
              {id === 'sessions' && sessionCount > 0 ? (
                <SidebarMenuBadge className="top-1/2 -translate-y-1/2">
                  {sessionCount}
                </SidebarMenuBadge>
              ) : null}
            </SidebarMenuItem>
          ))}
        </SidebarMenu>
      </SidebarGroup>
    </nav>
  );
}

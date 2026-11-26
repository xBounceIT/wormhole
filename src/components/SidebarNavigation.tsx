import { KeyRound, Network, Settings, Terminal } from 'lucide-react';

import { NavigationItem } from '@/components/ui/navigation-item';
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
] as const;

export type SidebarPage = (typeof sidebarNavigationItems)[number]['id'];

export function SidebarNavigation({
  activePage,
  onNavigate,
  onOpenSettings,
  sessionCount,
  settingsOpen = false,
}: {
  activePage: SidebarPage;
  onNavigate: (page: SidebarPage) => void;
  onOpenSettings: () => void;
  sessionCount: number;
  settingsOpen?: boolean;
}) {
  return (
    <nav aria-label="Main navigation">
      <SidebarGroup className="p-0">
        <SidebarMenu className="gap-0.5">
          {sidebarNavigationItems.map(({ id, label, icon: Icon }) => (
            <SidebarMenuItem key={id}>
              <NavigationItem
                aria-current={activePage === id ? 'page' : undefined}
                aria-label={label}
                data-active={activePage === id}
                icon={Icon}
                label={label}
                onClick={() => {
                  if (id !== activePage) onNavigate(id);
                }}
              />
              {id === 'sessions' && sessionCount > 0 ? (
                <SidebarMenuBadge className="top-1/2 -translate-y-1/2">
                  {sessionCount}
                </SidebarMenuBadge>
              ) : null}
            </SidebarMenuItem>
          ))}
          <SidebarMenuItem>
            <NavigationItem
              aria-expanded={settingsOpen}
              aria-haspopup="dialog"
              aria-label="Settings"
              data-active={settingsOpen}
              icon={Settings}
              label="Settings"
              onClick={onOpenSettings}
            />
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarGroup>
    </nav>
  );
}

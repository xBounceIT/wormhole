import connectionWorkspace from './media/connection-workspace.webp';
import browserVpnReconnect from './media/browser-vpn-reconnect.webp';
import settings from './media/settings.webp';
import oledTheme from './media/oled-theme.webp';
import workspaceRedesign from './media/workspace-redesign.gif';
import workspaceRedesignPoster from './media/workspace-redesign.png';
import sharedCredentialSlot from './media/shared-credential-slot.png';

type ChangelogMedia =
  | { kind: 'image'; src: string; alt: string }
  | { kind: 'gif'; src: string; poster: string; alt: string }
  | { kind: 'video'; src: string; poster?: string; label: string; captions?: string };

type ChangelogSlide = {
  title: string;
  subtitle: string;
  media: ChangelogMedia;
};

export type VisualChangelogRelease = {
  version: `${number}.${number}.0`;
  slides: readonly [ChangelogSlide, ...ChangelogSlide[]];
};

export const latestRelease: VisualChangelogRelease = {
  version: '2.5.0',
  slides: [
    {
      title: 'A new look for Wormhole',
      subtitle:
        'The title bar and sidebar now frame the workspace together. A rounded tab marks the active session, and the lightning bolt beside Connections opens Quick Connect.',
      media: {
        kind: 'gif',
        src: workspaceRedesign,
        poster: workspaceRedesignPoster,
        alt: 'The same SSH session in 2.4.4 and 2.5.0. The redesigned workspace has a continuous title bar and sidebar, a rounded active tab and a borderless terminal pane.',
      },
    },
    {
      title: 'Find an open connection by name',
      subtitle:
        'Click the arrow beside the session tabs and type a connection name. Choose a result to bring its tab into view.',
      media: {
        kind: 'image',
        src: connectionWorkspace,
        alt: 'The open-tab search shows two matches for “console”: Staging console and Gateway console.',
      },
    },
    {
      title: 'Reconnect the browser VPN and keep your tabs',
      subtitle:
        'If the tunnel drops, click the red reconnect button in the browser. Your tabs stay open, and their traffic stays blocked until the VPN is back.',
      media: {
        kind: 'image',
        src: browserVpnReconnect,
        alt: 'The Gateway, Monitoring and Runbook tabs stay open as the red reconnect button changes to a green check for the active WireGuard tunnel.',
      },
    },
    {
      title: 'Change settings without leaving your workspace',
      subtitle:
        'Open Settings over your connections. Choose a category on the left or use the search box to find a preference.',
      media: {
        kind: 'image',
        src: settings,
        alt: 'Settings opens on General with all eight categories visible on the left and preferences for appearance, tabs and the application on the right.',
      },
    },
    {
      title: 'Set a shared credential for a slot',
      subtitle:
        'Choose a slot by name in the connection editor. In Workspace administration, set the credential it uses when someone has no personal assignment.',
      media: {
        kind: 'image',
        src: sharedCredentialSlot,
        alt: 'The Operations remote desktop slot shows Operations RDP account as the selected credential, with Set shared default ready to confirm.',
      },
    },
    {
      title: 'Switch to the OLED theme',
      subtitle:
        'Open Settings, choose General and select OLED under Appearance for a darker sidebar and connection canvas.',
      media: {
        kind: 'image',
        src: oledTheme,
        alt: 'The same workspace in Dark and OLED, with a near-black sidebar and darker tunnel cards in OLED.',
      },
    },
  ],
};

export function getVisualChangelog(currentVersion: string): VisualChangelogRelease | null {
  return currentVersion === latestRelease.version ? latestRelease : null;
}

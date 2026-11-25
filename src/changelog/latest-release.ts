import vpnTunnels from './media/vpn-tunnels.webp';
import settings from './media/settings.webp';

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
      title: 'Find the right VPN tunnel faster',
      subtitle: 'Search your tunnels or filter by provider. Test or edit a tunnel from its card.',
      media: {
        kind: 'image',
        src: vpnTunnels,
        alt: 'VPN tunnels page with provider filters, search and tunnel cards.',
      },
    },
    {
      title: 'Change settings without leaving your workspace',
      subtitle:
        'Search and browse settings in a dialog over your connections, then pick up where you left off.',
      media: {
        kind: 'image',
        src: settings,
        alt: 'Settings dialog with a searchable list of categories beside the selected settings.',
      },
    },
  ],
};

export function getVisualChangelog(currentVersion: string): VisualChangelogRelease | null {
  return currentVersion === latestRelease.version ? latestRelease : null;
}

import { createLucideIcon } from 'lucide-react';

export const SftpConnectionIcon = createLucideIcon('folder-network', [
  [
    'path',
    {
      d: 'M20 14H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4l2 3h10a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2Z',
      key: 'folder',
    },
  ],
  ['path', { d: 'M12 14v3M5 19v-2h14v2', key: 'network' }],
  ['rect', { x: '2', y: '19', width: '6', height: '3', rx: '1', key: 'left-node' }],
  ['rect', { x: '16', y: '19', width: '6', height: '3', rx: '1', key: 'right-node' }],
]);

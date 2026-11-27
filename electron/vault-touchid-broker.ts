import { spawn, type ChildProcess, type SpawnOptions } from 'node:child_process';
import { Socket } from 'node:net';

type SpawnBroker = (executable: string, args: string[], options: SpawnOptions) => ChildProcess;

export function launchVaultTouchIDBroker(executable: string, start: SpawnBroker = spawn) {
  try {
    // Unix libuv creates an anonymous, duplex socket pair for this extra
    // descriptor. Pass its other end to the vault as fd 3, then close it here.
    const broker = start(executable, ['--operation', 'vault-touch-id-broker'], {
      stdio: ['ignore', 'ignore', 'ignore', 'pipe'],
      windowsHide: true,
    });
    const channel = broker.stdio[3];
    broker.on('error', () => channel?.destroy());
    broker.unref();
    if (!(channel instanceof Socket) || broker.pid === undefined) {
      channel?.destroy();
      return undefined;
    }
    channel.on('error', () => channel.destroy());
    channel.pause();
    return channel;
  } catch {
    return undefined;
  }
}

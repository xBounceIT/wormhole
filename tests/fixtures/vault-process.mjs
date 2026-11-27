import { createInterface } from 'node:readline';

const status = {
  formatVersion: 1,
  stage: 'foundation',
  protectionAvailable: false,
  sharedWorkspaceAvailable: false,
  unlocked: false,
  lockedMemory: false,
};
createInterface({ input: process.stdin })
  .on('line', (line) => {
    const request = JSON.parse(line);
    if (request.operation === 'lock') process.exit(0);
    const result =
      request.operation === 'status'
        ? status
        : request.operation === 'heartbeat'
          ? { alive: true }
          : { slots: null };
    process.stdout.write(JSON.stringify({ version: 1, id: request.id, result }) + '\n');
  })
  .on('close', () => process.exit(0));

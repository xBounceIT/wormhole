import assert from 'node:assert/strict';
import test from 'node:test';
import {
  BitwardenStorageCheckpoint,
  synchronizeBitwardenStorage,
  type BitwardenBrowserStorageSnapshot,
} from '../electron/bitwarden-storage-sync.ts';

const snapshot = (
  overrides: Partial<BitwardenBrowserStorageSnapshot> = {},
): BitwardenBrowserStorageSnapshot => ({
  localJson: '{"account":"saved"}',
  sessionJson: '{}',
  revision: 4,
  profileRevision: 4,
  restore: false,
  durable: true,
  ...overrides,
});

test('restart restores the remembered account even when a matching marker outlives Chromium storage', async () => {
  let live = { localJson: '{"defaults":true}', sessionJson: '{"runtime":"new-background"}' };
  let committed = false;
  await synchronizeBitwardenStorage(
    {
      read: async () => snapshot(), // matching revision must not suppress initial hydration
      capture: async () => live,
      restore: async (saved, expected) => {
        assert.equal(committed, false);
        assert.deepEqual(expected, live);
        assert.equal(saved.localJson, snapshot().localJson);
        assert.equal(
          saved.sessionJson,
          live.sessionJson,
          'cold startup must retain runtime bookkeeping',
        );
        live = saved;
      },
      flush: async () => {},
      commit: async (captured, revision) => {
        committed = true;
        assert.equal(captured.localJson, snapshot().localJson);
        assert.equal(revision, 4);
        return snapshot({ ...captured });
      },
    },
    true,
  );
  assert.equal(committed, true);
});

test('a newer external marker cannot promote missing Chromium state over a recovered backup', async () => {
  for (const nativeRevision of [undefined, 2]) {
    let live = { localJson: '{"defaults":true}', sessionJson: '{}', nativeRevision };
    await synchronizeBitwardenStorage(
      {
        read: async () => snapshot({ revision: 3, profileRevision: 5 }),
        capture: async () => live,
        restore: async (saved) => {
          live = { ...live, ...saved };
        },
        flush: async () => {},
        commit: async (captured, revision) => {
          assert.equal(captured.localJson, snapshot().localJson);
          assert.equal(revision, 3);
          return snapshot({ ...captured });
        },
      },
      true,
    );
  }
});

test('restart preserves a native token refresh or logout newer than the last protected checkpoint', async () => {
  for (const localJson of ['{"account":"new-login","token":"new"}', '{}']) {
    const live = { localJson, sessionJson: '{}', nativeRevision: 4 };
    await synchronizeBitwardenStorage(
      {
        read: async () => snapshot(),
        capture: async () => live,
        flush: async () => {},
        restore: async () =>
          assert.fail('native changes after the matching checkpoint must survive restart'),
        commit: async (captured, revision) => {
          assert.equal(captured.localJson, localJson);
          assert.equal(revision, 4);
          return snapshot({ ...captured, revision: 5 });
        },
        markRevision: async (revision) => {
          assert.equal(revision, 5);
        },
      },
      true,
    );
  }
});

test('a new profile can inherit a live session while a newer native marker survives backup recovery', async () => {
  let restores = 0;
  await synchronizeBitwardenStorage(
    {
      read: async () => snapshot({ sessionJson: '{"session":"live"}' }),
      capture: async () => snapshot(),
      flush: async () => {},
      restore: async (saved) => {
        restores++;
        assert.equal(saved.sessionJson, '{"session":"live"}');
      },
      commit: async () => snapshot(),
    },
    true,
  );
  assert.equal(restores, 1);
  await synchronizeBitwardenStorage(
    {
      read: async () => snapshot(),
      capture: async () => snapshot({ nativeRevision: 8 }),
      flush: async () => {},
      restore: async () => assert.fail('native revision is newer than the recovery copy'),
      commit: async (_saved, revision) => {
        assert.equal(revision, 8);
        return snapshot();
      },
    },
    true,
  );
});

test('first install and native profiles newer than a recovered backup preserve their state', async () => {
  for (const shared of [
    snapshot({ revision: 0, profileRevision: 0 }),
    snapshot({ revision: 3, profileRevision: 5 }),
  ]) {
    await synchronizeBitwardenStorage(
      {
        read: async () => shared,
        capture: async () => snapshot({ nativeRevision: shared.profileRevision }),
        flush: async () => {},
        restore: async () => assert.fail('newer profile must not be rolled back'),
        commit: async (_value, revision) => {
          assert.equal(revision, shared.profileRevision);
          return snapshot();
        },
      },
      true,
    );
  }
});

test('initial hydration failures cannot promote empty startup state into the recovery snapshot', async () => {
  await assert.rejects(
    synchronizeBitwardenStorage(
      {
        read: async () => snapshot(),
        capture: async () => ({ localJson: '{}', sessionJson: '{}' }),
        restore: async () => {
          throw new Error('restore unavailable');
        },
        flush: async () => assert.fail(),
        commit: async () => {
          assert.fail('empty startup must never commit');
        },
      },
      true,
    ),
    /restore unavailable/,
  );
});

test('unreadable protected storage cannot be replaced by an empty startup snapshot', async () => {
  await assert.rejects(
    synchronizeBitwardenStorage(
      {
        read: async () => snapshot({ revision: 0, profileRevision: 7, durable: false }),
        capture: async () => {
          assert.fail('must wait for native protection to recover');
        },
        restore: async () => assert.fail(),
        flush: async () => assert.fail(),
        commit: async () => {
          assert.fail('must never promote empty state over unreadable data');
        },
      },
      true,
    ),
    /temporarily unavailable/,
  );
});

test('a failed save after initial hydration does not allow a retry to undo a subsequent login', async () => {
  let initialized = false;
  let live = snapshot({ localJson: '{}' });
  let fail = true;
  const storage = {
    read: async () => snapshot(),
    capture: async () => live,
    restore: async (saved: { localJson: string; sessionJson: string }) => {
      assert.equal(initialized, false);
      live = snapshot({ ...saved });
    },
    hydrated: () => {
      initialized = true;
    },
    flush: async () => {},
    commit: async (captured: { localJson: string; sessionJson: string }) =>
      snapshot({ ...captured, durable: !fail }),
  };
  await assert.rejects(synchronizeBitwardenStorage(storage, !initialized), /saved securely/);
  live = snapshot({ localJson: '{"account":"new-login"}' });
  fail = false;
  await synchronizeBitwardenStorage(storage, !initialized);
  assert.equal(live.localJson, '{"account":"new-login"}');
});

test('a newly signed-in stale profile is captured before shared storage can replace it', async () => {
  const events: string[] = [];
  const live = { localJson: '{"account":"new-login"}', sessionJson: '{"token":"live"}' };
  await synchronizeBitwardenStorage({
    read: async () => snapshot({ restore: true, profileRevision: 2 }),
    capture: async () => {
      events.push('capture');
      return live;
    },
    flush: async () => {
      events.push('flush');
    },
    commit: async (captured, revision) => {
      events.push('commit');
      assert.deepEqual(captured, live);
      assert.equal(revision, 2);
      return snapshot({ ...live, revision: 5 });
    },
    restore: async () => {
      assert.fail('new login must never be overwritten before capture');
    },
  });
  assert.deepEqual(events, ['capture', 'flush', 'commit', 'flush']);
});

test('merged storage is restored conditionally and recaptured before being acknowledged', async () => {
  let live = snapshot({ localJson: '{"account":"new-login"}' });
  const merged = snapshot({
    localJson: '{"account":"new-login","other":"new"}',
    revision: 5,
    restore: true,
  });
  const revisions: number[] = [];
  await synchronizeBitwardenStorage({
    read: async () => snapshot(),
    capture: async () => live,
    flush: async () => {},
    commit: async (captured, revision) => {
      revisions.push(revision);
      return revisions.length === 1 ? merged : snapshot({ ...captured, revision: 6 });
    },
    restore: async (accepted, expected) => {
      assert.deepEqual(expected, live);
      assert.equal(accepted, merged);
      live = snapshot({ localJson: '{"account":"newer-login","other":"new"}' });
    },
  });
  assert.deepEqual(revisions, [4, 5]);
});

test('unpersisted snapshots are reported as failures so checkpoints retry', async () => {
  await assert.rejects(
    synchronizeBitwardenStorage({
      read: async () => snapshot(),
      capture: async () => snapshot(),
      flush: async () => {},
      commit: async () => snapshot({ durable: false }),
      restore: async () => assert.fail(),
    }),
    /saved securely/,
  );
});

test('continuous mutations have a bounded retry budget', async () => {
  let captures = 0;
  await assert.rejects(
    synchronizeBitwardenStorage({
      read: async () => snapshot(),
      capture: async () => {
        captures++;
        return snapshot();
      },
      flush: async () => {},
      commit: async () => snapshot({ restore: true }),
      restore: async () => {},
    }),
    /retry required/,
  );
  assert.equal(captures, 3);
});

test('capture and flush failures cannot replace the saved snapshot', async () => {
  for (const failure of ['capture', 'flush']) {
    await assert.rejects(
      synchronizeBitwardenStorage({
        read: async () => snapshot(),
        capture: async () => {
          if (failure === 'capture') throw new Error(failure);
          return snapshot();
        },
        flush: async () => {
          if (failure === 'flush') throw new Error(failure);
        },
        commit: async () => {
          assert.fail('failed read/flush must not commit');
        },
        restore: async () => assert.fail(),
      }),
      new RegExp(failure),
    );
  }
});

test('checkpoint coalesces overlapping saves, skips unchanged state and retains in-flight edits', async () => {
  const checkpoint = new BitwardenStorageCheckpoint();
  let revision = 0;
  let saves = 0;
  let finish!: () => void;
  const read = async () => revision;
  const first = checkpoint.run(read, async () => {
    saves++;
    await new Promise<void>((resolve) => {
      finish = resolve;
    });
  });
  assert.equal(checkpoint.isPending, true);
  assert.equal(
    checkpoint.run(read, async () => assert.fail()),
    first,
  );
  await new Promise<void>((resolve) => setImmediate(resolve));
  revision++;
  finish();
  await first;
  assert.equal(checkpoint.isPending, false);
  await checkpoint.run(read, async () => {
    saves++;
  });
  await checkpoint.run(read, async () => assert.fail('unchanged storage was saved again'));
  assert.equal(saves, 2);
});

test('checkpoint retries failed readiness and failed secure persistence', async () => {
  const checkpoint = new BitwardenStorageCheckpoint();
  await assert.rejects(
    checkpoint.run(
      async () => {
        throw new Error('not ready');
      },
      async () => assert.fail(),
    ),
    /not ready/,
  );
  await assert.rejects(
    checkpoint.run(
      async () => 0,
      async () => {
        throw new Error('disk failure');
      },
    ),
    /disk failure/,
  );
  let saves = 0;
  await checkpoint.run(
    async () => 0,
    async () => {
      saves++;
    },
  );
  assert.equal(saves, 1);
});

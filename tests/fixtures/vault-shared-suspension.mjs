import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { setTimeout } from 'node:timers/promises';

async function groupRevision(ports, groupId) {
  const groups = await ports.groups({ action: 'list' });
  assert.equal(groups.status, 'ready');
  return groups.page.entries.find((entry) => entry.id === groupId).revision;
}

export async function prepareGroup(ports) {
  const groupId = randomUUID();
  const revision = () => groupRevision(ports, groupId);
  const change = async (request) =>
    assert.equal((await ports.groups({ groupId, ...request })).status, 'changed');
  await change({ action: 'create', name: 'Suspension recipients' });
  for (const login of ['first-admin', 'recovered-admin']) {
    await change({ action: 'add-member', login, revision: await revision() });
  }
  const key = { groupId, revision: await revision() };
  const recipients = await ports.groupKey(key);
  assert.equal(recipients.status, 'review');
  assert.deepEqual(recipients.preview.members.map((m) => m.login).sort(), [
    'first-admin',
    'recovered-admin',
  ]);
  assert.equal(
    (await ports.groupKey({ ...key, review: recipients.preview.review })).status,
    'issued',
  );
  const page = await ports.nodeGrants.catalog({ after: '', epoch: '0', changeSeq: '0', limit: 32 });
  const folder = page.nodes.find((node) => node.name === 'Shared grant folder');
  assert.ok(folder?.grantBoundary && folder.grantRevision);
  const grant = {
    nodeId: folder.id,
    nodeRevision: folder.grantRevision,
    boundaryId: folder.grantBoundary,
    groupId,
    groupRevision: await revision(),
    mask: 3,
  };
  const sharing = await ports.nodeGrants.boundary(grant);
  assert.equal(sharing.status, 'review');
  assert.equal(
    (await ports.nodeGrants.boundary({ ...grant, review: sharing.preview.review })).status,
    'changed',
  );

  const subject = recipients.preview.members.find(
    (member) => member.login === 'recovered-admin',
  ).id;
  return { subject, groupId, boundaryId: folder.grantBoundary };
}

export async function suspendAccount(ports, { subject }) {
  const selection = { action: 'disable-account', targetId: subject };
  const review = await ports.access(selection);
  assert.equal(review.status, 'review');
  const stale = { ...selection, revision: String(BigInt(review.review.revision) + 1n) };
  assert.equal((await ports.access(stale)).status, 'stale');
  const current = await ports.access(selection);
  assert.equal(current.status, 'review');
  assert.equal(current.review.revision, review.review.revision);
  const confirmed = { ...selection, revision: review.review.revision };
  assert.equal((await ports.access(confirmed)).status, 'changed');
  assert.equal((await ports.access(confirmed)).status, 'unchanged');
}

export async function waitForRotation(ports, { subject, groupId, boundaryId }, expected) {
  const deadline = Date.now() + 20_000;
  let last;
  do {
    const groups = await ports.suspension({ accountId: subject, kind: 'groups' });
    const roots = await ports.suspension({ accountId: subject, kind: 'roots' });
    assert.equal(groups.status, 'ready');
    assert.equal(roots.status, 'ready');
    const group = groups.page.entries.find((entry) => entry.id === groupId);
    const captured = roots.page.entries.filter((entry) => entry.boundaryId === boundaryId);
    assert.ok(group && captured.length > 0, 'suspension must retain the group and its boundary');
    last = { group: group.status, roots: captured.map((entry) => entry.status) };
    if ((expected === 'queued' || expected === 'needs-removal') && group.status === expected) {
      if (expected === 'queued') assert.ok(group.jobId);
      else assert.equal(group.jobId, undefined);
      assert.deepEqual(captured.map((entry) => entry.kind).sort(), ['secret', 'view']);
      assert.ok(captured.every((entry) => entry.status === 'active'));
      return;
    }
    if (
      expected === 'resolved' &&
      group.status === 'resolved' &&
      captured.every((entry) => entry.status === 'retired')
    ) {
      const members = await ports.groups({
        action: 'members',
        groupId,
        revision: await groupRevision(ports, groupId),
      });
      assert.equal(members.status, 'ready');
      assert.deepEqual(
        members.page.entries.map((m) => m.login),
        ['first-admin'],
      );
      return;
    }
    await setTimeout(150);
  } while (Date.now() < deadline);
  assert.fail('Suspended group rotation did not complete: ' + JSON.stringify(last));
}

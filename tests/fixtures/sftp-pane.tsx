// Real pane, hooks, drag events and generated application CSS; only presentation wrappers are stubbed.
declare const React: typeof import('react');
declare const createRoot: typeof import('react-dom/client').createRoot;
declare const assert: typeof import('node:assert/strict');
declare function SftpFilePane(props: Record<string, unknown>): import('react').ReactElement;
declare const sftpDragDataType: string;

async function runSftpPaneTests() {
  const root = createRoot(document.getElementById('root'));
  const transfers = [];
  const state = (path: string) => ({
    status: 'ready',
    path,
    truncated: false,
    entries: [
      { name: 'folder', fullPath: `${path}/folder`, isDirectory: true, size: 0 },
      { name: 'file.txt', fullPath: `${path}/file.txt`, isDirectory: false, size: 12 },
    ],
  });
  await React.act(async () => {
    root.render(
      <React.StrictMode>
        <div className="flex h-[600px] gap-4 overflow-hidden">
          {(['local', 'remote'] as const).map((pane) => (
            <SftpFilePane
              key={pane}
              pane={pane}
              state={state(`/${pane}`)}
              onNavigate={() => {}}
              onRefresh={() => {}}
              onOperation={() => {}}
              onTransfer={(payload, destination) => transfers.push({ pane, payload, destination })}
            />
          ))}
        </div>
      </React.StrictMode>,
    );
  });
  const panes = [...document.querySelectorAll('section')];
  const overlay = (pane: Element) => pane.querySelector(':scope > [aria-hidden="true"]');
  const data = new DataTransfer();
  const drag = async (
    target: EventTarget,
    type: string,
    relatedTarget: EventTarget = null,
    transfer = data,
  ) => {
    const event = new DragEvent(type, {
      bubbles: true,
      cancelable: true,
      relatedTarget,
      dataTransfer: transfer,
    });
    await React.act(async () => {
      target.dispatchEvent(event);
    });
    return event;
  };
  const localFile = panes[0].querySelectorAll('[role="option"]')[1];
  await drag(localFile, 'dragstart');
  assert.equal(JSON.parse(data.getData(sftpDragDataType)).items[0].sourcePath, '/local/file.txt');
  for (const pane of panes) {
    const [folder, file] = pane.querySelectorAll('[role="option"]');
    const title = pane.querySelector('span');
    const bounds = pane.getBoundingClientRect().toJSON();
    const radius = getComputedStyle(pane).borderRadius;
    assert.equal((await drag(title, 'dragenter')).defaultPrevented, true);
    const border = overlay(pane);
    assert.ok(border);
    assert.deepEqual(pane.getBoundingClientRect().toJSON(), bounds, 'hover must not shift layout');
    assert.equal(getComputedStyle(pane).borderRadius, radius, 'clipping must stay stable');
    const style = getComputedStyle(border);
    assert.equal(style.pointerEvents, 'none', 'decoration must not intercept drag events');
    for (const edge of ['Top', 'Right', 'Bottom', 'Left']) {
      assert.equal(style[`border${edge}Width`], '1px');
      assert.equal(style[`border${edge}Style`], 'solid');
    }
    const borderBounds = border.getBoundingClientRect();
    for (const edge of ['top', 'right', 'bottom', 'left']) {
      assert.equal(
        borderBounds[edge],
        bounds[edge],
        'all borders must fit inside the clipped pane',
      );
    }
    assert.equal(style.borderRadius, radius);
    // Chromium enters the new descendant before leaving the old one. Observe between events.
    await drag(file.querySelector('span'), 'dragenter', title);
    await drag(title, 'dragleave', file.querySelector('span'));
    assert.equal(overlay(pane), border, 'moving across children must preserve the same overlay');
    await drag(file, 'dragover');
    assert.equal(overlay(pane), border);
    await drag(folder, 'dragenter', file);
    await drag(file, 'dragleave', folder);
    assert.equal(overlay(pane), null, 'directory is the destination');
    assert.ok(folder.classList.contains('ring-primary'));
    await drag(folder.querySelector('i'), 'dragenter', folder);
    await drag(folder, 'dragleave', folder.querySelector('i'));
    assert.ok(
      folder.classList.contains('ring-primary'),
      'folder feedback survives nested transitions',
    );
    await drag(folder, 'dragover');
    await drag(folder, 'drop');
    assert.equal(
      transfers.at(-1).destination,
      `${pane === panes[0] ? '/local' : '/remote'}/folder`,
    );
    assert.equal(folder.classList.contains('ring-primary'), false);
    await drag(file, 'dragenter');
    await drag(file, 'drop');
    assert.equal(transfers.at(-1).destination, pane === panes[0] ? '/local' : '/remote');
    assert.equal(overlay(pane), null);
    await drag(title, 'dragover');
    await drag(title, 'dragleave', document.body);
    assert.equal(overlay(pane), null, 'leaving pane clears feedback');
    await drag(title, 'dragenter');
    await drag(title, 'dragleave');
    assert.equal(overlay(pane), null, 'leaving window clears feedback');
  }
  await drag(panes[0], 'dragenter');
  await drag(panes[1], 'dragenter', panes[0]);
  await drag(panes[0], 'dragleave', panes[1]);
  assert.equal(overlay(panes[0]), null);
  assert.ok(overlay(panes[1]));
  await drag(localFile, 'dragend');
  assert.equal(overlay(panes[1]), null, 'cancel at source must clear the destination pane');
  const external = new DataTransfer();
  external.items.add(new window.File(['test'], 'external.txt'));
  await drag(panes[1], 'dragenter', null, external);
  assert.ok(overlay(panes[1]), 'external files receive feedback');
  await drag(document.body, 'drop', null, external);
  assert.equal(overlay(panes[1]), null);
  const unrelated = new DataTransfer();
  unrelated.setData('text/plain', 'text');
  assert.equal((await drag(panes[1], 'dragenter', null, unrelated)).defaultPrevented, false);
  assert.equal(overlay(panes[1]), null);
  const malformed = new DataTransfer();
  malformed.setData(sftpDragDataType, '{');
  await drag(panes[1], 'dragenter', null, malformed);
  const count = transfers.length;
  await drag(panes[1], 'drop', null, malformed);
  assert.equal(transfers.length, count);
  assert.equal(overlay(panes[1]), null);
  await React.act(async () => root.unmount());
}

runSftpPaneTests();

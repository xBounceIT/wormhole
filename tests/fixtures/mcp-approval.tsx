// Executed with the production dialog, React, Radix and Chromium by mcp-approval.test.ts.
declare const React: typeof import('react');
declare const createRoot: typeof import('react-dom/client').createRoot;
declare const assert: typeof import('node:assert/strict');
declare function McpApprovalDialog(props: Record<string, unknown>): import('react').ReactElement;

async function runMcpApprovalDialogTests() {
  const root = createRoot(document.getElementById('root'));
  const decisions: boolean[] = [];
  const approval = {
    approvalKind: 'session_control',
    requestId: 'request',
    sessionId: 'session',
    title: 'Production SSH',
    username: 'alice',
    host: 'example.test',
    port: 22,
    tool: 'run_command',
  };
  const mount = async (overrides = {}, visible = true) => {
    await React.act(async () => {
      root.render(
        <McpApprovalDialog
          approval={visible ? { ...approval, ...overrides } : undefined}
          onDecision={(approved: boolean) => decisions.push(approved)}
        />,
      );
    });
  };
  const dialog = () => document.querySelector('[role="dialog"]');
  const preview = () => document.querySelector('pre');
  const press = async (label: string) => {
    const button = [...dialog().querySelectorAll('button')].find(
      (item) => item.textContent === label,
    );
    assert.ok(button);
    await React.act(async () => button.click());
  };
  const content =
    'printf "<script>window.injected = true</script>"\n' + 'long command '.repeat(4000);
  await mount({ executionPreview: { content, truncated: true, redacted: true } });
  assert.equal(preview().textContent, content);
  assert.equal(preview().children.length, 0);
  assert.equal(window.injected, undefined);
  assert.match(dialog().textContent, /Preview truncated/);
  assert.match(dialog().textContent, /Detected sensitive values are hidden/);
  assert.match(dialog().textContent, /rest of the session's lifetime/);
  assert.match(dialog().textContent, /alice@example.test:22/);
  assert.equal(preview().getAttribute('aria-label'), 'Requested execution');
  assert.equal(preview().getAttribute('dir'), 'ltr');
  assert.equal(getComputedStyle(preview()).userSelect, 'text');
  assert.ok(preview().scrollHeight > preview().clientHeight);
  assert.ok(preview().getBoundingClientRect().height <= 256);
  const viewportMargin = 2 * Number.parseFloat(getComputedStyle(document.documentElement).fontSize);
  assert.ok(
    dialog().getBoundingClientRect().height <= window.innerHeight - viewportMargin + 1,
    JSON.stringify({
      height: dialog().getBoundingClientRect().height,
      viewport: window.innerHeight,
      margin: viewportMargin,
      maxHeight: getComputedStyle(dialog()).maxHeight,
    }),
  );
  assert.ok(dialog().getBoundingClientRect().width > 448);
  preview().focus();
  assert.equal(document.activeElement, preview());
  const range = document.createRange();
  range.selectNodeContents(preview());
  window.getSelection().removeAllRanges();
  window.getSelection().addRange(range);
  assert.equal(window.getSelection().toString(), content);
  await press('Allow');
  await press('Deny');
  await press('Close');
  assert.deepEqual(decisions, [true, false, false]);

  preview().scrollTop = preview().scrollHeight;
  assert.ok(preview().scrollTop > 0);
  const nextContent = `SECOND REQUEST\n${content}`;
  await mount({
    requestId: 'next-request',
    executionPreview: { content: nextContent, truncated: true, redacted: false },
  });
  assert.equal(preview().textContent, nextContent);
  assert.equal(
    preview().scrollTop,
    0,
    'the next approval must start at the beginning of its content',
  );

  const longRequest = {
    title: 'node '.repeat(390),
    executionPreview: { content, truncated: true, redacted: false },
  };
  await mount({ ...longRequest, requestId: 'long-request' });
  dialog().scrollTop = dialog().scrollHeight;
  preview().scrollTop = preview().scrollHeight;
  assert.ok(dialog().scrollTop > 0);
  assert.ok(preview().scrollTop > 0);
  await mount({ ...longRequest, requestId: 'long-request' });
  assert.ok(dialog().scrollTop > 0, 'rerendering the same approval must preserve reading position');
  assert.ok(preview().scrollTop > 0);
  await mount({ ...longRequest, requestId: 'next-long-request' });
  assert.equal(dialog().scrollTop, 0);
  assert.equal(preview().scrollTop, 0);

  for (const [tool, request] of [
    ['run_command', { command: 'ls -la', timeoutSeconds: 30 }],
    ['send_text', { text: 'echo hello\r\n\u0003' }],
    ['read_terminal', { maxBytes: 4096 }],
  ]) {
    const content = JSON.stringify(request, null, 2);
    await mount({ tool, executionPreview: { content, truncated: false, redacted: false } });
    assert.equal(preview().textContent, content);
    assert.match(dialog().textContent, new RegExp(tool));
    assert.doesNotMatch(dialog().textContent, /Preview truncated|Detected sensitive/);
  }
  await mount({
    approvalKind: 'open_connection',
    tool: 'open_connection',
    protocol: 'https',
    port: 443,
    path: '/console',
    connectionFolder: 'Servers',
    executionPreview: { content: '{"connectionId":"web-node"}', truncated: false, redacted: false },
  });
  assert.match(dialog().textContent, /HTTPS · example.test:443\/console/);
  assert.match(dialog().textContent, /Servers \/ Production SSH/);
  assert.match(
    dialog().textContent,
    /Every MCP request to open a connection requires a new approval/,
  );
  assert.doesNotMatch(dialog().textContent, /rest of the session's lifetime/);
  assert.equal(preview().textContent, '{"connectionId":"web-node"}');
  await mount();
  assert.equal(preview(), null);
  assert.match(dialog().textContent, /Execution details are unavailable/);
  await mount({}, false);
  // Radix can retain the node until its exit animation ends in a hidden window.
  if (dialog()) {
    assert.equal(dialog().getAttribute('data-state'), 'closed');
    assert.equal(getComputedStyle(dialog()).pointerEvents, 'none');
  }
  await React.act(async () => root.unmount());
}

runMcpApprovalDialogTests();

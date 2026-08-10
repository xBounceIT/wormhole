export type McpClient = 'claude-code' | 'claude-desktop' | 'codex';

export function buildMcpConfig(
  client: McpClient,
  endpoint: string,
  token: string,
  platform: string,
): string {
  if (client === 'codex') {
    const escapeToml = (value: string) => value.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
    return (
      '[mcp_servers.wormhole]\n' +
      `url = "${escapeToml(endpoint)}"\n` +
      `http_headers = { Authorization = "${escapeToml(`Bearer ${token}`)}" }\n`
    );
  }

  if (client === 'claude-desktop') {
    const remoteArguments = [
      'mcp-remote@latest',
      endpoint,
      '--header',
      'Authorization:${WORMHOLE_MCP_TOKEN}',
    ];
    return JSON.stringify(
      {
        mcpServers: {
          wormhole: {
            command: platform === 'win32' ? 'cmd' : 'npx',
            args: platform === 'win32' ? ['/c', 'npx', ...remoteArguments] : remoteArguments,
            env: { WORMHOLE_MCP_TOKEN: `Bearer ${token}` },
          },
        },
      },
      null,
      2,
    );
  }

  return JSON.stringify(
    {
      mcpServers: {
        wormhole: {
          type: 'http',
          url: endpoint,
          headers: { Authorization: `Bearer ${token}` },
        },
      },
    },
    null,
    2,
  );
}

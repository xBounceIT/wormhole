using Wormhole.Services.Ssh;

namespace Wormhole.Services.Mcp;

/// <summary>Metadata about a live, connected SSH session exposed to MCP clients.</summary>
public sealed record McpSessionInfo(
    string Id,
    string Host,
    int Port,
    string Username,
    string Title,
    string Status);

/// <summary>
/// The bridge between the MCP tool surface and Wormhole's live SSH tabs. All members marshal to
/// the UI thread as needed (the tab collection and approval dialogs are UI-thread bound), gate
/// the first action against a session on a per-session approval dialog, and audit-log every
/// action. Resolved as a singleton from the WinUI container and re-registered into the Kestrel
/// host's container so the MCP tool type can depend on it.
/// </summary>
public interface IMcpSessionRegistry
{
    Task<IReadOnlyList<McpSessionInfo>> ListSessionsAsync(CancellationToken cancellationToken = default);

    Task<ShellCommandResult> RunCommandAsync(string sessionId, string command, int timeoutSeconds, CancellationToken cancellationToken = default);

    Task SendTextAsync(string sessionId, string text, CancellationToken cancellationToken = default);

    Task<string> ReadTerminalAsync(string sessionId, int maxBytes, CancellationToken cancellationToken = default);
}

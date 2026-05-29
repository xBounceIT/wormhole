using System.ComponentModel;
using ModelContextProtocol.Server;
using Wormhole.Services.Ssh;

namespace Wormhole.Services.Mcp;

/// <summary>
/// The MCP tool surface for controlling live SSH sessions. Thin shim over
/// <see cref="IMcpSessionRegistry"/> — all UI marshaling, per-session approval, and audit
/// logging happen there. Scope is deliberately limited to already-open sessions: there is no
/// tool to open a connection or read saved credentials.
/// </summary>
[McpServerToolType]
public sealed class McpSshTools
{
    private readonly IMcpSessionRegistry _registry;

    public McpSshTools(IMcpSessionRegistry registry) => _registry = registry;

    [McpServerTool(Name = "list_sessions")]
    [Description("List the SSH sessions currently open and connected in Wormhole. Returns each session's id (use it with the other tools), host, port, username, tab title, and status.")]
    public Task<IReadOnlyList<McpSessionInfo>> ListSessions(CancellationToken cancellationToken)
        => _registry.ListSessionsAsync(cancellationToken);

    [McpServerTool(Name = "run_command")]
    [Description(
        "Run a single shell command on a connected SSH session and return its captured output and exit code. " +
        "This drives the user's live terminal, so it assumes a normal POSIX shell prompt is in the foreground " +
        "(not vim/less/a REPL). For interactive programs, use send_text + read_terminal instead. " +
        "The first action on a session asks the user to approve AI-agent control.")]
    public Task<ShellCommandResult> RunCommand(
        [Description("Session id from list_sessions.")] string sessionId,
        [Description("A single shell command to run at the prompt.")] string command,
        [Description("Max seconds to wait for the command to finish (default 30).")] int timeoutSeconds = 30,
        CancellationToken cancellationToken = default)
        => _registry.RunCommandAsync(sessionId, command, timeoutSeconds, cancellationToken);

    [McpServerTool(Name = "send_text")]
    [Description(
        "Type raw text into a connected SSH session exactly as if the user typed it; no output is captured. " +
        "Use it to answer interactive prompts or send control sequences. Append \\r to submit a line; " +
        "send \\u0003 for Ctrl-C. The first action on a session asks the user to approve AI-agent control.")]
    public async Task<string> SendText(
        [Description("Session id from list_sessions.")] string sessionId,
        [Description("The exact text/bytes to send. Include a trailing \\r to press Enter.")] string text,
        CancellationToken cancellationToken = default)
    {
        await _registry.SendTextAsync(sessionId, text, cancellationToken);
        return "ok";
    }

    [McpServerTool(Name = "read_terminal")]
    [Description(
        "Return recent terminal output (scrollback) from a connected SSH session as plain text with ANSI " +
        "codes stripped. Use it after send_text to see what happened. " +
        "The first action on a session asks the user to approve AI-agent control.")]
    public Task<string> ReadTerminal(
        [Description("Session id from list_sessions.")] string sessionId,
        [Description("Max bytes of the most recent output to return (default 65536).")] int maxBytes = 65536,
        CancellationToken cancellationToken = default)
        => _registry.ReadTerminalAsync(sessionId, maxBytes, cancellationToken);
}

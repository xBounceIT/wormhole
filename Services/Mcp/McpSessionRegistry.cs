using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Dispatching;
using Wormhole.Services.Security;
using Wormhole.Services.Ssh;
using Wormhole.ViewModels;
using Wormhole.ViewModels.Sessions;

namespace Wormhole.Services.Mcp;

/// <inheritdoc />
public sealed class McpSessionRegistry : IMcpSessionRegistry
{
    private readonly ShellViewModel _shell;
    private readonly IDialogService _dialog;
    private readonly IAppLockState _lockState;
    private readonly ILogger _audit;
    private readonly DispatcherQueue? _dispatcher;

    public McpSessionRegistry(
        ShellViewModel shell,
        IDialogService dialog,
        IAppLockState lockState,
        ILoggerFactory loggerFactory)
    {
        _shell = shell;
        _dialog = dialog;
        _lockState = lockState;
        try
        {
            _dispatcher = DispatcherQueue.GetForCurrentThread();
        }
        catch (COMException)
        {
            _dispatcher = null;
        }
        // Dedicated audit category so MCP-initiated actions are greppable in the Serilog file.
        _audit = loggerFactory.CreateLogger("Wormhole.McpAudit");
    }

    public Task<IReadOnlyList<McpSessionInfo>> ListSessionsAsync(CancellationToken cancellationToken = default)
        => OnUiAsync<IReadOnlyList<McpSessionInfo>>(() =>
        {
            ThrowIfLocked();
            var list = new List<McpSessionInfo>();
            foreach (var tab in _shell.Tabs)
            {
                if (tab is SshSessionViewModel ssh && ssh.IsMcpConnected)
                {
                    var p = ssh.Profile;
                    list.Add(new McpSessionInfo(
                        ssh.McpId.ToString(),
                        p?.Host ?? string.Empty,
                        p?.Port ?? 0,
                        p?.Username ?? string.Empty,
                        ssh.Title,
                        ssh.Status.ToString()));
                }
            }
            return list;
        });

    public async Task<ShellCommandResult> RunCommandAsync(string sessionId, string command, int timeoutSeconds, CancellationToken cancellationToken = default)
    {
        ThrowIfLocked();
        var vm = await ResolveApprovedAsync(sessionId).ConfigureAwait(false);
        var timeout = TimeSpan.FromSeconds(timeoutSeconds <= 0 ? 30 : timeoutSeconds);

        var result = await vm.RunCommandAsync(command, timeout, cancellationToken).ConfigureAwait(false);

        // Audit the action and outcome but NEVER the command text or captured output — either can
        // contain inline secrets (e.g. "mysql -p<pass>"). CLAUDE.md/AGENTS.md: never log credentials.
        _audit.LogInformation(
            "run_command {User}@{Host} -> exit={Exit} timedOut={TimedOut} truncated={Truncated} ({Length} chars)",
            vm.Profile?.Username, vm.Profile?.Host, result.ExitCode, result.TimedOut, result.Truncated, result.Output.Length);
        return result;
    }

    public async Task SendTextAsync(string sessionId, string text, CancellationToken cancellationToken = default)
    {
        ThrowIfLocked();
        var vm = await ResolveApprovedAsync(sessionId).ConfigureAwait(false);
        // Log only the byte count — raw text may be a password typed at a prompt.
        _audit.LogInformation("send_text {User}@{Host}: {Bytes} bytes",
            vm.Profile?.Username, vm.Profile?.Host, Encoding.UTF8.GetByteCount(text));
        await vm.SendTextAsync(text, cancellationToken).ConfigureAwait(false);
    }

    public async Task<string> ReadTerminalAsync(string sessionId, int maxBytes, CancellationToken cancellationToken = default)
    {
        ThrowIfLocked();
        var vm = await ResolveApprovedAsync(sessionId).ConfigureAwait(false);
        // TerminalReplayBuffer.Snapshot is itself thread-safe, so no UI hop needed here.
        var snapshot = vm.SnapshotTerminal();
        if (maxBytes > 0 && snapshot.Length > maxBytes)
        {
            var start = snapshot.Length - maxBytes;
            // Don't start in the middle of a multi-byte UTF-8 sequence: skip continuation bytes
            // (10xxxxxx) so GetString below doesn't emit a leading replacement char.
            while (start < snapshot.Length && (snapshot[start] & 0xC0) == 0x80) start++;
            snapshot = snapshot[start..];
        }
        _audit.LogInformation("read_terminal {User}@{Host}: {Bytes} bytes",
            vm.Profile?.Username, vm.Profile?.Host, snapshot.Length);
        return TerminalText.StripAnsi(Encoding.UTF8.GetString(snapshot));
    }

    // Resolve the session and obtain (or confirm) the user's per-session approval — all on the
    // UI thread. Throws with an agent-readable message on any failure so the SDK surfaces it as
    // a tool error.
    private Task<SshSessionViewModel> ResolveApprovedAsync(string sessionId)
        => OnUiAsync(async () =>
        {
            ThrowIfLocked();
            var vm = FindOnUi(sessionId)
                ?? throw new InvalidOperationException(
                    $"No live SSH session with id '{sessionId}'. Call list_sessions for current ids.");
            if (!vm.IsMcpConnected)
                throw new InvalidOperationException("That SSH session is not connected.");

            var approved = await vm.EnsureMcpApprovedAsync(_dialog).ConfigureAwait(true);
            if (!approved)
                throw new InvalidOperationException("The user denied AI-agent control of that session.");
            return vm;
        });

    private void ThrowIfLocked()
    {
        if (_lockState.IsLocked)
        {
            throw new InvalidOperationException("Wormhole is locked. Unlock the app before using MCP tools.");
        }
    }

    // Must run on the UI thread (enumerates the UI-bound Tabs collection).
    private SshSessionViewModel? FindOnUi(string sessionId)
    {
        foreach (var tab in _shell.Tabs)
        {
            if (tab is SshSessionViewModel ssh && ssh.McpId.ToString() == sessionId)
            {
                return ssh;
            }
        }
        return null;
    }

    private Task<T> OnUiAsync<T>(Func<T> func)
    {
        var dq = _dispatcher;
        if (dq is null) return Task.FromResult(func()); // no window (tests/headless) — run inline
        var tcs = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!dq.TryEnqueue(() =>
            {
                try { tcs.SetResult(func()); }
                catch (Exception ex) { tcs.SetException(ex); }
            }))
        {
            tcs.SetException(new InvalidOperationException("UI dispatcher unavailable (window closing?)."));
        }
        return tcs.Task;
    }

    private Task<T> OnUiAsync<T>(Func<Task<T>> func)
    {
        var dq = _dispatcher;
        if (dq is null) return func();
        var tcs = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!dq.TryEnqueue(async () =>
            {
                try { tcs.SetResult(await func().ConfigureAwait(true)); }
                catch (Exception ex) { tcs.SetException(ex); }
            }))
        {
            tcs.SetException(new InvalidOperationException("UI dispatcher unavailable (window closing?)."));
        }
        return tcs.Task;
    }
}

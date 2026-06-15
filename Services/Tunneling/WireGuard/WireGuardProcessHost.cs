using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Wormhole.Services.Tunneling.WireGuard;

/// <summary>
/// Owns the lifetime of <c>wormhole-wgproxy.exe</c>: writes the JSON config to its stdin,
/// reads <c>READY &lt;port&gt;</c> from stdout, and surfaces stderr through ILogger. Killing
/// the host kills the sidecar process. The process exits on stdin close (parent died) or SIGTERM.
/// </summary>
public sealed class WireGuardProcessHost : IAsyncDisposable
{
    private static readonly TimeSpan ReadyTimeout = TimeSpan.FromSeconds(15);
    private static readonly byte[] s_newline = new byte[] { (byte)'\n' };
    // Bounded so a misbehaving sidecar that floods stderr can't bloat the failure message.
    private const int MaxStderrTailLines = 20;

    private readonly ILogger _logger;
    private readonly Process _process;
    private readonly Task _stderrPump;
    private readonly ProcessExitSignal _processExit;
    // Last few stderr lines, kept so an early-exit failure surfaces the sidecar's own
    // diagnostic instead of an opaque pipe error.
    private readonly ConcurrentQueue<string> _stderrTail = new();
    private int _disposedFlag;
    private int _socksPort;

    private WireGuardProcessHost(Process process, ILogger logger)
    {
        _process = process;
        _logger = logger;
        _processExit = new ProcessExitSignal(process);
        _stderrPump = PumpStderrAsync();
    }

    public IPEndPoint SocksEndpoint => new(IPAddress.Loopback, _socksPort);

    public Task<int?> ProcessExited => _processExit.Exited;

    public static async Task<WireGuardProcessHost> StartAsync(
        string sidecarPath,
        WireGuardSidecarConfig config,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(sidecarPath))
            throw new ArgumentException("Sidecar path required.", nameof(sidecarPath));

        var psi = new ProcessStartInfo
        {
            FileName = sidecarPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        var process = new Process { StartInfo = psi, EnableRaisingEvents = true };
        try
        {
            process.Start();
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode is 2 or 3)
        {
            // ERROR_FILE_NOT_FOUND (2) or ERROR_PATH_NOT_FOUND (3) — the latter fires when
            // the parent directory of the sidecar binary doesn't exist (half-installed or
            // dev build that hasn't run Fetch-WgProxy yet). Rewrap so the operator sees
            // the path that was attempted and the build-step that's supposed to populate it.
            throw new FileNotFoundException(
                $"WireGuard sidecar binary not found at '{sidecarPath}'. The Fetch-WgProxy build step should have produced it.",
                sidecarPath, ex);
        }

        var host = new WireGuardProcessHost(process, logger);
        try
        {
            // Single timeout CTS covers BOTH the stdin write AND the stdout READY read. If the
            // sidecar process accepts spawn but stalls reading stdin (cold-start AV scan, slow
            // disk), the JSON write blocks at the OS-pipe layer once the small kernel buffer
            // fills. Without a timeout on the write the caller would see "operation cancelled"
            // (their own cancel) instead of "sidecar didn't become ready". Hoist timeoutCts
            // above the write so the budget applies to the whole handshake.
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(ReadyTimeout);

            // Serialize straight to the stdin pipe instead of materializing the JSON as a
            // string first — saves one full allocation of the (~400 byte) payload on the SSH
            // connect hot path. The trailing newline is cosmetic for the sidecar's
            // json.NewDecoder (which terminates on the closing brace) but kept so the line is
            // visually separated when running the sidecar interactively for debugging.
            var stdin = process.StandardInput.BaseStream;
            try
            {
                await JsonSerializer.SerializeAsync(stdin, config, cancellationToken: timeoutCts.Token).ConfigureAwait(false);
                await stdin.WriteAsync(s_newline, timeoutCts.Token).ConfigureAwait(false);
                await stdin.FlushAsync(timeoutCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException(
                    $"WireGuard sidecar did not accept its configuration on stdin within {ReadyTimeout.TotalSeconds:F0}s.");
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException)
            {
                // The sidecar exited and closed its stdin mid-write, so the OS pipe write throws
                // a raw "the pipe is being closed" IOException. Surface the sidecar's captured
                // stderr instead of that opaque message.
                throw await host.BuildEarlyExitExceptionAsync(
                    "closed its stdin before accepting the configuration", ex).ConfigureAwait(false);
            }
            // Do NOT close stdin: the sidecar treats EOF as a shutdown signal.

            string? line;
            try
            {
                line = await process.StandardOutput.ReadLineAsync(timeoutCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                // Timeout fired (not the caller cancelling) — raise a concrete TimeoutException
                // so SshSessionViewModel.ConnectAsync's generic catch surfaces an actionable
                // "tunnel sidecar didn't become ready" message instead of swallowing this as
                // the user-cancel path that quietly transitions to Disconnected.
                throw new TimeoutException(
                    $"WireGuard sidecar did not produce a READY line within {ReadyTimeout.TotalSeconds:F0}s.");
            }
            if (line is null)
                throw await host.BuildEarlyExitExceptionAsync("exited before becoming ready", null).ConfigureAwait(false);

            // Expected: "READY <port>"
            if (!line.StartsWith("READY ", StringComparison.Ordinal) ||
                !int.TryParse(line.AsSpan(6), out var port) ||
                port is < 1 or > 65535)
            {
                throw new IOException($"WireGuard sidecar produced unexpected handshake line: '{line}'.");
            }
            host._socksPort = port;
            logger.LogInformation("WireGuard sidecar ready on 127.0.0.1:{Port} (pid {Pid}).", port, process.Id);
            return host;
        }
        catch
        {
            await host.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private async Task PumpStderrAsync()
    {
        try
        {
            string? line;
            while ((line = await _process.StandardError.ReadLineAsync().ConfigureAwait(false)) is not null)
            {
                if (line.Length == 0) continue;
                _logger.LogInformation("[wgproxy] {Line}", line);
                _stderrTail.Enqueue(line);
                while (_stderrTail.Count > MaxStderrTailLines && _stderrTail.TryDequeue(out _)) { }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Stderr pump for WireGuard sidecar ended.");
        }
    }

    /// <summary>
    /// Builds an actionable exception for an early sidecar exit, folding in the sidecar's
    /// captured stderr tail and exit code, so a closed-pipe IOException or a null READY line
    /// surfaces what the sidecar actually printed rather than an opaque pipe error. Waits
    /// briefly for the process to exit and the stderr pump to drain; only runs on the failure
    /// path, inside <see cref="ReadyTimeout"/>.
    /// </summary>
    private async Task<Exception> BuildEarlyExitExceptionAsync(string what, Exception? inner)
    {
        try
        {
            using var exitCts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            await _process.WaitForExitAsync(exitCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { /* still running — report what we have */ }
        catch (InvalidOperationException) { /* no associated process / already gone */ }

        try { await Task.WhenAny(_stderrPump, Task.Delay(TimeSpan.FromMilliseconds(500))).ConfigureAwait(false); }
        catch { /* pump faults are logged inside PumpStderrAsync */ }

        int? exitCode = null;
        try { if (_process.HasExited) exitCode = _process.ExitCode; }
        catch { /* best effort */ }

        var tail = string.Join(" / ", _stderrTail.ToArray());
        var detail = string.IsNullOrWhiteSpace(tail) ? "no diagnostic output was captured" : tail;
        var code = exitCode is { } c ? $" (exit code {c})" : string.Empty;
        return new IOException($"WireGuard sidecar {what}{code}. Sidecar reported: {detail}", inner);
    }

    public async ValueTask DisposeAsync()
    {
        // Interlocked guard so concurrent dispose calls (the SocksTunnelInstance onDispose
        // hook plus, e.g., a direct teardown on the same path) don't double-kill the
        // process or race the stderr pump.
        if (Interlocked.Exchange(ref _disposedFlag, 1) != 0) return;

        try
        {
            // Closing stdin signals graceful shutdown to the sidecar.
            try { _process.StandardInput.Close(); } catch { /* best effort */ }

            // Async wait — DisposeAsync runs on session-teardown continuations, so blocking
            // the calling thread for up to 2s with the synchronous overload would stall the
            // dispatcher behind it.
            using var waitCts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            try
            {
                await _process.WaitForExitAsync(waitCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                try { _process.Kill(entireProcessTree: true); } catch { /* best effort */ }
            }
        }
        catch (InvalidOperationException)
        {
            // Process already exited.
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error while shutting down WireGuard sidecar.");
        }

        _processExit.Complete();
        _processExit.Dispose();
        try { await _stderrPump.ConfigureAwait(false); } catch { /* logged inside */ }
        try { _process.Dispose(); } catch { /* best effort */ }
    }
}

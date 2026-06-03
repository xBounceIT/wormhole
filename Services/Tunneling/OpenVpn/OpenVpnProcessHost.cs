using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Wormhole.Services.Tunneling.OpenVpn;

/// <summary>
/// Owns the lifetime of <c>wormhole-ovpnproxy.exe</c>: writes the JSON config to its stdin,
/// reads <c>READY &lt;port&gt;</c> from stdout, and surfaces stderr through ILogger. Killing
/// the host kills the sidecar process. The process exits on stdin close (parent died) or
/// SIGTERM. The ready timeout is longer than the WireGuard sidecar's because OpenVPN's TLS
/// handshake + push-reply exchange can run several seconds on a healthy server and longer
/// when a firewall is misbehaving.
/// </summary>
public sealed class OpenVpnProcessHost : IAsyncDisposable
{
    // Must strictly contain the sidecar's own ovpn_wait_connected budget (30s, see
    // ovpn_cgo.go) plus the time we spend BEFORE that wait even begins: stdin JSON write,
    // ovpn_load_profile, ovpn_set_creds, ovpn_connect_async, SOCKS5 listener bind, and the
    // READY emit + read-back through the pipe. The parent timer starts at the top of
    // StartAsync, so a healthy session that consumes the full 30s sidecar budget plus a
    // couple of seconds of setup would otherwise be killed as a false timeout right as it
    // succeeds. The 15s slack swallows AV-scan / cold-start jitter without changing the
    // user-perceived handshake budget.
    private static readonly TimeSpan ReadyTimeout = TimeSpan.FromSeconds(45);
    private static readonly byte[] s_newline = new byte[] { (byte)'\n' };
    // Bounded so a misbehaving sidecar that floods stderr can't bloat the failure message;
    // the fatal line is almost always among the last few, so a small tail suffices.
    private const int MaxStderrTailLines = 20;

    private readonly ILogger _logger;
    private readonly Process _process;
    private readonly Task _stderrPump;
    // Last few stderr lines, kept so an early-exit failure can surface the sidecar's own
    // diagnostic (e.g. "OpenVPN3 binding not linked") instead of an opaque pipe error.
    private readonly ConcurrentQueue<string> _stderrTail = new();
    private int _disposedFlag;
    private int _socksPort;

    private OpenVpnProcessHost(Process process, ILogger logger)
    {
        _process = process;
        _logger = logger;
        _stderrPump = PumpStderrAsync();
    }

    public IPEndPoint SocksEndpoint => new(IPAddress.Loopback, _socksPort);

    public static async Task<OpenVpnProcessHost> StartAsync(
        string sidecarPath,
        OpenVpnSidecarConfig config,
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
            // dev build that hasn't run Fetch-OvpnProxy yet). Rewrap so the operator sees
            // the path that was attempted and the build-step that's supposed to populate it.
            throw new FileNotFoundException(
                $"OpenVPN sidecar binary not found at '{sidecarPath}'. The Fetch-OvpnProxy build step should have produced it.",
                sidecarPath, ex);
        }

        var host = new OpenVpnProcessHost(process, logger);
        try
        {
            // Single timeout CTS covers BOTH the stdin write AND the stdout READY read. If the
            // sidecar process accepts spawn but stalls reading stdin (cold-start AV scan,
            // debugger attach, slow disk), the JSON write blocks at the OS-pipe layer once the
            // small kernel buffer fills — and without a timeout on the write itself the caller
            // would see "operation cancelled" (their own cancel) instead of an actionable
            // "sidecar didn't become ready". Hoisting timeoutCts above the write closes that
            // gap. ReadyTimeout is the budget for the whole startup handshake.
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(ReadyTimeout);

            // Serialize straight to the stdin pipe — same pattern as the WireGuard sidecar.
            // The trailing newline is cosmetic for the sidecar's json.NewDecoder but useful
            // when running interactively for debugging. Do NOT close stdin afterward: the
            // sidecar treats EOF as a shutdown signal and exits.
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
                    $"OpenVPN sidecar did not accept its configuration on stdin within {ReadyTimeout.TotalSeconds:F0}s.");
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException)
            {
                // The sidecar exited (e.g. the mock-only build fataling "OpenVPN3 binding not
                // linked") and closed its stdin mid-write, so the OS pipe write throws a raw
                // "the pipe is being closed" IOException. Surface the sidecar's captured stderr
                // instead of that opaque message.
                throw await host.BuildEarlyExitExceptionAsync(
                    "closed its stdin before accepting the configuration", ex).ConfigureAwait(false);
            }

            string? line;
            try
            {
                line = await process.StandardOutput.ReadLineAsync(timeoutCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                // Timeout fired (not the caller cancelling). Raise a concrete TimeoutException
                // so the session connect path surfaces an actionable "tunnel sidecar didn't
                // become ready" message instead of swallowing this as the user-cancel path.
                throw new TimeoutException(
                    $"OpenVPN sidecar did not produce a READY line within {ReadyTimeout.TotalSeconds:F0}s.");
            }
            if (line is null)
                throw await host.BuildEarlyExitExceptionAsync("exited before becoming ready", null).ConfigureAwait(false);

            if (!line.StartsWith("READY ", StringComparison.Ordinal) ||
                !int.TryParse(line.AsSpan(6), out var port) ||
                port is < 1 or > 65535)
            {
                throw new IOException($"OpenVPN sidecar produced unexpected handshake line: '{line}'.");
            }
            host._socksPort = port;
            logger.LogInformation("OpenVPN sidecar ready on 127.0.0.1:{Port} (pid {Pid}).", port, process.Id);
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
                _logger.LogInformation("[ovpnproxy] {Line}", line);
                _stderrTail.Enqueue(line);
                while (_stderrTail.Count > MaxStderrTailLines && _stderrTail.TryDequeue(out _)) { }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Stderr pump for OpenVPN sidecar ended.");
        }
    }

    /// <summary>
    /// Builds an actionable exception for an early sidecar exit, folding in the sidecar's
    /// captured stderr tail and exit code. The raw failures — a closed-pipe IOException on the
    /// stdin write, or a null READY line — otherwise reach the UI as an opaque "the pipe is
    /// being closed" / "exited before becoming ready" with the sidecar's real diagnostic (e.g.
    /// "OpenVPN3 binding not linked") stranded in the log. Waits briefly for the process to
    /// finish exiting and the stderr pump to drain so the message carries what the sidecar
    /// actually printed. Only runs on the failure path, well inside <see cref="ReadyTimeout"/>.
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

        // Let the stderr pump flush the final lines (the fatal message is usually last).
        try { await Task.WhenAny(_stderrPump, Task.Delay(TimeSpan.FromMilliseconds(500))).ConfigureAwait(false); }
        catch { /* pump faults are logged inside PumpStderrAsync */ }

        int? exitCode = null;
        try { if (_process.HasExited) exitCode = _process.ExitCode; }
        catch { /* best effort */ }

        var tail = string.Join(" / ", _stderrTail.ToArray());
        var detail = string.IsNullOrWhiteSpace(tail) ? "no diagnostic output was captured" : tail;
        var code = exitCode is { } c ? $" (exit code {c})" : string.Empty;
        return new IOException($"OpenVPN sidecar {what}{code}. Sidecar reported: {detail}", inner);
    }

    public async ValueTask DisposeAsync()
    {
        // Interlocked guard so concurrent dispose calls don't double-kill the process or
        // race the stderr pump.
        if (Interlocked.Exchange(ref _disposedFlag, 1) != 0) return;

        try
        {
            // Closing stdin signals graceful shutdown to the sidecar.
            try { _process.StandardInput.Close(); } catch { /* best effort */ }

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
            _logger.LogWarning(ex, "Error while shutting down OpenVPN sidecar.");
        }

        try { await _stderrPump.ConfigureAwait(false); } catch { /* logged inside */ }
        try { _process.Dispose(); } catch { /* best effort */ }
    }
}

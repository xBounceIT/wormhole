using System;
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

    private readonly ILogger _logger;
    private readonly Process _process;
    private readonly Task _stderrPump;
    private int _disposedFlag;

    private WireGuardProcessHost(Process process, ILogger logger)
    {
        _process = process;
        _logger = logger;
        _stderrPump = Task.Run(PumpStderrAsync);
    }

    public int SocksPort { get; private set; }
    public IPEndPoint SocksEndpoint => new(IPAddress.Loopback, SocksPort);

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
            var json = JsonSerializer.Serialize(config);
            await process.StandardInput.WriteLineAsync(json.AsMemory(), cancellationToken).ConfigureAwait(false);
            await process.StandardInput.FlushAsync(cancellationToken).ConfigureAwait(false);
            // Do NOT close stdin: the sidecar treats EOF as a shutdown signal.

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(ReadyTimeout);
            var line = await process.StandardOutput.ReadLineAsync(timeoutCts.Token).ConfigureAwait(false)
                ?? throw new IOException("WireGuard sidecar exited before becoming ready.");

            // Expected: "READY <port>"
            if (!line.StartsWith("READY ", StringComparison.Ordinal) ||
                !int.TryParse(line.AsSpan(6), out var port) ||
                port is < 1 or > 65535)
            {
                throw new IOException($"WireGuard sidecar produced unexpected handshake line: '{line}'.");
            }
            host.SocksPort = port;
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
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Stderr pump for WireGuard sidecar ended.");
        }
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

        try { await _stderrPump.ConfigureAwait(false); } catch { /* logged inside */ }
        try { _process.Dispose(); } catch { /* best effort */ }
    }
}

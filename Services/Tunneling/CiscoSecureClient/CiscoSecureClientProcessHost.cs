using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Wormhole.Services.Tunneling.CiscoSecureClient;

/// <summary>
/// Owns the lifetime of <c>wormhole-ciscoproxy.exe</c>: writes the JSON config to its stdin,
/// reads <c>READY &lt;port&gt;</c> from stdout, and surfaces stderr through ILogger. Mirrors
/// <see cref="Fortinet.FortinetProcessHost"/> contract beat-for-beat so the protocol shape stays
/// uniform across tunnel kinds; only the readiness budget differs.
/// </summary>
public sealed class CiscoSecureClientProcessHost : IAsyncDisposable
{
    // AnyConnect login (HTTPS aggregate-auth round-trips, optional second-factor challenge, then
    // the CSTP TLS CONNECT) is heavier than WireGuard's UDP handshake — and a 2FA prompt can add
    // a round-trip — so allow a longer ready window before bailing.
    private static readonly TimeSpan ReadyTimeout = TimeSpan.FromSeconds(40);
    private static readonly byte[] s_newline = new byte[] { (byte)'\n' };

    private readonly ILogger _logger;
    private readonly Process _process;
    private readonly Task _stderrPump;
    private int _disposedFlag;
    private int _socksPort;

    private CiscoSecureClientProcessHost(Process process, ILogger logger)
    {
        _process = process;
        _logger = logger;
        _stderrPump = PumpStderrAsync();
    }

    public IPEndPoint SocksEndpoint => new(IPAddress.Loopback, _socksPort);

    public static async Task<CiscoSecureClientProcessHost> StartAsync(
        string sidecarPath,
        CiscoSecureClientSidecarConfig config,
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
            throw new FileNotFoundException(
                $"Cisco Secure Client sidecar binary not found at '{sidecarPath}'. The Fetch-CiscoProxy build step should have produced it.",
                sidecarPath, ex);
        }

        var host = new CiscoSecureClientProcessHost(process, logger);
        try
        {
            // Single timeout CTS covers BOTH the stdin write AND the stdout READY read, matching
            // the WireGuard/OpenVPN/Fortinet hosts.
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(ReadyTimeout);

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
                    $"Cisco Secure Client sidecar did not accept its configuration on stdin within {ReadyTimeout.TotalSeconds:F0}s.");
            }
            // Do NOT close stdin: the sidecar treats EOF as a shutdown signal.

            string? line;
            try
            {
                line = await process.StandardOutput.ReadLineAsync(timeoutCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException(
                    $"Cisco Secure Client sidecar did not produce a READY line within {ReadyTimeout.TotalSeconds:F0}s.");
            }
            if (line is null) throw new IOException("Cisco Secure Client sidecar exited before becoming ready.");

            if (!line.StartsWith("READY ", StringComparison.Ordinal) ||
                !int.TryParse(line.AsSpan(6), out var port) ||
                port is < 1 or > 65535)
            {
                throw new IOException($"Cisco Secure Client sidecar produced unexpected handshake line: '{line}'.");
            }
            host._socksPort = port;
            logger.LogInformation("Cisco Secure Client sidecar ready on 127.0.0.1:{Port} (pid {Pid}).", port, process.Id);
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
                _logger.LogInformation("[ciscoproxy] {Line}", line);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Stderr pump for Cisco Secure Client sidecar ended.");
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposedFlag, 1) != 0) return;

        try
        {
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
            _logger.LogWarning(ex, "Error while shutting down Cisco Secure Client sidecar.");
        }

        try { await _stderrPump.ConfigureAwait(false); } catch { /* logged inside */ }
        try { _process.Dispose(); } catch { /* best effort */ }
    }
}

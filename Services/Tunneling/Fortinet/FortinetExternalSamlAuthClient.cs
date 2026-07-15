using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling.Fortinet;

internal sealed class FortinetExternalSamlAuthClient
{
    private const int MaxRequestHeaderBytes = 16 * 1024;
    private static readonly TimeSpan s_defaultRequestTimeout = TimeSpan.FromSeconds(5);
    private static readonly byte[] s_successResponse = BuildResponse(
        "200 OK",
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Wormhole VPN</title></head>" +
        "<body><p>Authentication received. You can return to Wormhole.</p></body></html>");
    private static readonly byte[] s_badRequestResponse = BuildResponse(
        "400 Bad Request",
        "<!doctype html><html><body><p>Invalid authentication callback.</p></body></html>");

    private readonly IFortinetExternalBrowserLauncher _browserLauncher;
    private readonly TimeSpan _requestTimeout;

    internal FortinetExternalSamlAuthClient(
        IFortinetExternalBrowserLauncher browserLauncher,
        TimeSpan? requestTimeout = null)
    {
        _browserLauncher = browserLauncher;
        _requestTimeout = requestTimeout ?? s_defaultRequestTimeout;
        if (_requestTimeout <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(requestTimeout));
    }

    internal async Task<FortinetSamlAuthResult> AuthenticateAsync(
        FortinetSettings settings,
        CancellationToken cancellationToken)
    {
        var listener = new TcpListener(IPAddress.Loopback, settings.SamlRedirectPort);
        try
        {
            try
            {
                listener.Start(backlog: 4);
            }
            catch (SocketException ex)
            {
                throw new InvalidOperationException(
                    $"Could not listen on 127.0.0.1:{settings.SamlRedirectPort} for the Fortinet SAML callback. " +
                    "Verify that this matches the FortiGate saml-redirect-port and that no other application is using it.",
                    ex);
            }

            // Bind first: the identity provider may redirect back immediately when the default browser
            // already has a live SSO session.
            _browserLauncher.Open(FortinetSamlProtocol.BuildStartUri(settings));

            while (true)
            {
                using var client = await listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
                using var requestCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                requestCts.CancelAfter(_requestTimeout);

                string? target;
                try
                {
                    target = await ReadRequestTargetAsync(client.GetStream(), requestCts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    // A local probe or abandoned browser connection must not monopolize the
                    // single callback listener for the whole five-minute SSO window.
                    continue;
                }
                if (!FortinetSamlProtocol.TryParseAuthId(target, out var authId))
                {
                    await TryWriteResponseAsync(
                        client.GetStream(), s_badRequestResponse, requestCts.Token, cancellationToken).ConfigureAwait(false);
                    continue;
                }

                await TryWriteResponseAsync(
                    client.GetStream(), s_successResponse, requestCts.Token, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                return FortinetSamlAuthResult.FromAuthId(authId);
            }
        }
        finally
        {
            listener.Stop();
        }
    }

    private static async Task<string?> ReadRequestTargetAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[MaxRequestHeaderBytes];
        var count = 0;
        while (count < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(count, buffer.Length - count), cancellationToken)
                .ConfigureAwait(false);
            if (read == 0) return null;
            count += read;

            var headerEnd = FindHeaderEnd(buffer.AsSpan(0, count));
            if (headerEnd < 0) continue;

            var requestLineEnd = buffer.AsSpan(0, headerEnd).IndexOf("\r\n"u8);
            if (requestLineEnd <= 0) return null;
            var requestLine = Encoding.ASCII.GetString(buffer, 0, requestLineEnd);
            var pieces = requestLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            return pieces.Length == 3
                && pieces[0].Equals("GET", StringComparison.Ordinal)
                && pieces[2] is "HTTP/1.0" or "HTTP/1.1"
                    ? pieces[1]
                    : null;
        }

        return null;
    }

    private static int FindHeaderEnd(ReadOnlySpan<byte> bytes) => bytes.IndexOf("\r\n\r\n"u8);

    private static async Task WriteResponseAsync(
        NetworkStream stream,
        byte[] response,
        CancellationToken cancellationToken)
    {
        await stream.WriteAsync(response, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task TryWriteResponseAsync(
        NetworkStream stream,
        byte[] response,
        CancellationToken requestToken,
        CancellationToken operationToken)
    {
        try
        {
            await WriteResponseAsync(stream, response, requestToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!operationToken.IsCancellationRequested)
        {
            // The callback itself is already complete; the local confirmation page is best effort.
        }
        catch (IOException)
        {
            // The browser may close the loopback connection immediately after sending the request.
        }
    }

    private static byte[] BuildResponse(string status, string body)
    {
        var bodyBytes = Encoding.UTF8.GetBytes(body);
        var headers = Encoding.ASCII.GetBytes(
            $"HTTP/1.1 {status}\r\nConnection: close\r\nContent-Type: text/html; charset=utf-8\r\n" +
            $"Content-Length: {bodyBytes.Length}\r\nCache-Control: no-store\r\n" +
            "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'\r\n\r\n");
        using var response = new MemoryStream(headers.Length + bodyBytes.Length);
        response.Write(headers);
        response.Write(bodyBytes);
        return response.ToArray();
    }
}

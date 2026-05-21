using System;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Wormhole.Services.Tunneling;

/// <summary>
/// Minimal RFC 1928 SOCKS5 client: no-auth method only, CONNECT command, DOMAINNAME address type.
/// Sized for the in-process tunnel use case where the SOCKS5 server is always our own sidecar.
/// </summary>
public static class Socks5Client
{
    public static async Task<Stream> ConnectAsync(
        IPEndPoint socksEndpoint,
        string targetHost,
        int targetPort,
        CancellationToken cancellationToken)
    {
        if (socksEndpoint is null) throw new ArgumentNullException(nameof(socksEndpoint));
        if (string.IsNullOrWhiteSpace(targetHost)) throw new ArgumentException("target host required", nameof(targetHost));
        if (targetPort is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(targetPort));

        // SOCKS5 DOMAINNAME is ASCII-only per RFC 1928. Punycode-convert IDN hostnames so a
        // profile like "münchen.example.com" doesn't get silently mangled into "b?nchen..."
        // by Encoding.ASCII and then fail downstream as a confusing NXDOMAIN.
        string asciiHost;
        try { asciiHost = new IdnMapping().GetAscii(targetHost); }
        catch (ArgumentException ex)
        {
            throw new ArgumentException($"target host '{targetHost}' is not a valid IDN/ASCII hostname", nameof(targetHost), ex);
        }
        var hostBytes = Encoding.ASCII.GetBytes(asciiHost);
        if (hostBytes.Length > 255) throw new ArgumentException("target host too long for SOCKS5 DOMAINNAME (>255)", nameof(targetHost));

        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        NetworkStream? stream = null;
        try
        {
            await socket.ConnectAsync(socksEndpoint, cancellationToken).ConfigureAwait(false);
            // ownsSocket: true makes Dispose on the returned stream close the socket. The
            // default NetworkStream from TcpClient.GetStream() does NOT own its socket,
            // so an earlier version leaked a TcpClient/Socket per SSH session.
            stream = new NetworkStream(socket, ownsSocket: true);

            await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, cancellationToken).ConfigureAwait(false);
            var greetingResp = await ReadExactAsync(stream, 2, cancellationToken).ConfigureAwait(false);
            if (greetingResp[0] != 0x05) throw new IOException($"SOCKS5: unexpected version 0x{greetingResp[0]:x2} in greeting reply");
            if (greetingResp[1] != 0x00) throw new IOException($"SOCKS5: server selected unsupported auth method 0x{greetingResp[1]:x2}");

            var req = new byte[7 + hostBytes.Length];
            req[0] = 0x05;
            req[1] = 0x01;
            req[2] = 0x00;
            req[3] = 0x03;
            req[4] = (byte)hostBytes.Length;
            Buffer.BlockCopy(hostBytes, 0, req, 5, hostBytes.Length);
            req[5 + hostBytes.Length] = (byte)((targetPort >> 8) & 0xff);
            req[6 + hostBytes.Length] = (byte)(targetPort & 0xff);
            await stream.WriteAsync(req, cancellationToken).ConfigureAwait(false);

            var head = await ReadExactAsync(stream, 4, cancellationToken).ConfigureAwait(false);
            if (head[0] != 0x05) throw new IOException($"SOCKS5: unexpected version 0x{head[0]:x2} in connect reply");
            if (head[1] != 0x00) throw new IOException($"SOCKS5: CONNECT failed with reply code 0x{head[1]:x2} ({DescribeReply(head[1])})");

            // Consume BND.ADDR + BND.PORT (we don't use them).
            int addrSkip = head[3] switch
            {
                0x01 => 4,
                0x04 => 16,
                0x03 => (await ReadExactAsync(stream, 1, cancellationToken).ConfigureAwait(false))[0],
                _ => throw new IOException($"SOCKS5: unknown bound address type 0x{head[3]:x2}"),
            };
            await ReadExactAsync(stream, addrSkip + 2, cancellationToken).ConfigureAwait(false);

            return stream;
        }
        catch
        {
            if (stream is not null) stream.Dispose();
            else socket.Dispose();
            throw;
        }
    }

    private static async Task<byte[]> ReadExactAsync(NetworkStream stream, int count, CancellationToken ct)
    {
        var buf = new byte[count];
        var read = 0;
        while (read < count)
        {
            var n = await stream.ReadAsync(buf.AsMemory(read, count - read), ct).ConfigureAwait(false);
            if (n == 0) throw new EndOfStreamException("SOCKS5: unexpected end of stream");
            read += n;
        }
        return buf;
    }

    private static string DescribeReply(byte code) => code switch
    {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown",
    };
}

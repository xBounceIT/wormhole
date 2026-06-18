using System;
using System.Buffers.Binary;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Wormhole.Services.Tunneling;

/// <summary>
/// Minimal RFC 1928 SOCKS5 client: no-auth method only, CONNECT command. Emits ATYP=0x01
/// (IPv4) / 0x04 (IPv6) for parsed IP literals and ATYP=0x03 (DOMAINNAME) for hostnames.
/// Sized for the in-process tunnel use case where the SOCKS5 server is always our own sidecar.
/// </summary>
public static class Socks5Client
{
    private static readonly byte[] s_greeting = new byte[] { 0x05, 0x01, 0x00 };
    private static readonly IdnMapping s_idn = new();

    public static async Task<Stream> ConnectAsync(
        IPEndPoint socksEndpoint,
        string targetHost,
        int targetPort,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(socksEndpoint);
        if (string.IsNullOrWhiteSpace(targetHost)) throw new ArgumentException("target host required", nameof(targetHost));
        if (targetPort is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(targetPort));

        // Build the address portion of the CONNECT request. SOCKS5 supports three address
        // families; pick the right one up-front:
        //   - IPv4 literal  → ATYP=0x01, 4 raw bytes
        //   - IPv6 literal  → ATYP=0x04, 16 raw bytes (colon-form, MUST NOT go through IdnMapping
        //                      which throws on colons)
        //   - hostname      → ATYP=0x03, Punycoded ASCII bytes prefixed by length
        //
        // Without the IP-literal branches an IPv6 host like "2001:db8::10" hits
        // IdnMapping.GetAscii and throws before any I/O, making every IPv6 target through the
        // tunnel a guaranteed failure even though the sidecar handles ATYP=0x04 fine.
        byte atyp;
        byte[] addrBytes;
        if (IPAddress.TryParse(targetHost, out var ip))
        {
            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                atyp = 0x01;
                addrBytes = ip.GetAddressBytes(); // 4 bytes, network order
            }
            else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                atyp = 0x04;
                addrBytes = ip.GetAddressBytes(); // 16 bytes, network order
            }
            else
            {
                throw new ArgumentException(
                    $"target host '{targetHost}' parsed as IP but unsupported address family {ip.AddressFamily}.",
                    nameof(targetHost));
            }
        }
        else
        {
            // SOCKS5 DOMAINNAME is ASCII-only per RFC 1928. Punycode-convert IDN hostnames so a
            // profile like "münchen.example.com" doesn't get silently mangled into "b?nchen..."
            // by Encoding.ASCII and then fail downstream as a confusing NXDOMAIN.
            string asciiHost;
            try { asciiHost = s_idn.GetAscii(targetHost); }
            catch (ArgumentException ex)
            {
                throw new ArgumentException($"target host '{targetHost}' is not a valid IDN/ASCII hostname or IP literal", nameof(targetHost), ex);
            }
            var byteCount = Encoding.ASCII.GetByteCount(asciiHost);
            if (byteCount > 255) throw new ArgumentException("target host too long for SOCKS5 DOMAINNAME (>255)", nameof(targetHost));
            atyp = 0x03;
            // DOMAINNAME is length-prefixed; pack [len][bytes] into addrBytes so the wire
            // assembly below stays uniform across atyp branches.
            addrBytes = new byte[1 + byteCount];
            addrBytes[0] = (byte)byteCount;
            Encoding.ASCII.GetBytes(asciiHost, addrBytes.AsSpan(1));
        }

        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        NetworkStream? stream = null;
        try
        {
            await socket.ConnectAsync(socksEndpoint, cancellationToken).ConfigureAwait(false);
            // ownsSocket: true makes Dispose on the returned stream close the socket. The
            // default NetworkStream from TcpClient.GetStream() does NOT own its socket,
            // so an earlier version leaked a TcpClient/Socket per SSH session.
            stream = new NetworkStream(socket, ownsSocket: true);

            await stream.WriteAsync(s_greeting, cancellationToken).ConfigureAwait(false);
            var greetingResp = new byte[2];
            await stream.ReadExactlyAsync(greetingResp, cancellationToken).ConfigureAwait(false);
            if (greetingResp[0] != 0x05) throw new IOException($"SOCKS5: unexpected version 0x{greetingResp[0]:x2} in greeting reply");
            if (greetingResp[1] != 0x00) throw new IOException($"SOCKS5: server selected unsupported auth method 0x{greetingResp[1]:x2}");

            // [VER, CMD, RSV, ATYP, ADDR..., PORT(2)] — uniform across all three atyps because
            // addrBytes already includes the length byte for DOMAINNAME.
            var req = new byte[4 + addrBytes.Length + 2];
            req[0] = 0x05;
            req[1] = 0x01;
            req[2] = 0x00;
            req[3] = atyp;
            Buffer.BlockCopy(addrBytes, 0, req, 4, addrBytes.Length);
            BinaryPrimitives.WriteUInt16BigEndian(req.AsSpan(4 + addrBytes.Length), (ushort)targetPort);
            await stream.WriteAsync(req, cancellationToken).ConfigureAwait(false);

            var head = new byte[4];
            await stream.ReadExactlyAsync(head, cancellationToken).ConfigureAwait(false);
            if (head[0] != 0x05) throw new IOException($"SOCKS5: unexpected version 0x{head[0]:x2} in connect reply");

            // Consume BND.ADDR + BND.PORT (we don't use them). DOMAINNAME (0x03) carries a
            // 1-byte length prefix that has to be read out-of-band to size the skip buffer.
            var failureDetail = await ReadBoundAddressOrDetailAsync(stream, head[3], cancellationToken).ConfigureAwait(false);
            if (head[1] != 0x00)
            {
                var message = $"SOCKS5: CONNECT failed with reply code 0x{head[1]:x2} ({DescribeReply(head[1])})";
                if (!string.IsNullOrWhiteSpace(failureDetail))
                {
                    message += $": {failureDetail}";
                }
                throw new IOException(message);
            }

            return stream;
        }
        catch
        {
            if (stream is not null) stream.Dispose();
            else socket.Dispose();
            throw;
        }
    }

    private static async Task<string?> ReadBoundAddressOrDetailAsync(Stream stream, byte atyp, CancellationToken cancellationToken)
    {
        int addrLength;
        switch (atyp)
        {
            case 0x01:
                addrLength = 4;
                break;
            case 0x04:
                addrLength = 16;
                break;
            case 0x03:
                var lenBuf = new byte[1];
                await stream.ReadExactlyAsync(lenBuf, cancellationToken).ConfigureAwait(false);
                addrLength = lenBuf[0];
                var addressAndPortBytes = new byte[addrLength + 2];
                await stream.ReadExactlyAsync(addressAndPortBytes, cancellationToken).ConfigureAwait(false);
                return addrLength == 0 ? null : Encoding.UTF8.GetString(addressAndPortBytes, 0, addrLength);
            default:
                throw new IOException($"SOCKS5: unknown bound address type 0x{atyp:x2}");
        }

        var skipBuf = new byte[addrLength + 2];
        await stream.ReadExactlyAsync(skipBuf, cancellationToken).ConfigureAwait(false);
        return null;
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

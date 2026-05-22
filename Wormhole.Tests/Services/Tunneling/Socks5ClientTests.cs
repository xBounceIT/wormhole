using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Services.Tunneling;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

public class Socks5ClientTests
{
    [Fact]
    public async Task ConnectAsync_NegotiatesNoAuthAndForwardsBytes()
    {
        using var server = new FakeSocksServer();
        server.Start();

        try
        {
            var stream = await Socks5Client.ConnectAsync(
                server.LocalEndpoint, "target.example", 22, CancellationToken.None);
            await using (stream)
            {
                await stream.WriteAsync(Encoding.ASCII.GetBytes("ping"), CancellationToken.None);
                var buf = new byte[4];
                var n = await ReadExactAsync(stream, buf, CancellationToken.None);
                Assert.Equal(4, n);
                Assert.Equal("pong", Encoding.ASCII.GetString(buf));
            }
        }
        finally
        {
            await server.StopAsync();
        }

        Assert.Equal("target.example", server.LastRequestedHost);
        Assert.Equal(22, server.LastRequestedPort);
    }

    [Fact]
    public async Task ConnectAsync_ThrowsWhenServerReplyIsErrorCode()
    {
        using var server = new FakeSocksServer { ReplyCode = 0x05 /* connection refused */ };
        server.Start();

        try
        {
            await Assert.ThrowsAsync<IOException>(() =>
                Socks5Client.ConnectAsync(server.LocalEndpoint, "any.example", 1234, CancellationToken.None));
        }
        finally
        {
            await server.StopAsync();
        }
    }

    [Fact]
    public async Task ConnectAsync_SendsIPv4LiteralAsAtyp1()
    {
        using var server = new FakeSocksServer();
        server.Start();

        try
        {
            var stream = await Socks5Client.ConnectAsync(
                server.LocalEndpoint, "192.0.2.10", 22, CancellationToken.None);
            await using (stream)
            {
                await stream.WriteAsync(Encoding.ASCII.GetBytes("ping"), CancellationToken.None);
                var buf = new byte[4];
                await ReadExactAsync(stream, buf, CancellationToken.None);
                Assert.Equal("pong", Encoding.ASCII.GetString(buf));
            }
        }
        finally
        {
            await server.StopAsync();
        }

        Assert.Equal(0x01, server.LastAtyp);
        Assert.Equal("192.0.2.10", server.LastRequestedHost);
        Assert.Equal(22, server.LastRequestedPort);
    }

    [Fact]
    public async Task ConnectAsync_SendsIPv6LiteralAsAtyp4()
    {
        // Regression: previously every target ran through IdnMapping.GetAscii, which throws
        // on the colons in an IPv6 literal -- so any tunnel-enabled connection to an IPv6
        // host would fail before any network I/O. Now IP literals must skip IDN and emit
        // the right ATYP.
        using var server = new FakeSocksServer();
        server.Start();

        try
        {
            var stream = await Socks5Client.ConnectAsync(
                server.LocalEndpoint, "2001:db8::10", 22, CancellationToken.None);
            await using (stream)
            {
                await stream.WriteAsync(Encoding.ASCII.GetBytes("ping"), CancellationToken.None);
                var buf = new byte[4];
                await ReadExactAsync(stream, buf, CancellationToken.None);
                Assert.Equal("pong", Encoding.ASCII.GetString(buf));
            }
        }
        finally
        {
            await server.StopAsync();
        }

        Assert.Equal(0x04, server.LastAtyp);
        // Server normalizes back to dotted/colon form via IPAddress for equality independent
        // of how the literal was bracketed in the client.
        Assert.Equal(IPAddress.Parse("2001:db8::10"), IPAddress.Parse(server.LastRequestedHost!));
        Assert.Equal(22, server.LastRequestedPort);
    }

    private static async Task<int> ReadExactAsync(Stream s, byte[] buf, CancellationToken ct)
    {
        var read = 0;
        while (read < buf.Length)
        {
            var n = await s.ReadAsync(buf.AsMemory(read, buf.Length - read), ct);
            if (n == 0) break;
            read += n;
        }
        return read;
    }

    private sealed class FakeSocksServer : IDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private Task? _loop;
        private readonly CancellationTokenSource _cts = new();

        public IPEndPoint LocalEndpoint => (IPEndPoint)_listener.LocalEndpoint;
        public byte ReplyCode { get; set; } = 0x00;
        public byte LastAtyp { get; private set; }
        public string? LastRequestedHost { get; private set; }
        public int LastRequestedPort { get; private set; }

        public void Start()
        {
            _listener.Start();
            _loop = Task.Run(LoopAsync);
        }

        private async Task LoopAsync()
        {
            try
            {
                while (!_cts.IsCancellationRequested)
                {
                    var c = await _listener.AcceptTcpClientAsync(_cts.Token);
                    _ = Task.Run(() => HandleAsync(c));
                }
            }
            catch { /* shutting down */ }
        }

        private async Task HandleAsync(TcpClient c)
        {
            using (c)
            await using (var s = c.GetStream())
            {
                // Greeting
                var hdr = new byte[2];
                if (await ReadExactAsync(s, hdr, default) < 2) return;
                var methods = new byte[hdr[1]];
                if (await ReadExactAsync(s, methods, default) < methods.Length) return;
                await s.WriteAsync(new byte[] { 0x05, 0x00 });

                // Request: ver, cmd, rsv, atyp
                var req = new byte[4];
                if (await ReadExactAsync(s, req, default) < 4) return;
                LastAtyp = req[3];
                string parsedHost;
                switch (req[3])
                {
                    case 0x01: // IPv4
                        {
                            var ipv4 = new byte[4];
                            if (await ReadExactAsync(s, ipv4, default) < 4) return;
                            parsedHost = new IPAddress(ipv4).ToString();
                            break;
                        }
                    case 0x03: // DOMAINNAME
                        {
                            var lenBuf = new byte[1];
                            if (await ReadExactAsync(s, lenBuf, default) < 1) return;
                            var host = new byte[lenBuf[0]];
                            if (await ReadExactAsync(s, host, default) < host.Length) return;
                            parsedHost = Encoding.ASCII.GetString(host);
                            break;
                        }
                    case 0x04: // IPv6
                        {
                            var ipv6 = new byte[16];
                            if (await ReadExactAsync(s, ipv6, default) < 16) return;
                            parsedHost = new IPAddress(ipv6).ToString();
                            break;
                        }
                    default:
                        await s.WriteAsync(new byte[] { 0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0 });
                        return;
                }
                var portBuf = new byte[2];
                if (await ReadExactAsync(s, portBuf, default) < 2) return;

                LastRequestedHost = parsedHost;
                LastRequestedPort = (portBuf[0] << 8) | portBuf[1];

                await s.WriteAsync(new byte[] { 0x05, ReplyCode, 0x00, 0x01, 0, 0, 0, 0, 0, 0 });

                if (ReplyCode == 0x00)
                {
                    // Echo "ping"->"pong"
                    var msg = new byte[4];
                    if (await ReadExactAsync(s, msg, default) < 4) return;
                    if (Encoding.ASCII.GetString(msg) == "ping")
                    {
                        await s.WriteAsync(Encoding.ASCII.GetBytes("pong"));
                    }
                }
            }
        }

        public async Task StopAsync()
        {
            _cts.Cancel();
            try { _listener.Stop(); } catch { }
            if (_loop is not null) { try { await _loop; } catch { } }
        }

        public void Dispose() { _cts.Dispose(); }
    }
}

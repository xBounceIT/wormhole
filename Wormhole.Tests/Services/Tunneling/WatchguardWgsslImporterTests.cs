using System.Formats.Tar;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Threading.Tasks;
using Wormhole.Services.Tunneling.Watchguard;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

public class WatchguardWgsslImporterTests
{
    [Fact]
    public async Task ImportAsync_ParsesServerPortAndCerts()
    {
        const string clientOvpn = """
            client
            proto tcp-client
            remote firebox.example.com 4443
            cipher AES-256-CBC
            """;
        const string ca = "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n";
        const string cert = "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n";
        const string key = "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n";

        using var stream = BuildTar(new[]
        {
            ("client.ovpn", clientOvpn),
            ("ca.crt", ca),
            ("client.crt", cert),
            ("client.pem", key),
        });

        var result = await WatchguardWgsslImporter.ImportAsync(stream);

        Assert.Equal("firebox.example.com", result.Server);
        Assert.Equal(4443, result.Port);
        Assert.Contains("CA", result.CaPem);
        Assert.Contains("CERT", result.ClientCertPem);
        Assert.Contains("KEY", result.ClientKeyPem);
        Assert.Contains("remote firebox.example.com 4443", result.ProfileOvpn);
        Assert.Contains("cipher AES-256-CBC", result.ProfileOvpn);
        // Username/Password are deliberately blank — the .wgssl format doesn't carry creds.
        Assert.Equal(string.Empty, result.Username);
        Assert.Equal(string.Empty, result.Password);
    }

    [Fact]
    public async Task ImportAsync_DefaultsPortTo443WhenMissingFromRemote()
    {
        const string clientOvpn = "client\nremote firebox.example.com\n";

        using var stream = BuildTar(new[]
        {
            ("client.ovpn", clientOvpn),
            ("ca.crt", "ca"),
            ("client.crt", "cert"),
            ("client.pem", "key"),
        });

        var result = await WatchguardWgsslImporter.ImportAsync(stream);

        Assert.Equal(443, result.Port);
    }

    [Fact]
    public async Task ImportAsync_StripsLeadingDotSlashFromEntryNames()
    {
        const string clientOvpn = "remote firebox.example.com 443";
        using var stream = BuildTar(new[]
        {
            ("./client.ovpn", clientOvpn),
            ("./ca.crt", "ca"),
            ("./client.crt", "cert"),
            ("./client.pem", "key"),
        });

        var result = await WatchguardWgsslImporter.ImportAsync(stream);

        Assert.Equal("firebox.example.com", result.Server);
    }

    [Fact]
    public async Task ImportAsync_ReportsMissingEntries()
    {
        // Missing client.pem — importer should list the missing file in the error message so
        // the user knows what their .wgssl is short of, instead of getting a generic "couldn't
        // import" message.
        using var stream = BuildTar(new[]
        {
            ("client.ovpn", "remote firebox.example.com 443"),
            ("ca.crt", "ca"),
            ("client.crt", "cert"),
        });

        var ex = await Assert.ThrowsAsync<InvalidDataException>(() => WatchguardWgsslImporter.ImportAsync(stream));
        Assert.Contains("client.pem", ex.Message);
    }

    [Fact]
    public async Task ImportAsync_FailsOnEmbeddedOvpnWithoutRemote()
    {
        const string clientOvpn = "client\ncipher AES-256-CBC\n";
        using var stream = BuildTar(new[]
        {
            ("client.ovpn", clientOvpn),
            ("ca.crt", "ca"),
            ("client.crt", "cert"),
            ("client.pem", "key"),
        });

        await Assert.ThrowsAsync<InvalidDataException>(() => WatchguardWgsslImporter.ImportAsync(stream));
    }

    [Fact]
    public async Task ImportAsync_RejectsOversizedEntry()
    {
        // 2 MiB entry exceeds the 1 MiB safety cap — protects against an OOM via picking a huge
        // file. Use a string of ascii bytes that compresses well at the tar layer but materializes
        // to the full size when extracted.
        var bigBlob = new string('A', 2 * 1024 * 1024);
        using var stream = BuildTar(new[]
        {
            ("client.ovpn", "remote firebox 443"),
            ("ca.crt", bigBlob),
            ("client.crt", "cert"),
            ("client.pem", "key"),
        });

        await Assert.ThrowsAsync<InvalidDataException>(() => WatchguardWgsslImporter.ImportAsync(stream));
    }

    [Fact]
    public async Task ImportAsync_RejectsExcessiveEntryCount()
    {
        // Hostile archive with many small entries — each well under 1 MiB so per-entry cap
        // doesn't trip, but aggregate dictionary growth is what we're guarding against.
        var entries = new (string Name, string Content)[200];
        for (int i = 0; i < entries.Length; i++)
            entries[i] = ($"file{i}.txt", "tiny");
        using var stream = BuildTar(entries);

        await Assert.ThrowsAsync<InvalidDataException>(() => WatchguardWgsslImporter.ImportAsync(stream));
    }

    [Fact]
    public async Task ImportAsync_ParsesTabSeparatedRemoteDirective()
    {
        // OpenVPN config tokens accept tab separators. Stock .wgssl uses spaces today but
        // tolerating tabs keeps the importer compatible with hand-crafted profiles or older
        // firmware spellings.
        const string clientOvpn = "client\nremote\tfirebox.example.com\t4443\n";

        using var stream = BuildTar(new[]
        {
            ("client.ovpn", clientOvpn),
            ("ca.crt", "ca"),
            ("client.crt", "cert"),
            ("client.pem", "key"),
        });

        var result = await WatchguardWgsslImporter.ImportAsync(stream);

        Assert.Equal("firebox.example.com", result.Server);
        Assert.Equal(4443, result.Port);
    }

    [Fact]
    public async Task ImportAsync_AcceptsGzippedTarBundle()
    {
        // Real `.wgssl` exports from a Firebox are gzip-compressed tar archives (the vendor
        // extraction workflow itself renames them to `.tgz`). The importer must transparently
        // decompress these — otherwise normal user inputs fail with a tar-parsing error
        // before client.ovpn is ever read.
        const string clientOvpn = "remote firebox.example.com 4443";
        using var stream = BuildTarGz(new[]
        {
            ("client.ovpn", clientOvpn),
            ("ca.crt", "ca"),
            ("client.crt", "cert"),
            ("client.pem", "key"),
        });

        var result = await WatchguardWgsslImporter.ImportAsync(stream);

        Assert.Equal("firebox.example.com", result.Server);
        Assert.Equal(4443, result.Port);
        Assert.Equal("ca", result.CaPem);
        Assert.Equal("cert", result.ClientCertPem);
        Assert.Equal("key", result.ClientKeyPem);
    }

    [Fact]
    public async Task ImportAsync_LeavesCallerOwnedStreamOpen()
    {
        // Lifetime contract: ImportAsync MUST NOT dispose the caller's input stream — the
        // dialog and other call sites pass the stream via `using` and dispose it themselves.
        // A previous draft of ConcatStream's Dispose closed the inner input too, which would
        // surface as ObjectDisposedException at the call site's outer `using` boundary on
        // some runtimes / observers that re-touch the stream after import.
        using var stream = BuildTarGz(new[]
        {
            ("client.ovpn", "remote firebox.example.com 443"),
            ("ca.crt", "ca"),
            ("client.crt", "cert"),
            ("client.pem", "key"),
        });

        _ = await WatchguardWgsslImporter.ImportAsync(stream);

        // CanRead / CanSeek throw on disposed MemoryStream — accessing them as a smoke test
        // is enough to detect a double-dispose without touching the bytes.
        Assert.True(stream.CanRead);
        Assert.True(stream.CanSeek);
    }

    [Fact]
    public async Task ImportAsync_RejectsGzipBomb()
    {
        // Hostile bundle: small on disk, expands to far more than the 64 MiB cap. Guards
        // against the worst-case gzip ratio (~1000:1 on repetitive payloads). The cap is
        // applied on the DECOMPRESSED byte count, so the bomb trips it before the tar reader
        // ever attempts to allocate per-entry buffers.
        var giant = new string('A', 80 * 1024 * 1024); // 80 MiB plaintext
        using var rawTar = BuildTar(new[]
        {
            ("client.ovpn", "remote firebox 443"),
            ("ca.crt", giant),
            ("client.crt", "cert"),
            ("client.pem", "key"),
        });
        using var gz = new MemoryStream();
        using (var compressor = new GZipStream(gz, CompressionLevel.Optimal, leaveOpen: true))
        {
            rawTar.CopyTo(compressor);
        }
        gz.Position = 0;

        await Assert.ThrowsAsync<InvalidDataException>(() => WatchguardWgsslImporter.ImportAsync(gz));
    }

    /// <summary>Build a minimal POSIX-ustar tar archive in memory containing the named files.</summary>
    private static MemoryStream BuildTar((string Name, string Content)[] files)
    {
        var ms = new MemoryStream();
        using (var writer = new TarWriter(ms, TarEntryFormat.Ustar, leaveOpen: true))
        {
            foreach (var (name, content) in files)
            {
                var bytes = Encoding.UTF8.GetBytes(content);
                var entry = new UstarTarEntry(TarEntryType.RegularFile, name)
                {
                    DataStream = new MemoryStream(bytes),
                };
                writer.WriteEntry(entry);
            }
        }
        ms.Position = 0;
        return ms;
    }

    /// <summary>Same as <see cref="BuildTar"/> but the bytes are gzip-compressed — matches the
    /// real-world .wgssl bundle shape.</summary>
    private static MemoryStream BuildTarGz((string Name, string Content)[] files)
    {
        using var raw = BuildTar(files);
        var gz = new MemoryStream();
        using (var compressor = new GZipStream(gz, CompressionLevel.Optimal, leaveOpen: true))
        {
            raw.CopyTo(compressor);
        }
        gz.Position = 0;
        return gz;
    }
}

using System.Formats.Tar;
using System.IO;
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
}

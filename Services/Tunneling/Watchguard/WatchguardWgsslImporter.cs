using System;
using System.Collections.Generic;
using System.Formats.Tar;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling.Watchguard;

/// <summary>
/// Parses the `.wgssl` bundle a Firebox emits ("Download your Mobile VPN with SSL profile")
/// into a partially-populated <see cref="WatchguardSettings"/>. The bundle is a plain tar
/// archive containing client.ovpn, ca.crt, client.crt, client.pem at the archive root.
///
/// Server / Port are inferred from the `remote &lt;host&gt; &lt;port&gt;` directive in client.ovpn.
/// The Username/Password fields are NOT populated — the user types those into the dialog
/// after import, matching the official WatchGuard client UX.
/// </summary>
public static class WatchguardWgsslImporter
{
    private const string ClientOvpnEntry = "client.ovpn";
    private const string CaEntry = "ca.crt";
    private const string CertEntry = "client.crt";
    private const string KeyEntry = "client.pem";

    /// <summary>
    /// Per-entry size cap. A genuine .wgssl bundle's largest entry (the PEM-encoded CA chain)
    /// is ~10 KiB on a fresh Firebox. 1 MiB leaves three orders of magnitude of headroom for
    /// hand-customized CAs while keeping a malicious or accidentally-huge pick (the dialog's
    /// file picker filter includes `*`) from allocating gigabytes on the UI thread.
    /// </summary>
    private const int MaxEntrySizeBytes = 1 * 1024 * 1024;

    /// <summary>
    /// Total-archive entry-count cap. The .wgssl format has exactly four entries; a real bundle
    /// stays under ~10. A hostile or accidentally-mis-picked archive (e.g. a backup tar with
    /// 100k files) would otherwise bypass MaxEntrySizeBytes by spreading the payload across many
    /// small entries — each fits under 1 MiB but the aggregate dictionary heap grows unbounded.
    /// Cap at 64 to allow generous headroom while keeping worst-case aggregate at &lt;= 64 MiB.
    /// </summary>
    private const int MaxEntryCount = 64;

    public static async Task<WatchguardSettings> ImportAsync(Stream wgsslStream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(wgsslStream);

        // Read the whole archive into a dictionary so we can stage the four required entries
        // in any order — the tar format is single-pass, but the file layout the Firebox emits
        // isn't guaranteed alphabetical and we don't want a "missing entry" error to depend on
        // which file the archive lists last.
        var entries = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var seenEntryCount = 0;
        await using var reader = new TarReader(wgsslStream, leaveOpen: true);
        while (await reader.GetNextEntryAsync(copyData: false, cancellationToken).ConfigureAwait(false) is { } entry)
        {
            // Count EVERY tar header — including directories, symlinks, and zero-length regular
            // files — so a hostile archive can't bypass the cap by spamming non-RegularFile
            // entries that the filters below would otherwise skip silently.
            seenEntryCount++;
            if (seenEntryCount > MaxEntryCount)
            {
                throw new InvalidDataException(
                    $"The .wgssl bundle contains more than {MaxEntryCount} entries — refusing to load. " +
                    "A genuine Firebox export has 4 entries.");
            }

            if (entry.EntryType != TarEntryType.RegularFile && entry.EntryType != TarEntryType.V7RegularFile)
                continue;

            // Some `.wgssl` archives prepend "./" to entry names; strip leading "./" so the
            // lookups below work regardless of how the archive was generated.
            var name = entry.Name;
            if (name.StartsWith("./", StringComparison.Ordinal)) name = name[2..];

            if (entry.DataStream is null) continue;

            // Reject oversized entries before allocating anything large. entry.Length is the
            // declared tar header length; trusting it is fine because we additionally cap the
            // CopyToAsync at the same limit via a wrapping stream below — so even a header
            // that lies about its size can't exceed the cap.
            if (entry.Length > MaxEntrySizeBytes)
            {
                throw new InvalidDataException(
                    $"The .wgssl bundle entry '{name}' is {entry.Length} bytes — exceeds the {MaxEntrySizeBytes}-byte safety cap. " +
                    "Refusing to load.");
            }

            using var ms = new MemoryStream();
            await CopyWithCapAsync(entry.DataStream, ms, MaxEntrySizeBytes, cancellationToken).ConfigureAwait(false);
            entries[name] = Encoding.UTF8.GetString(ms.ToArray());
        }

        var missing = new List<string>();
        if (!entries.ContainsKey(ClientOvpnEntry)) missing.Add(ClientOvpnEntry);
        if (!entries.ContainsKey(CaEntry)) missing.Add(CaEntry);
        if (!entries.ContainsKey(CertEntry)) missing.Add(CertEntry);
        if (!entries.ContainsKey(KeyEntry)) missing.Add(KeyEntry);
        if (missing.Count > 0)
        {
            throw new InvalidDataException(
                $"The .wgssl bundle is missing required file(s): {string.Join(", ", missing)}. " +
                "Re-download the Mobile VPN with SSL profile from the Firebox.");
        }

        var (server, port) = ParseRemote(entries[ClientOvpnEntry]);

        return new WatchguardSettings
        {
            Server = server,
            Port = port,
            // Username/Password intentionally left blank — the user types them into the dialog
            // after import. The Firebox doesn't ship credentials inside .wgssl.
            CaPem = entries[CaEntry].Trim(),
            ClientCertPem = entries[CertEntry].Trim(),
            ClientKeyPem = entries[KeyEntry].Trim(),
        };
    }

    /// <summary>
    /// Streams from <paramref name="source"/> into <paramref name="destination"/> and throws
    /// <see cref="InvalidDataException"/> once the total copied byte count exceeds
    /// <paramref name="capBytes"/>. Guards against tar entries whose declared length under-
    /// reports the actual payload (the entry.Length check is advisory; the actual stream may
    /// run longer if the archive is malformed or hostile).
    /// </summary>
    private static async Task CopyWithCapAsync(Stream source, Stream destination, int capBytes, CancellationToken ct)
    {
        var buffer = new byte[8192];
        long total = 0;
        int read;
        while ((read = await source.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false)) > 0)
        {
            total += read;
            if (total > capBytes)
            {
                throw new InvalidDataException(
                    $"A .wgssl entry exceeded the {capBytes}-byte safety cap during read. Refusing to load.");
            }
            await destination.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
        }
    }

    private static readonly char[] s_directiveSeparators = { ' ', '\t' };

    private static (string Server, int Port) ParseRemote(string clientOvpn)
    {
        foreach (var rawLine in clientOvpn.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith(';')) continue;
            // OpenVPN config tokens can be separated by space OR tab; old .wgssl archives have
            // been seen using tabs. Use a unified whitespace split so both work.
            if (!StartsWithDirective(line, "remote")) continue;

            // remote <host> [<port>] [<proto>] — port and proto are optional; default port for
            // WatchGuard SSL VPN is 443 even if omitted from the directive.
            var parts = line.Split(s_directiveSeparators, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) continue;
            var server = parts[1].Trim();
            var port = 443;
            if (parts.Length >= 3 && int.TryParse(parts[2], out var parsedPort) && parsedPort is >= 1 and <= 65535)
                port = parsedPort;
            return (server, port);
        }

        throw new InvalidDataException(
            "The embedded client.ovpn has no 'remote <host> <port>' directive — can't infer the gateway address.");
    }

    private static bool StartsWithDirective(string line, string directive)
    {
        if (line.Length <= directive.Length) return false;
        if (!line.StartsWith(directive, StringComparison.OrdinalIgnoreCase)) return false;
        var next = line[directive.Length];
        return next == ' ' || next == '\t';
    }
}

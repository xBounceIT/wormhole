using System;
using System.Buffers;
using System.Collections.Generic;
using System.Formats.Tar;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling.Watchguard;

/// <summary>
/// Parses the `.wgssl` bundle a Firebox emits ("Download your Mobile VPN with SSL profile")
/// into a partially-populated <see cref="WatchguardSettings"/>. The bundle is a gzip-compressed
/// tar archive (real-world Firebox exports; the vendor workflow itself renames `.wgssl` to
/// `.tgz` before extracting) containing client.ovpn, ca.crt, client.crt, client.pem at the
/// archive root. Raw uncompressed tars are also accepted as a fallback so hand-prepared
/// bundles still work.
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

    /// <summary>
    /// Total-archive byte cap on the (post-decompression) tar stream. Protects against gzip-bomb
    /// inputs where a tiny .wgssl expands to gigabytes — gzip ratios of 1000:1 are routine on
    /// repetitive payloads. The MaxEntryCount × MaxEntrySizeBytes product (64 MiB) is the natural
    /// upper bound for legitimate content, and we apply it to the WHOLE archive so the tar reader
    /// can't be tricked into walking a huge decompressed stream looking for entries.
    /// </summary>
    private const long MaxDecompressedBytes = (long)MaxEntryCount * MaxEntrySizeBytes;

    public static async Task<WatchguardSettings> ImportAsync(Stream wgsslStream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(wgsslStream);

        // The .wgssl file emitted by a Firebox is a GZIPPED tar (the vendor extraction workflow
        // renames it to `.tgz`). Detect the gzip magic (0x1f 0x8b) and transparently decompress
        // before parsing as tar. Older hand-prepared bundles are raw tar — accept those too so
        // the importer doesn't silently break for power users.
        //
        // The peeked bytes are then concatenated with the remainder of the original stream so we
        // don't require a seekable input (FileStream from the picker is, but the importer is a
        // public API and a non-seekable upstream stream could be passed in tests / future code).
        var tarStream = await DetectAndOpenTarStreamAsync(wgsslStream, cancellationToken).ConfigureAwait(false);

        // Read the whole archive into a dictionary so we can stage the four required entries
        // in any order — the tar format is single-pass, but the file layout the Firebox emits
        // isn't guaranteed alphabetical and we don't want a "missing entry" error to depend on
        // which file the archive lists last.
        var entries = new Dictionary<string, string>(capacity: 4, StringComparer.OrdinalIgnoreCase);
        var seenEntryCount = 0;
        await using var _tarOwner = tarStream;
        await using var reader = new TarReader(tarStream, leaveOpen: true);
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

            var initialCapacity = entry.Length > 0 ? (int)entry.Length : 0;
            using var ms = initialCapacity == 0 ? new MemoryStream() : new MemoryStream(initialCapacity);
            await CopyWithCapAsync(entry.DataStream, ms, MaxEntrySizeBytes, cancellationToken).ConfigureAwait(false);
            entries[name] = DecodeUtf8(ms);
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
            ProfileOvpn = entries[ClientOvpnEntry].Trim(),
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
        var rented = ArrayPool<byte>.Shared.Rent(8192);
        try
        {
            var buffer = rented.AsMemory(0, 8192);
            long total = 0;
            int read;
            while ((read = await source.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
            {
                total += read;
                if (total > capBytes)
                {
                    throw new InvalidDataException(
                        $"A .wgssl entry exceeded the {capBytes}-byte safety cap during read. Refusing to load.");
                }
                await destination.WriteAsync(buffer[..read], ct).ConfigureAwait(false);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private static string DecodeUtf8(MemoryStream stream)
    {
        return Encoding.UTF8.GetString(stream.GetBuffer(), 0, checked((int)stream.Length));
    }

    private static (string Server, int Port) ParseRemote(string clientOvpn)
    {
        var remaining = clientOvpn.AsSpan();
        while (true)
        {
            ReadOnlySpan<char> rawLine;
            var newline = remaining.IndexOf('\n');
            if (newline < 0)
            {
                rawLine = remaining;
                remaining = ReadOnlySpan<char>.Empty;
            }
            else
            {
                rawLine = remaining[..newline];
                remaining = remaining[(newline + 1)..];
            }

            var line = rawLine.Trim();
            if (line.Length == 0 || line[0] == '#' || line[0] == ';')
            {
                if (remaining.IsEmpty) break;
                continue;
            }

            // OpenVPN config tokens can be separated by space OR tab; old .wgssl archives have
            // been seen using tabs. Parse token spans directly so large configs don't allocate
            // one string per line while we search for the remote directive.
            if (!TryConsumeDirective(line, "remote", out var rest))
            {
                if (remaining.IsEmpty) break;
                continue;
            }

            // remote <host> [<port>] [<proto>] — port and proto are optional; default port for
            // WatchGuard SSL VPN is 443 even if omitted from the directive.
            if (!TryReadToken(rest, out var server, out rest))
            {
                if (remaining.IsEmpty) break;
                continue;
            }

            var port = 443;
            if (TryReadToken(rest, out var portToken, out _) &&
                int.TryParse(portToken, out var parsedPort) &&
                parsedPort is >= 1 and <= 65535)
            {
                port = parsedPort;
            }
            return (server.ToString(), port);
        }

        throw new InvalidDataException(
            "The embedded client.ovpn has no 'remote <host> <port>' directive — can't infer the gateway address.");
    }

    private static bool TryConsumeDirective(
        ReadOnlySpan<char> line,
        string directive,
        out ReadOnlySpan<char> rest)
    {
        if (line.Length <= directive.Length ||
            !line[..directive.Length].Equals(directive, StringComparison.OrdinalIgnoreCase))
        {
            rest = default;
            return false;
        }

        var next = line[directive.Length];
        if (next != ' ' && next != '\t')
        {
            rest = default;
            return false;
        }

        rest = TrimTokenWhitespace(line[(directive.Length + 1)..]);
        return true;
    }

    private static bool TryReadToken(
        ReadOnlySpan<char> value,
        out ReadOnlySpan<char> token,
        out ReadOnlySpan<char> rest)
    {
        value = TrimTokenWhitespace(value);
        if (value.IsEmpty)
        {
            token = default;
            rest = default;
            return false;
        }

        var end = 0;
        while (end < value.Length && value[end] != ' ' && value[end] != '\t')
        {
            end++;
        }

        token = value[..end];
        rest = value[end..];
        return true;
    }

    private static ReadOnlySpan<char> TrimTokenWhitespace(ReadOnlySpan<char> value)
    {
        var start = 0;
        while (start < value.Length && (value[start] == ' ' || value[start] == '\t'))
        {
            start++;
        }

        return value[start..];
    }

    /// <summary>
    /// Peeks the first two bytes of <paramref name="input"/>; if they match the gzip magic
    /// (0x1f 0x8b) wraps the stream in <see cref="GZipStream"/> + a byte-count cap, otherwise
    /// returns a stream that yields the peeked bytes followed by the rest of the input. The
    /// returned stream must be disposed by the caller (it owns the wrappers; the original
    /// <paramref name="input"/> is left to the caller).
    /// </summary>
    private static async Task<Stream> DetectAndOpenTarStreamAsync(Stream input, CancellationToken cancellationToken)
    {
        var magic = new byte[2];
        var read = 0;
        while (read < magic.Length)
        {
            var n = await input.ReadAsync(magic.AsMemory(read, magic.Length - read), cancellationToken).ConfigureAwait(false);
            if (n == 0) break;
            read += n;
        }

        if (read < 2)
        {
            // Short input — not a tar OR a gzip; let TarReader produce the clearest error.
            return new MemoryStream(magic, 0, read, writable: false);
        }

        // Splice peeked bytes back in front of the rest of the input so downstream readers see
        // the original byte sequence. Works for non-seekable streams (the picker's stream IS
        // seekable but the importer is a public API and we don't want to require it).
        Stream rejoined = new ConcatStream(new MemoryStream(magic, writable: false), input);

        var isGzip = magic[0] == 0x1f && magic[1] == 0x8b;
        if (!isGzip) return rejoined;

        // Wrap in GZipStream, then in a length-capped reader so a gzip bomb (small input, huge
        // expansion) trips the cap before the tar reader walks past safe limits.
        var gz = new GZipStream(rejoined, CompressionMode.Decompress, leaveOpen: false);
        return new CappedReadStream(gz, MaxDecompressedBytes);
    }

    /// <summary>
    /// Read-only stream that concatenates two underlying streams. Disposes <c>_first</c>
    /// (which we always own — it's the peeked-bytes MemoryStream) but NOT <c>_second</c>
    /// (the original input is caller-owned per ImportAsync's contract; the caller passed it
    /// in via <c>using</c> and expects to dispose it themselves). Used to splice peeked magic
    /// bytes back in front of the original input.
    /// </summary>
    private sealed class ConcatStream : Stream
    {
        private readonly Stream _first;
        private readonly Stream _second;
        private bool _firstDone;

        public ConcatStream(Stream first, Stream second) { _first = first; _second = second; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (!_firstDone)
            {
                var n = _first.Read(buffer, offset, count);
                if (n > 0) return n;
                _firstDone = true;
            }
            return _second.Read(buffer, offset, count);
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (!_firstDone)
            {
                var n = await _first.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (n > 0) return n;
                _firstDone = true;
            }
            return await _second.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        }

        protected override void Dispose(bool disposing)
        {
            // _first is the peeked-bytes MemoryStream we created internally — we own it.
            // _second is the caller's input — leave it alone so the caller's `using` scope
            // disposes it exactly once (avoids double-dispose + matches the documented
            // ownership semantics of DetectAndOpenTarStreamAsync).
            if (disposing)
            {
                try { _first.Dispose(); } catch { /* best effort */ }
            }
            base.Dispose(disposing);
        }
    }

    /// <summary>
    /// Read-only stream that throws <see cref="InvalidDataException"/> once the cumulative byte
    /// count read exceeds <see cref="_cap"/>. Disposes the wrapped stream on Dispose.
    /// </summary>
    private sealed class CappedReadStream : Stream
    {
        private readonly Stream _inner;
        private readonly long _cap;
        private long _read;

        public CappedReadStream(Stream inner, long cap) { _inner = inner; _cap = cap; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => _read; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count)
        {
            var n = _inner.Read(buffer, offset, count);
            Account(n);
            return n;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var n = await _inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            Account(n);
            return n;
        }

        private void Account(int n)
        {
            if (n <= 0) return;
            _read += n;
            if (_read > _cap)
            {
                throw new InvalidDataException(
                    $"The .wgssl bundle expands to more than {_cap} bytes when decompressed — refusing to load (possible gzip bomb).");
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) { try { _inner.Dispose(); } catch { /* best effort */ } }
            base.Dispose(disposing);
        }
    }
}

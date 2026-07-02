using Wormhole.Data.Repositories;
using Wormhole.Models;

namespace Wormhole.Services.Bitwarden;

public sealed class BitwardenCredentialCatalogService : IBitwardenCredentialCatalogService
{
    private static readonly ProtocolType[] VirtualProtocols = [ProtocolType.Ssh, ProtocolType.Rdp, ProtocolType.Vnc];

    private readonly ICredentialRepository _credentials;
    private readonly IBitwardenCredentialCacheRepository _cache;
    private readonly IAppSettingsService _settings;

    public BitwardenCredentialCatalogService(
        ICredentialRepository credentials,
        IBitwardenCredentialCacheRepository cache,
        IAppSettingsService settings)
    {
        _credentials = credentials;
        _cache = cache;
        _settings = settings;
    }

    public async Task<IReadOnlyList<CredentialProfile>> GetCredentialPageProfilesAsync(CancellationToken cancellationToken = default)
    {
        var local = await _credentials.GetAllAsync(cancellationToken).ConfigureAwait(false);
        if (!_settings.Current.EnableBitwardenVault)
        {
            return local;
        }

        var entries = await _cache.GetAllAsync(cancellationToken).ConfigureAwait(false);
        var linkedItemIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var credential in local)
        {
            if (credential.SecretProvider == CredentialSecretProvider.Bitwarden &&
                !string.IsNullOrWhiteSpace(credential.BitwardenItemId))
            {
                linkedItemIds.Add(credential.BitwardenItemId.Trim());
            }
        }

        var profiles = new List<CredentialProfile>(local.Count + entries.Count);
        profiles.AddRange(local);
        foreach (var entry in entries)
        {
            if (linkedItemIds.Contains(entry.ItemId)) continue;
            profiles.Add(Project(entry, ProtocolType.Ssh, pageProjection: true));
        }
        profiles.Sort((a, b) => string.CompareOrdinal(a.Name, b.Name));
        return profiles;
    }

    public async Task<IReadOnlyList<CredentialProfile>> GetPickerProfilesAsync(CancellationToken cancellationToken = default)
    {
        var local = await _credentials.GetAllAsync(cancellationToken).ConfigureAwait(false);
        if (!_settings.Current.EnableBitwardenVault)
        {
            return local;
        }

        var entries = await _cache.GetAllAsync(cancellationToken).ConfigureAwait(false);
        var profiles = new List<CredentialProfile>(local.Count + entries.Count * VirtualProtocols.Length);
        profiles.AddRange(local);
        AddVirtualProfiles(profiles, local, entries, protocolFilter: null);
        profiles.Sort((a, b) => string.CompareOrdinal(a.Name, b.Name));
        return profiles;
    }

    public async Task<IReadOnlyList<CredentialProfile>> GetProfilesForProtocolAsync(
        ProtocolType protocol,
        CancellationToken cancellationToken = default)
    {
        var local = await _credentials.GetAllAsync(cancellationToken).ConfigureAwait(false);
        var localForProtocol = local.Where(c => c.Protocol == protocol).ToList();
        if (!_settings.Current.EnableBitwardenVault || protocol is not (ProtocolType.Ssh or ProtocolType.Rdp or ProtocolType.Vnc))
        {
            return localForProtocol;
        }

        var entries = await _cache.GetAllAsync(cancellationToken).ConfigureAwait(false);
        AddVirtualProfiles(localForProtocol, local, entries, protocol);
        localForProtocol.Sort((a, b) => string.CompareOrdinal(a.Name, b.Name));
        return localForProtocol;
    }

    public async Task<CredentialProfile?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var local = await _credentials.GetByIdAsync(id, cancellationToken).ConfigureAwait(false);
        if (local is not null || !_settings.Current.EnableBitwardenVault)
        {
            return local;
        }

        var entries = await _cache.GetAllAsync(cancellationToken).ConfigureAwait(false);
        foreach (var entry in entries)
        {
            foreach (var protocol in VirtualProtocols)
            {
                if (entry.GetCredentialId(protocol) == id)
                {
                    return Project(entry, protocol, pageProjection: false);
                }
            }
        }
        return null;
    }

    private static void AddVirtualProfiles(
        List<CredentialProfile> target,
        IReadOnlyList<CredentialProfile> local,
        IReadOnlyList<BitwardenCredentialCacheEntry> entries,
        ProtocolType? protocolFilter)
    {
        var linked = new HashSet<(ProtocolType Protocol, string ItemId)>();
        foreach (var credential in local)
        {
            if (credential.SecretProvider != CredentialSecretProvider.Bitwarden) continue;
            if (string.IsNullOrWhiteSpace(credential.BitwardenItemId)) continue;
            linked.Add((credential.Protocol, credential.BitwardenItemId.Trim()));
        }

        foreach (var entry in entries)
        {
            foreach (var protocol in VirtualProtocols)
            {
                if (protocolFilter is { } filter && protocol != filter) continue;
                if (linked.Contains((protocol, entry.ItemId))) continue;
                target.Add(Project(entry, protocol, pageProjection: false));
            }
        }
    }

    private static CredentialProfile Project(
        BitwardenCredentialCacheEntry entry,
        ProtocolType protocol,
        bool pageProjection)
    {
        BitwardenVirtualCredentialIds.EnsureIds(entry);
        return new CredentialProfile
        {
            Id = entry.GetCredentialId(protocol),
            Name = entry.Name,
            Username = entry.Username,
            Protocol = protocol,
            Kind = CredentialKind.Password,
            SecretProvider = CredentialSecretProvider.Bitwarden,
            BitwardenItemId = entry.ItemId,
            BitwardenItemName = entry.Name,
            BitwardenFieldPath = BitwardenDefaults.PasswordFieldPath,
            CreatedAt = entry.UpdatedAtUtc.UtcDateTime,
            IsVirtualBitwarden = true,
        };
    }
}

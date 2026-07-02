using System.Security.Cryptography;
using System.Text;
using Wormhole.Models;

namespace Wormhole.Services.Bitwarden;

public static class BitwardenVirtualCredentialIds
{
    private const string Namespace = "wormhole-bitwarden-virtual-credential-v1";

    public static Guid ForItem(string itemId, ProtocolType protocol)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(itemId);
        var material = $"{Namespace}:{protocol}:{itemId.Trim()}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(material));
        return new Guid(hash[..16]);
    }

    public static void EnsureIds(BitwardenCredentialCacheEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        if (entry.SshCredentialId == Guid.Empty)
        {
            entry.SshCredentialId = ForItem(entry.ItemId, ProtocolType.Ssh);
        }
        if (entry.RdpCredentialId == Guid.Empty)
        {
            entry.RdpCredentialId = ForItem(entry.ItemId, ProtocolType.Rdp);
        }
        if (entry.VncCredentialId == Guid.Empty)
        {
            entry.VncCredentialId = ForItem(entry.ItemId, ProtocolType.Vnc);
        }
    }
}

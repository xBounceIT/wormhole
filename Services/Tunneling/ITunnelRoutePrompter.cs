using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling;

/// <summary>
/// Resolves whether a single connect attempt should go through the profile's configured VPN
/// tunnel or connect directly, optionally asking the user.
/// <para>
/// When the <see cref="AppSettings.PromptBeforeTunnelConnect"/> setting is on and the profile
/// is configured for a tunnel, the user is prompted to pick tunnel-vs-direct for this attempt.
/// This covers targets that are reachable directly on some networks (office LAN) and only
/// through the VPN on others (remote) — without forcing the user to edit the connection's
/// tunnel config every time they move networks.
/// </para>
/// </summary>
public interface ITunnelRoutePrompter
{
    /// <summary>
    /// Returns the profile to use for this connect attempt. When the user chooses to connect
    /// directly, the returned profile has <see cref="ConnectionProfile.TunnelEnabled"/> forced
    /// to <c>false</c> so the normal tunnel-establish path becomes a no-op. Returns the input
    /// profile unchanged when prompting is disabled or the profile has no tunnel. Returns
    /// <c>null</c> when the user cancels the prompt (caller should abort the connect silently).
    /// </summary>
    Task<ConnectionProfile?> ResolveRouteAsync(ConnectionProfile profile, CancellationToken cancellationToken);
}

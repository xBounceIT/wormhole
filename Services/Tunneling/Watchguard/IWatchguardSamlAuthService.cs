using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling.Watchguard;

public interface IWatchguardSamlAuthService
{
    Task<WatchguardSamlAuthResult> AuthenticateAsync(
        WatchguardSettings settings,
        string configName,
        CancellationToken cancellationToken);
}

public sealed record WatchguardSamlAuthResult(
    string Username,
    string Token,
    IReadOnlyList<Cookie> Cookies);

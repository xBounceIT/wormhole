using System;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling.Fortinet;

public interface IFortinetSamlAuthService
{
    Task<FortinetSamlAuthResult> AuthenticateAsync(
        FortinetSettings settings,
        string configName,
        CancellationToken cancellationToken);
}

public sealed record FortinetSamlAuthResult(string? AuthId, string? SvpnCookie)
{
    public static FortinetSamlAuthResult FromAuthId(string authId) =>
        new(authId, SvpnCookie: null);

    public static FortinetSamlAuthResult FromSvpnCookie(string cookie) =>
        new(AuthId: null, cookie);

    public bool HasExactlyOneCredential =>
        !string.IsNullOrWhiteSpace(AuthId) ^ !string.IsNullOrWhiteSpace(SvpnCookie);
}

public interface IFortinetExternalBrowserLauncher
{
    void Open(Uri uri);
}

using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;

namespace Wormhole.Services.Tunneling.AzureVpn;

/// <summary>
/// Outcome of a Microsoft Entra ID token acquisition for an Azure VPN tunnel.
/// <see cref="AccessToken"/> is the bearer JWT the gateway validates (sent as the OpenVPN
/// <c>auth-user-pass</c> password); <see cref="RefreshToken"/>, when granted
/// (<c>offline_access</c> scope), lets the next connect skip the interactive popup. Both are
/// secrets — never log them.
/// </summary>
public sealed record AzureVpnTokenResult(string AccessToken, string? RefreshToken);

/// <summary>
/// Interactive Microsoft Entra ID sign-in for Azure VPN tunnels — the separate Office 365 popup
/// the native Azure VPN Client shows. Implementations own the UI (a WebView2 window running the
/// OAuth2 authorization-code + PKCE flow) and the code-for-token exchange.
/// </summary>
public interface IAzureVpnAuthService
{
    /// <summary>
    /// Opens the sign-in popup and runs the full interactive flow. Throws
    /// <see cref="System.InvalidOperationException"/> when the user closes the window without
    /// completing sign-in, and <see cref="System.OperationCanceledException"/> on token cancel.
    /// </summary>
    Task<AzureVpnTokenResult> AuthenticateInteractiveAsync(
        AzureVpnSettings settings,
        string configName,
        CancellationToken cancellationToken);
}

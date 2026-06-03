namespace Wormhole.Models;

/// <summary>
/// How a <see cref="StormshieldSettings"/> tunnel obtains its OpenVPN profile, mirroring the two
/// modes the official Stormshield SSL VPN Client exposes:
///
/// <list type="bullet">
///   <item><see cref="Automatic"/> — the vendor's "Stormshield mode": the client authenticates to
///   the SNS firewall captive portal over HTTPS (username/password [+ OTP], or client certificate)
///   and securely retrieves its per-user OpenVPN profile (with inline CA / client cert / key) on
///   every connect. This is the native handshake.</item>
///   <item><see cref="Import"/> — the vendor's "OpenVPN mode": the user pastes a static <c>.ovpn</c>
///   they already downloaded from the firewall's <c>/auth</c> "Personal data" page. No HTTPS
///   pre-auth happens; OpenVPN does mutual TLS + auth-user-pass directly.</item>
/// </list>
///
/// Stored as an int in the DPAPI secret blob; values are pinned so reordering never silently
/// reinterprets an existing tunnel.
/// </summary>
public enum StormshieldConnectionMode
{
    Automatic = 0,
    Import = 1,
}

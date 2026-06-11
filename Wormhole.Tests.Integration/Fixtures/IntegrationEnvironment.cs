using System;
using System.IO;

namespace Wormhole.Tests.Integration.Fixtures;

/// <summary>
/// Reads env vars set by the CI <c>vpn-integration</c> job (and by developers running
/// the bootstrap script locally) so each test can decide whether the supporting infra
/// is up. Tests <c>Skip.IfNot(...Configured, ...)</c> rather than asserting, so the
/// project stays runnable as a no-op outside a configured environment.
///
/// Env contract (mirrored in <c>tests/vpn-fixtures/README.md</c> and the CI workflow):
///   WORMHOLE_WGPROXY_PATH               absolute path to the wormhole-wgproxy binary
///   WORMHOLE_WG_CLIENT_CONFIG           absolute path to a JSON file matching WireGuardSidecarConfig
///   WORMHOLE_WG_ECHO_TARGET             IP/hostname of the echo server reached through the tunnel (default 10.20.0.10)
///   WORMHOLE_WG_ECHO_PORT               TCP port of the echo server               (default 7777)
///   WORMHOLE_OVPNPROXY_PATH             absolute path to the wormhole-ovpnproxy binary
///   WORMHOLE_OPENVPN_CLIENT_PROFILE     absolute path to a client .ovpn profile
///   WORMHOLE_OPENVPN_ECHO_TARGET        IP/hostname of the echo server reached through the tunnel (default 10.20.0.10)
///   WORMHOLE_OPENVPN_ECHO_PORT          TCP port of the echo server               (default 7777)
///   WORMHOLE_OPENVPN_ECHO_HOSTNAME      DNS name of the echo server, resolvable only via the
///                                       server-pushed in-tunnel DNS               (default echo.vpn.test)
/// </summary>
internal static class IntegrationEnvironment
{
    public static string? WgProxyPath => Env("WORMHOLE_WGPROXY_PATH");
    public static string? WgClientConfigPath => Env("WORMHOLE_WG_CLIENT_CONFIG");
    // The echo-target container sits on the shared docker bridge at 10.20.0.10
    // (see tests/vpn-fixtures/docker-compose.yml). Both VPNs route the bridge
    // subnet through the tunnel, so this address is reachable only after a
    // successful handshake — the load-bearing test signal. The earlier in-tunnel
    // /24 (10.13.13.0 / 10.8.0.0) addresses had no listener, so the test would
    // time out even with a perfectly healthy tunnel.
    public static string WgEchoTarget => Env("WORMHOLE_WG_ECHO_TARGET") ?? "10.20.0.10";
    public static int WgEchoPort => ParsePort("WORMHOLE_WG_ECHO_PORT", 7777);

    public static string? OvpnProxyPath => Env("WORMHOLE_OVPNPROXY_PATH");
    public static string? OvpnClientProfilePath => Env("WORMHOLE_OPENVPN_CLIENT_PROFILE");
    public static string OvpnEchoTarget => Env("WORMHOLE_OPENVPN_ECHO_TARGET") ?? "10.20.0.10";
    public static int OvpnEchoPort => ParsePort("WORMHOLE_OPENVPN_ECHO_PORT", 7777);
    // Resolvable ONLY by the fixture dnsmasq container (10.20.0.53), which the OpenVPN
    // server pushes as `dhcp-option DNS`. Dialing this name through SOCKS5 proves the
    // sidecar plumbed the pushed DNS into its netstack resolver — the OS resolver
    // cannot answer it, so a pass can't come from a resolution-path leak either.
    public static string OvpnEchoHostname => Env("WORMHOLE_OPENVPN_ECHO_HOSTNAME") ?? "echo.vpn.test";

    public static bool WireGuardConfigured =>
        !string.IsNullOrEmpty(WgProxyPath) && File.Exists(WgProxyPath) &&
        !string.IsNullOrEmpty(WgClientConfigPath) && File.Exists(WgClientConfigPath);

    public static bool OpenVpnConfigured =>
        !string.IsNullOrEmpty(OvpnProxyPath) && File.Exists(OvpnProxyPath) &&
        !string.IsNullOrEmpty(OvpnClientProfilePath) && File.Exists(OvpnClientProfilePath);

    private static string? Env(string name)
    {
        var v = Environment.GetEnvironmentVariable(name);
        return string.IsNullOrWhiteSpace(v) ? null : v;
    }

    private static int ParsePort(string name, int fallback) =>
        int.TryParse(Env(name), out var p) && p is > 0 and < 65536 ? p : fallback;
}

using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Wormhole.Models;
using Wormhole.Services.Tunneling.Fortinet;
using Xunit;

namespace Wormhole.Tests.Services.Tunneling;

public class FortinetSamlProtocolTests
{
    [Fact]
    public void LegacyJson_UsesBackwardCompatibleSsoDefaults()
    {
        var settings = JsonSerializer.Deserialize<FortinetSettings>(
            """{"Host":"vpn.example.com","Port":443,"Username":"alice","Password":"secret"}""")!;

        Assert.False(settings.UseSingleSignOn);
        Assert.True(settings.UseExternalBrowser);
        Assert.Equal(FortinetSettings.DefaultSamlRedirectPort, settings.SamlRedirectPort);
    }

    [Theory]
    [InlineData(false, "ExampleRealm")]
    [InlineData(true, null)]
    public void SanitizedForAuthenticationMode_ClearsInactiveCredentialsWithoutMutatingSource(
        bool useExternalBrowser,
        string? expectedRealm)
    {
        var source = NewSsoSettings(useExternalBrowser);
        source.Username = "legacy-user";
        source.Password = "legacy-password";
        source.TotpSecret = "legacy-totp";
        source.Realm = "ExampleRealm";

        var sanitized = source.SanitizedForAuthenticationMode();

        Assert.NotSame(source, sanitized);
        Assert.Empty(sanitized.Username);
        Assert.Empty(sanitized.Password);
        Assert.Null(sanitized.TotpSecret);
        Assert.Equal(expectedRealm, sanitized.Realm);
        Assert.Equal("legacy-user", source.Username);
        Assert.Equal("legacy-password", source.Password);
        Assert.Equal("legacy-totp", source.TotpSecret);
    }

    [Fact]
    public void BuildStartUri_ExternalBrowserUsesRedirectFlowAndCustomGatewayPort()
    {
        var settings = NewSsoSettings(useExternalBrowser: true);
        settings.Port = 10443;

        var uri = FortinetSamlProtocol.BuildStartUri(settings);

        Assert.Equal("vpn.example.com", uri.Host);
        Assert.Equal(10443, uri.Port);
        Assert.Equal("/remote/saml/start", uri.AbsolutePath);
        Assert.Equal("?redirect=1", uri.Query);
    }

    [Fact]
    public void BuildStartUri_EmbeddedBrowserCarriesRealm()
    {
        var settings = NewSsoSettings(useExternalBrowser: false);
        settings.Realm = "Example Realm";

        var uri = FortinetSamlProtocol.BuildStartUri(settings);

        Assert.Equal("/remote/saml/start", uri.AbsolutePath);
        Assert.Equal("?realm=Example%20Realm", uri.Query);
    }

    [Fact]
    public void SelectSvpnCookieValue_RequiresHttpOnlyCookieAndExactName()
    {
        var cookies = new[]
        {
            ("SVPNCOOKIE", "script-visible", false),
            ("svpncookie", "wrong-name", true),
            ("SVPNCOOKIE", "fresh", true),
        };

        Assert.Equal(
            "fresh",
            FortinetSamlProtocol.SelectSvpnCookieValue(cookies));
        Assert.Null(FortinetSamlProtocol.SelectSvpnCookieValue(
            new[] { ("SVPNCOOKIE", "script-visible", false) }));
        Assert.True(FortinetSamlProtocol.IsSvpnCookieName("SVPNCOOKIE"));
        Assert.False(FortinetSamlProtocol.IsSvpnCookieName("svpncookie"));
    }

    [Theory]
    [InlineData("/?id=alpha%2Bbeta%2Fgamma%3D", "alpha+beta/gamma=")]
    [InlineData("/callback?ignored=x&id=opaque-token", "opaque-token")]
    public void TryParseAuthId_DecodesExactlyOnce(string target, string expected)
    {
        Assert.True(FortinetSamlProtocol.TryParseAuthId(target, out var authId));
        Assert.Equal(expected, authId);
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/?id=")]
    [InlineData("/?other=value")]
    [InlineData("/?id=%")]
    [InlineData("/?id=%ZZ")]
    [InlineData("https://attacker.example/?id=value")]
    public void TryParseAuthId_RejectsMalformedCallbacks(string target)
    {
        Assert.False(FortinetSamlProtocol.TryParseAuthId(target, out _));
    }

    [Fact]
    public async Task ExternalClient_BindsBeforeLaunchAndReturnsAuthId()
    {
        var port = GetFreePort();
        var callbackResponse = string.Empty;
        Task? callbackTask = null;
        var launcher = new RecordingLauncher(uri =>
        {
            Assert.Equal("?redirect=1", uri.Query);
            callbackTask = SendCallbackAsync(port, "/?id=alpha%2Bbeta%2Fgamma%3D",
                response => callbackResponse = response);
        });
        var client = new FortinetExternalSamlAuthClient(launcher);
        var settings = NewSsoSettings(useExternalBrowser: true);
        settings.SamlRedirectPort = port;

        var result = await client.AuthenticateAsync(settings, CancellationToken.None);
        await callbackTask!;

        Assert.Equal("alpha+beta/gamma=", result.AuthId);
        Assert.Null(result.SvpnCookie);
        Assert.Contains("200 OK", callbackResponse, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ExternalClient_IgnoresMalformedRequestThenAcceptsValidCallback()
    {
        var port = GetFreePort();
        Task? callbackTask = null;
        var launcher = new RecordingLauncher(_ =>
        {
            callbackTask = Task.Run(async () =>
            {
                await SendCallbackAsync(port, "/?id=wrong-version", httpVersion: "HTTP/1.9");
                await SendCallbackAsync(port, "/?other=value");
                await SendCallbackAsync(port, "/?id=second-attempt");
            });
        });
        var client = new FortinetExternalSamlAuthClient(launcher);
        var settings = NewSsoSettings(useExternalBrowser: true);
        settings.SamlRedirectPort = port;

        var result = await client.AuthenticateAsync(settings, CancellationToken.None);
        await callbackTask!;

        Assert.Equal("second-attempt", result.AuthId);
    }

    [Fact]
    public async Task ExternalClient_AbandonedConnectionDoesNotBlockValidCallback()
    {
        var port = GetFreePort();
        Task? callbackTask = null;
        var launcher = new RecordingLauncher(_ =>
        {
            callbackTask = Task.Run(async () =>
            {
                using var abandoned = new TcpClient();
                await abandoned.ConnectAsync(IPAddress.Loopback, port);
                await Task.Delay(100);
                await SendCallbackAsync(port, "/?id=after-timeout");
            });
        });
        var client = new FortinetExternalSamlAuthClient(
            launcher, requestTimeout: TimeSpan.FromMilliseconds(25));
        var settings = NewSsoSettings(useExternalBrowser: true);
        settings.SamlRedirectPort = port;

        var result = await client.AuthenticateAsync(settings, CancellationToken.None);
        await callbackTask!;

        Assert.Equal("after-timeout", result.AuthId);
    }

    [Fact]
    public async Task ExternalClient_ReportsOccupiedCallbackPortWithoutLaunchingBrowser()
    {
        var port = GetFreePort();
        var occupied = new TcpListener(IPAddress.Loopback, port);
        occupied.Start();
        try
        {
            var launcher = new RecordingLauncher(_ => throw new InvalidOperationException("must not launch"));
            var client = new FortinetExternalSamlAuthClient(launcher);
            var settings = NewSsoSettings(useExternalBrowser: true);
            settings.SamlRedirectPort = port;

            var error = await Assert.ThrowsAsync<InvalidOperationException>(
                () => client.AuthenticateAsync(settings, CancellationToken.None));

            Assert.Contains(port.ToString(), error.Message, StringComparison.Ordinal);
            Assert.False(launcher.WasOpened);
        }
        finally
        {
            occupied.Stop();
        }
    }

    [Fact]
    public async Task ExternalClient_HonorsCancellationWhileWaitingForCallback()
    {
        var port = GetFreePort();
        var client = new FortinetExternalSamlAuthClient(new RecordingLauncher(_ => { }));
        var settings = NewSsoSettings(useExternalBrowser: true);
        settings.SamlRedirectPort = port;
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => client.AuthenticateAsync(settings, cancellation.Token));
    }

    private static FortinetSettings NewSsoSettings(bool useExternalBrowser) => new()
    {
        Host = "vpn.example.com",
        Port = 443,
        UseSingleSignOn = true,
        UseExternalBrowser = useExternalBrowser,
    };

    private static int GetFreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static async Task SendCallbackAsync(
        int port,
        string target,
        Action<string>? captureResponse = null,
        string httpVersion = "HTTP/1.1")
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, port);
        var stream = tcp.GetStream();
        var request = Encoding.ASCII.GetBytes(
            $"GET {target} {httpVersion}\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(request);
        await stream.FlushAsync();
        tcp.Client.Shutdown(SocketShutdown.Send);

        using var reader = new System.IO.StreamReader(stream, Encoding.UTF8);
        var response = await reader.ReadToEndAsync();
        captureResponse?.Invoke(response);
    }

    private sealed class RecordingLauncher(Action<Uri> onOpen) : IFortinetExternalBrowserLauncher
    {
        public bool WasOpened { get; private set; }

        public void Open(Uri uri)
        {
            WasOpened = true;
            onOpen(uri);
        }
    }
}

using System.Text.Json;
using Wormhole.Helpers;
using Wormhole.Interop.Rdp;

namespace Wormhole.RdpHost.Tests;

public sealed class RdpHostContractTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    [Fact]
    public void JsonContract_IgnoresControllerOnlyFieldsRemovedFromTheActiveXModel()
    {
        const string json = """
            {
              "op": "start",
              "profile": {
                "nodeId": "saved-rdp",
                "name": "Production RDP",
                "host": "rdp.example",
                "port": 3391,
                "username": "operator",
                "gatewayBypassLocal": true,
                "useExternalClient": false
              }
            }
            """;

        var command = JsonSerializer.Deserialize<RdpHostCommand>(json, JsonOptions);

        Assert.NotNull(command);
        var profile = command.Profile.ToRdpConnectionProfile();
        Assert.Equal("rdp.example", profile.Host);
        Assert.Equal(3391, profile.Port);
        Assert.Equal("operator", profile.Username);
    }

    [Theory]
    [InlineData(-1, 3389)]
    [InlineData(0, 3389)]
    [InlineData(1, 1)]
    [InlineData(65535, 65535)]
    [InlineData(65536, 3389)]
    public void ProfileMapping_BoundsPortAndNormalizesOptionalIdentity(int port, int expectedPort)
    {
        var profile = new RdpHostProfile
        {
            Host = "rdp.example",
            Port = port,
            Username = " ",
            Domain = "\t",
        }.ToRdpConnectionProfile();

        Assert.Equal("rdp.example", profile.Host);
        Assert.Equal(expectedPort, profile.Port);
        Assert.Null(profile.Username);
        Assert.Null(profile.RdpDomain);
    }

    [Fact]
    public void ProfileMapping_PreservesTheEmbeddedElectronSettings()
    {
        var profile = new RdpHostProfile
        {
            Host = "rdp.example",
            Port = 3390,
            Username = "operator",
            Domain = "EXAMPLE",
            ScreenSize = "1440x900",
            FullScreen = true,
            ColorDepth = 24,
            UseAllMonitors = true,
            AudioMode = 2,
            AudioCaptureMode = 1,
            KeyboardHookMode = 1,
            RedirectClipboard = false,
            RedirectPrinters = true,
            RedirectSmartCards = true,
            RedirectPorts = true,
            RedirectDevices = true,
            RedirectDrives = "C,D",
            ConnectionSpeed = 6,
            DesktopBackground = false,
            FontSmoothing = false,
            DesktopComposition = false,
            WindowDrag = false,
            MenuAnimation = false,
            VisualStyles = false,
            BitmapCaching = false,
            AutoReconnect = false,
            ServerAuthentication = 1,
            GatewayUsageMethod = 1,
            GatewayHostname = "gateway.example",
            GatewayUseSameCreds = true,
        }.ToRdpConnectionProfile();

        Assert.Equal("operator", profile.Username);
        Assert.Equal("EXAMPLE", profile.RdpDomain);
        Assert.Equal("1440x900", profile.RdpScreenSize);
        Assert.True(profile.RdpFullScreen);
        Assert.Equal(24, profile.RdpColorDepth);
        Assert.True(profile.RdpUseAllMonitors);
        Assert.Equal(2, profile.RdpAudioMode);
        Assert.Equal(1, profile.RdpAudioCaptureMode);
        Assert.Equal(1, profile.RdpKeyboardHookMode);
        Assert.False(profile.RdpRedirectClipboard);
        Assert.True(profile.RdpRedirectPrinters);
        Assert.True(profile.RdpRedirectSmartCards);
        Assert.True(profile.RdpRedirectPorts);
        Assert.True(profile.RdpRedirectDevices);
        Assert.Equal("C,D", profile.RdpRedirectDrives);
        Assert.Equal(6, profile.RdpConnectionSpeed);
        Assert.False(profile.RdpDesktopBackground);
        Assert.False(profile.RdpFontSmoothing);
        Assert.False(profile.RdpDesktopComposition);
        Assert.False(profile.RdpWindowDrag);
        Assert.False(profile.RdpMenuAnimation);
        Assert.False(profile.RdpVisualStyles);
        Assert.False(profile.RdpBitmapCaching);
        Assert.False(profile.RdpAutoReconnect);
        Assert.Equal(1, profile.RdpServerAuthentication);
        Assert.Equal(1, profile.RdpGatewayUsageMethod);
        Assert.Equal("gateway.example", profile.RdpGatewayHostname);
        Assert.True(profile.RdpGatewayUseSameCreds);
    }

    [Theory]
    [InlineData(true, false, false)]
    [InlineData(false, false, true)]
    [InlineData(true, true, false)]
    [InlineData(false, true, true)]
    public void BoundsFlags_PreserveVisibilityAndZOrderRules(
        bool sizeChanged,
        bool reveal,
        bool expectNoZOrder)
    {
        var flags = RdpHostBoundsWindowPos.BuildFlags(sizeChanged, reveal);

        Assert.Equal(reveal, (flags & Win32Interop.SWP_SHOWWINDOW) != 0);
        Assert.Equal(expectNoZOrder, (flags & Win32Interop.SWP_NOZORDER) != 0);
        Assert.NotEqual(0u, flags & Win32Interop.SWP_NOACTIVATE);
    }

    [Fact]
    public void EventSink_DoesNotLeakSubscriberFailuresIntoComDispatch()
    {
        var sink = new MsTscAxEventsSink();
        sink.Connected += () => throw new InvalidOperationException("handler failure");

        var error = Record.Exception(sink.OnConnected);

        Assert.Null(error);
    }
}

using Wormhole.Models;
using Wormhole.Services;
using Wormhole.ViewModels;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public class QuickConnectViewModelTests
{
    [Fact]
    public void ProtocolChoices_ExposeSshRdpAndVnc()
    {
        var vm = new QuickConnectViewModel(new CapturingSessionTabFactory());

        Assert.Collection(
            vm.ProtocolChoices,
            item => Assert.Equal(ProtocolType.Ssh, item.Protocol),
            item => Assert.Equal(ProtocolType.Rdp, item.Protocol),
            item => Assert.Equal(ProtocolType.Vnc, item.Protocol));
    }

    [Fact]
    public void Connect_Vnc_UsesDefaultPortAndIgnoresUsername()
    {
        var tabs = new CapturingSessionTabFactory();
        var vm = new QuickConnectViewModel(tabs)
        {
            Host = "operator@vnc.example.com",
            Username = "typed-user",
        };
        vm.SelectedProtocolChoice = vm.ProtocolChoices.Single(c => c.Protocol == ProtocolType.Vnc);

        vm.Connect();

        var profile = Assert.Single(tabs.Opened);
        Assert.Equal(ProtocolType.Vnc, profile.Protocol);
        Assert.Equal("vnc.example.com", profile.Host);
        Assert.Equal(5900, profile.Port);
        Assert.Null(profile.Username);
    }

    [Fact]
    public void Connect_Rdp_UsesSelectedProtocolChoice()
    {
        var tabs = new CapturingSessionTabFactory();
        var vm = new QuickConnectViewModel(tabs)
        {
            Host = "rdp.example.com",
        };
        vm.SelectedProtocolChoice = vm.ProtocolChoices.Single(c => c.Protocol == ProtocolType.Rdp);

        vm.Connect();

        var profile = Assert.Single(tabs.Opened);
        Assert.Equal(ProtocolType.Rdp, profile.Protocol);
        Assert.Equal(3389, profile.Port);
    }

    private sealed class CapturingSessionTabFactory : ISessionTabFactory
    {
        public List<ConnectionProfile> Opened { get; } = new();

        public void Open(ConnectionProfile profile) => Opened.Add(profile);
    }
}

using Wormhole.Models;
using Wormhole.Services;
using Wormhole.ViewModels;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public class QuickConnectViewModelTests
{
    [Fact]
    public void ProtocolChoices_ExposeSshRdpVncAndSerial()
    {
        var vm = new QuickConnectViewModel(new CapturingSessionTabFactory());

        Assert.Collection(
            vm.ProtocolChoices,
            item => Assert.Equal(ProtocolType.Ssh, item.Protocol),
            item => Assert.Equal(ProtocolType.Rdp, item.Protocol),
            item => Assert.Equal(ProtocolType.Vnc, item.Protocol),
            item => Assert.Equal(ProtocolType.Serial, item.Protocol));
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

    [Theory]
    [InlineData("COM1", "COM1", SerialDefaults.BaudRate)]
    [InlineData(" COM3:115200 ", "COM3", 115200)]
    public void SerialConnect_OpensSerialProfile(string input, string expectedPortName, int expectedBaudRate)
    {
        var factory = new CapturingSessionTabFactory();
        var vm = new QuickConnectViewModel(factory)
        {
            Protocol = ProtocolType.Serial,
            Host = input,
        };

        vm.Connect();

        Assert.Null(vm.ErrorMessage);
        var profile = Assert.Single(factory.Opened);
        Assert.Equal(ProtocolType.Serial, profile.Protocol);
        Assert.Equal(expectedPortName, profile.Name);
        Assert.Equal(expectedPortName, profile.Host);
        Assert.Equal(0, profile.Port);
        Assert.Equal(expectedBaudRate, profile.SerialBaudRate);
        Assert.Equal(SerialDefaults.DataBits, profile.SerialDataBits);
        Assert.Equal(SerialDefaults.StopBits, profile.SerialStopBits);
        Assert.Equal(SerialDefaults.Parity, profile.SerialParity);
        Assert.Equal(SerialDefaults.FlowControl, profile.SerialFlowControl);
    }

    [Theory]
    [InlineData("COM1:")]
    [InlineData("COM1:abc")]
    [InlineData("COM1:0")]
    [InlineData(":115200")]
    public void SerialConnect_InvalidBaudSuffix_SetsErrorAndDoesNotOpenTab(string input)
    {
        var factory = new CapturingSessionTabFactory();
        var vm = new QuickConnectViewModel(factory)
        {
            Protocol = ProtocolType.Serial,
            Host = input,
        };

        vm.Connect();

        Assert.Empty(factory.Opened);
        Assert.Equal("Serial quick connect must use COM1 or COM1:115200.", vm.ErrorMessage);
    }

    private sealed class CapturingSessionTabFactory : ISessionTabFactory
    {
        public List<ConnectionProfile> Opened { get; } = new();

        public void Open(ConnectionProfile profile) => Opened.Add(profile);
    }
}

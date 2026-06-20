using Wormhole.Models;
using Wormhole.Services;
using Wormhole.ViewModels;
using Xunit;

namespace Wormhole.Tests.ViewModels;

public class QuickConnectViewModelTests
{
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
        var profile = Assert.IsType<ConnectionProfile>(factory.LastOpened);
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

        Assert.Null(factory.LastOpened);
        Assert.Equal("Serial quick connect must use COM1 or COM1:115200.", vm.ErrorMessage);
    }

    private sealed class CapturingSessionTabFactory : ISessionTabFactory
    {
        public ConnectionProfile? LastOpened { get; private set; }

        public void Open(ConnectionProfile profile) => LastOpened = profile;
    }
}

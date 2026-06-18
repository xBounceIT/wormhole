using Windows.Security.Credentials.UI;
using Wormhole.Services.Security;
using Xunit;

namespace Wormhole.Tests.Services.Security;

public sealed class WindowsHelloServiceTests
{
    [Fact]
    public async Task CheckAvailabilityAsync_WhenRemoteDesktopSession_ReturnsFallbackMessageAndSkipsHello()
    {
        var checkCount = 0;
        var service = new WindowsHelloService(
            new FakeRemoteDesktopSessionDetector(true),
            _ =>
            {
                checkCount++;
                return Task.FromResult(UserConsentVerifierAvailability.Available);
            },
            (_, _, _) => Task.FromResult(UserConsentVerificationResult.Verified));

        var availability = await service.CheckAvailabilityAsync();

        Assert.False(availability.IsAvailable);
        Assert.Equal(WindowsHelloService.RemoteDesktopUnavailableMessage, availability.Message);
        Assert.Equal(0, checkCount);
    }

    [Fact]
    public async Task RequestVerificationAsync_WhenRemoteDesktopSession_ReturnsFallbackMessageAndSkipsHello()
    {
        var requestCount = 0;
        var service = new WindowsHelloService(
            new FakeRemoteDesktopSessionDetector(true),
            _ => Task.FromResult(UserConsentVerifierAvailability.Available),
            (_, _, _) =>
            {
                requestCount++;
                return Task.FromResult(UserConsentVerificationResult.Verified);
            });

        var verification = await service.RequestVerificationAsync(IntPtr.Zero, "Unlock Wormhole");

        Assert.False(verification.IsVerified);
        Assert.Equal(WindowsHelloService.RemoteDesktopUnavailableMessage, verification.Message);
        Assert.Equal(0, requestCount);
    }

    private sealed class FakeRemoteDesktopSessionDetector : IRemoteDesktopSessionDetector
    {
        private readonly bool _isRemoteDesktopSession;

        public FakeRemoteDesktopSessionDetector(bool isRemoteDesktopSession)
        {
            _isRemoteDesktopSession = isRemoteDesktopSession;
        }

        public bool IsRemoteDesktopSession() => _isRemoteDesktopSession;
    }
}

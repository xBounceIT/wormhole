using Wormhole.Models;
using Wormhole.Services.Security;
using Xunit;

namespace Wormhole.Tests.Services.Security;

public sealed class AppAuthenticationVerifierTests
{
    [Fact]
    public async Task VerifyAsync_WindowsHelloVerified_DoesNotPromptFallback()
    {
        var auth = new FakeAuth { PinVerified = true };
        var hello = new FakeHello { Available = true, Verified = true };
        var verifier = new AppAuthenticationVerifier(auth, hello);
        var promptCount = 0;

        var result = await verifier.VerifyAsync(
            AppAuthenticationMode.WindowsHello,
            AppAuthenticationFallbackMethod.Pin,
            IntPtr.Zero,
            "Unlock",
            _ =>
            {
                promptCount++;
                return Task.FromResult<string?>("1234");
            });

        Assert.True(result.Succeeded);
        Assert.Equal(0, promptCount);
        Assert.Equal(1, hello.RequestCount);
    }

    [Fact]
    public async Task VerifyAsync_WindowsHelloUnavailable_UsesFallback()
    {
        var auth = new FakeAuth { PinVerified = true };
        var hello = new FakeHello { Available = false };
        var verifier = new AppAuthenticationVerifier(auth, hello);

        var result = await verifier.VerifyAsync(
            AppAuthenticationMode.WindowsHello,
            AppAuthenticationFallbackMethod.Pin,
            IntPtr.Zero,
            "Unlock",
            _ => Task.FromResult<string?>("1234"));

        Assert.True(result.Succeeded);
        Assert.Equal(0, hello.RequestCount);
        Assert.Equal(AppAuthenticationFallbackMethod.Pin, auth.LastMethod);
    }

    [Fact]
    public async Task VerifyAsync_WindowsHelloRejected_UsesFallback()
    {
        var auth = new FakeAuth { PasswordVerified = true };
        var hello = new FakeHello { Available = true, Verified = false };
        var verifier = new AppAuthenticationVerifier(auth, hello);

        var result = await verifier.VerifyAsync(
            AppAuthenticationMode.WindowsHello,
            AppAuthenticationFallbackMethod.Password,
            IntPtr.Zero,
            "Unlock",
            _ => Task.FromResult<string?>("password"));

        Assert.True(result.Succeeded);
        Assert.Equal(1, hello.RequestCount);
        Assert.Equal(AppAuthenticationFallbackMethod.Password, auth.LastMethod);
    }

    [Fact]
    public async Task VerifyAsync_WindowsHelloInteropFailure_UsesFallback()
    {
        var auth = new FakeAuth { PinVerified = true };
        var hello = new FakeHello { Available = true, RequestException = new InvalidOperationException("Hello unavailable") };
        var verifier = new AppAuthenticationVerifier(auth, hello);

        var result = await verifier.VerifyAsync(
            AppAuthenticationMode.WindowsHello,
            AppAuthenticationFallbackMethod.Pin,
            IntPtr.Zero,
            "Unlock",
            _ => Task.FromResult<string?>("1234"));

        Assert.True(result.Succeeded);
        Assert.Equal(1, hello.RequestCount);
        Assert.Equal(AppAuthenticationFallbackMethod.Pin, auth.LastMethod);
    }

    [Fact]
    public async Task VerifyAsync_WrongFallbackSecret_Fails()
    {
        var auth = new FakeAuth();
        var verifier = new AppAuthenticationVerifier(auth, new FakeHello());

        var result = await verifier.VerifyAsync(
            AppAuthenticationMode.Pin,
            AppAuthenticationFallbackMethod.Pin,
            IntPtr.Zero,
            "Unlock",
            _ => Task.FromResult<string?>("wrong"));

        Assert.False(result.Succeeded);
        Assert.Equal("Invalid PIN.", result.Message);
    }

    private sealed class FakeHello : IWindowsHelloService
    {
        public bool Available { get; set; }
        public bool Verified { get; set; }
        public Exception? AvailabilityException { get; set; }
        public Exception? RequestException { get; set; }
        public int RequestCount { get; private set; }

        public Task<WindowsHelloAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default)
        {
            if (AvailabilityException is not null)
            {
                throw AvailabilityException;
            }
            return Task.FromResult(new WindowsHelloAvailability(Available, Available ? "available" : "unavailable"));
        }

        public Task<WindowsHelloVerification> RequestVerificationAsync(
            IntPtr ownerHwnd,
            string message,
            CancellationToken cancellationToken = default)
        {
            RequestCount++;
            if (RequestException is not null)
            {
                throw RequestException;
            }
            return Task.FromResult(new WindowsHelloVerification(Verified, Verified ? "verified" : "rejected"));
        }
    }

    private sealed class FakeAuth : IAppAuthenticationService
    {
        public bool PinVerified { get; set; }
        public bool PasswordVerified { get; set; }
        public AppAuthenticationFallbackMethod? LastMethod { get; private set; }

        public AppAuthenticationSecretValidation ValidateSecret(AppAuthenticationFallbackMethod method, string secret) =>
            new(true, null);

        public Task<AppAuthenticationSecretStatus> GetStatusAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(new AppAuthenticationSecretStatus(true, true, false));

        public Task<bool> IsConfiguredForModeAsync(
            AppAuthenticationMode mode,
            AppAuthenticationFallbackMethod fallback,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(true);

        public Task SetSecretAsync(
            AppAuthenticationFallbackMethod method,
            string secret,
            CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task<bool> VerifySecretAsync(
            AppAuthenticationFallbackMethod method,
            string secret,
            CancellationToken cancellationToken = default)
        {
            LastMethod = method;
            return Task.FromResult(method == AppAuthenticationFallbackMethod.Pin ? PinVerified : PasswordVerified);
        }

        public Task DeleteAllAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}

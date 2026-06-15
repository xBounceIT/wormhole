using Microsoft.Extensions.Logging.Abstractions;
using Wormhole.Models;
using Wormhole.Services.Security;
using Xunit;

namespace Wormhole.Tests.Services.Security;

public sealed class AppAuthenticationServiceTests
{
    [Theory]
    [InlineData("", false)]
    [InlineData("123", false)]
    [InlineData("1234", true)]
    [InlineData("123456789012", true)]
    [InlineData("1234567890123", false)]
    [InlineData("12a4", false)]
    public void ValidateSecret_ValidatesPinRangeAndDigits(string pin, bool expected)
    {
        using var store = new TempStore();
        var service = store.CreateService();

        Assert.Equal(expected, service.ValidateSecret(AppAuthenticationFallbackMethod.Pin, pin).IsValid);
    }

    [Theory]
    [InlineData("short", false)]
    [InlineData("12345678", true)]
    public void ValidateSecret_ValidatesPasswordRange(string password, bool expected)
    {
        using var store = new TempStore();
        var service = store.CreateService();

        Assert.Equal(expected, service.ValidateSecret(AppAuthenticationFallbackMethod.Password, password).IsValid);
    }

    [Fact]
    public async Task SetAndVerify_Pin_WrongSecretFails()
    {
        using var store = new TempStore();
        var service = store.CreateService();

        await service.SetSecretAsync(AppAuthenticationFallbackMethod.Pin, "123456");

        Assert.True(await service.VerifySecretAsync(AppAuthenticationFallbackMethod.Pin, "123456"));
        Assert.False(await service.VerifySecretAsync(AppAuthenticationFallbackMethod.Pin, "654321"));
        Assert.False(await service.VerifySecretAsync(AppAuthenticationFallbackMethod.Password, "123456"));
    }

    [Fact]
    public async Task SetAndVerify_Password_WrongSecretFails()
    {
        using var store = new TempStore();
        var service = store.CreateService();

        await service.SetSecretAsync(AppAuthenticationFallbackMethod.Password, "correct horse");

        Assert.True(await service.VerifySecretAsync(AppAuthenticationFallbackMethod.Password, "correct horse"));
        Assert.False(await service.VerifySecretAsync(AppAuthenticationFallbackMethod.Password, "battery staple"));
    }

    [Fact]
    public async Task MissingStore_ReportsNoSecrets()
    {
        using var store = new TempStore();
        var service = store.CreateService();

        var status = await service.GetStatusAsync();

        Assert.False(status.HasPin);
        Assert.False(status.HasPassword);
        Assert.False(status.IsCorrupted);
    }

    [Fact]
    public async Task CorruptedStore_ReportsCorruptionAndRejectsVerification()
    {
        using var store = new TempStore();
        await File.WriteAllTextAsync(store.Path, "not-json");
        var service = store.CreateService();

        var status = await service.GetStatusAsync();

        Assert.True(status.IsCorrupted);
        Assert.False(await service.VerifySecretAsync(AppAuthenticationFallbackMethod.Pin, "1234"));
    }

    [Fact]
    public async Task SetSecret_OverwritesCorruptedStore()
    {
        using var store = new TempStore();
        await File.WriteAllTextAsync(store.Path, "not-json");
        var service = store.CreateService();

        await service.SetSecretAsync(AppAuthenticationFallbackMethod.Pin, "1234");
        var status = await service.GetStatusAsync();

        Assert.True(status.HasPin);
        Assert.False(status.IsCorrupted);
        Assert.True(await service.VerifySecretAsync(AppAuthenticationFallbackMethod.Pin, "1234"));
    }

    private sealed class TempStore : IDisposable
    {
        private readonly string _dir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "wormhole-auth-tests-" + Guid.NewGuid().ToString("N"));

        public string Path => System.IO.Path.Combine(_dir, "app-auth.dpapi");

        public TempStore() => Directory.CreateDirectory(_dir);

        public AppAuthenticationService CreateService() =>
            new(Path, 1_000, NullLogger<AppAuthenticationService>.Instance, new PassThroughProtector());

        public void Dispose()
        {
            try { Directory.Delete(_dir, recursive: true); }
            catch { }
        }
    }

    private sealed class PassThroughProtector : IAppAuthenticationDataProtector
    {
        public byte[] Protect(byte[] plaintext) => plaintext.ToArray();
        public byte[] Unprotect(byte[] protectedBlob) => protectedBlob.ToArray();
    }
}

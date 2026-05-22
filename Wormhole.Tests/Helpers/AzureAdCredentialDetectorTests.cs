using Wormhole.Helpers;
using Wormhole.Models;
using Xunit;

namespace Wormhole.Tests.Helpers;

public class AzureAdCredentialDetectorTests
{
    [Fact]
    public void NullCredential_IsNotAzureAd()
    {
        Assert.False(AzureAdCredentialDetector.IsAzureAd(null));
    }

    [Fact]
    public void EmptyDomainAndUsername_IsNotAzureAd()
    {
        var cred = new CredentialProfile { Name = "x", Domain = null, Username = null };
        Assert.False(AzureAdCredentialDetector.IsAzureAd(cred));
    }

    [Theory]
    [InlineData("AzureAD")]
    [InlineData("azuread")]
    [InlineData("AZUREAD")]
    [InlineData("AzureAd")]
    public void DomainEqualsAzureAd_IsAzureAd(string domain)
    {
        var cred = new CredentialProfile { Name = "x", Domain = domain, Username = "user@tenant.com" };
        Assert.True(AzureAdCredentialDetector.IsAzureAd(cred));
    }

    [Theory]
    [InlineData("AzureAD\\user@tenant.onmicrosoft.com")]
    [InlineData("azuread\\bob")]
    [InlineData("AZUREAD\\alice@contoso.com")]
    public void UsernameWithAzureAdPrefix_IsAzureAd(string username)
    {
        var cred = new CredentialProfile { Name = "x", Domain = null, Username = username };
        Assert.True(AzureAdCredentialDetector.IsAzureAd(cred));
    }

    [Theory]
    [InlineData("MYCORP", "alice")]
    [InlineData("WORKGROUP", "bob")]
    [InlineData("", "user@contoso.com")]
    [InlineData("CONTOSO", "user@contoso.onmicrosoft.com")]
    [InlineData(null, "AzureADish")] // 'AzureAD' substring without trailing backslash is NOT a match
    public void NonAzureAdDomainAndUsername_IsNotAzureAd(string? domain, string username)
    {
        // We deliberately do NOT match bare *@*.onmicrosoft.com UPNs because on-prem AD
        // accounts synced to M365 share that format without being AAD-joined for RDP purposes.
        // The "AzureAD" prefix on Username requires the trailing backslash.
        var cred = new CredentialProfile { Name = "x", Domain = domain, Username = username };
        Assert.False(AzureAdCredentialDetector.IsAzureAd(cred));
    }
}

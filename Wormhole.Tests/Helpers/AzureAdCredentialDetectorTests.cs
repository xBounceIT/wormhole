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

    // --- Standalone field probes ----------------------------------------------------------

    [Theory]
    [InlineData("AzureAD", true)]
    [InlineData("azuread", true)]
    [InlineData("  AzureAD  ", true)] // trims surrounding whitespace
    [InlineData("AzureADish", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void HasAzureAdDomain_MatchesExactValueIgnoringCaseAndWhitespace(string? value, bool expected)
    {
        Assert.Equal(expected, AzureAdCredentialDetector.HasAzureAdDomain(value));
    }

    [Theory]
    [InlineData("AzureAD\\alice", true)]
    [InlineData("  AzureAD\\alice", true)] // trims leading whitespace
    [InlineData("azuread\\bob", true)]
    [InlineData("MYCORP\\alice", false)]
    [InlineData("AzureAD", false)] // missing backslash → not a UPN-style prefix
    [InlineData("", false)]
    [InlineData(null, false)]
    public void HasAzureAdPrefix_MatchesUsernamePrefixIgnoringCaseAndLeadingWhitespace(string? value, bool expected)
    {
        Assert.Equal(expected, AzureAdCredentialDetector.HasAzureAdPrefix(value));
    }

    // --- Profile overload: node fields trigger detection even without a saved credential.

    [Fact]
    public void Profile_WithAzureAdDomainOnNode_DetectedEvenWithNullCredential()
    {
        // The motivating scenario from the production crash log: user has "Prompt every
        // time" (CredentialId = null), but typed "AzureAD" into the node's Domain field.
        // The credential-only overload returned false here and the embedded path crashed
        // the app deterministically. The profile overload must catch this.
        var profile = MakeProfile(rdpDomain: "AzureAD");
        Assert.True(AzureAdCredentialDetector.IsAzureAd(profile, credential: null));
    }

    [Fact]
    public void Profile_WithAzureAdUsernameOnNode_DetectedEvenWithNullCredential()
    {
        var profile = MakeProfile(username: "AzureAD\\alice@tenant.com");
        Assert.True(AzureAdCredentialDetector.IsAzureAd(profile, credential: null));
    }

    [Fact]
    public void Profile_OnlyCredentialIsAzureAd_StillDetected()
    {
        var profile = MakeProfile();
        var cred = new CredentialProfile { Name = "x", Domain = "AzureAD" };
        Assert.True(AzureAdCredentialDetector.IsAzureAd(profile, cred));
    }

    [Fact]
    public void Profile_NoAzureAdSignalsAnywhere_NotDetected()
    {
        var profile = MakeProfile(rdpDomain: "CORP", username: "alice");
        var cred = new CredentialProfile { Name = "x", Domain = "CORP", Username = "alice" };
        Assert.False(AzureAdCredentialDetector.IsAzureAd(profile, cred));
    }

    [Fact]
    public void Profile_NullArgument_Throws()
    {
        Assert.Throws<ArgumentNullException>(
            () => AzureAdCredentialDetector.IsAzureAd(profile: null!, credential: null));
    }

    private static ConnectionProfile MakeProfile(string? rdpDomain = null, string? username = null) =>
        new()
        {
            NodeId = Guid.NewGuid(),
            Name = "test",
            Protocol = ProtocolType.Rdp,
            Host = "host",
            Port = 3389,
            RdpDomain = rdpDomain,
            Username = username,
        };
}

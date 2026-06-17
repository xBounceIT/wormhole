using Wormhole.Helpers.Converters;
using Wormhole.Models;
using Xunit;

namespace Wormhole.Tests.Helpers;

public sealed class CredentialProfileDisplayConverterTests
{
    private readonly CredentialProfileDisplayConverter _converter = new();

    [Fact]
    public void Convert_RealCredentialStartingWithParenthesis_StillShowsProtocol()
    {
        var profile = new CredentialProfile
        {
            Id = Guid.NewGuid(),
            Name = "(prod)",
            Protocol = ProtocolType.Rdp,
        };

        var text = _converter.Convert(profile, typeof(string), null!, string.Empty);

        Assert.Equal("(prod) (RDP)", text);
    }

    [Fact]
    public void Convert_SentinelCredential_DoesNotAppendProtocol()
    {
        var profile = new CredentialProfile
        {
            Id = CredentialBindingSentinelIds.Inherit,
            Name = "(Inherit from folder)",
            Protocol = ProtocolType.Ssh,
        };

        var text = _converter.Convert(profile, typeof(string), null!, string.Empty);

        Assert.Equal("(Inherit from folder)", text);
    }
}

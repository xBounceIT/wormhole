using Renci.SshNet;
using Wormhole.Services.Ssh;
using Xunit;

namespace Wormhole.Tests.Services;

public class SshAuthMethodsBuilderTests
{
    [Fact]
    public void Build_EmptyCredentials_ReturnsEmptyArray()
    {
        var methods = SshAuthMethodsBuilder.Build("alice", SshCredentials.Empty);

        Assert.Same(Array.Empty<AuthenticationMethod>(), methods);
    }

    [Fact]
    public void Build_PasswordCredential_ReturnsPasswordMethod()
    {
        var methods = SshAuthMethodsBuilder.Build("alice", new SshCredentials("secret", null, null));

        var method = Assert.Single(methods);
        var password = Assert.IsType<PasswordAuthenticationMethod>(method);
        Assert.Equal("alice", password.Username);
    }
}

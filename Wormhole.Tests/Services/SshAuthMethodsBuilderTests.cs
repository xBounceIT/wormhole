using Renci.SshNet;
using Wormhole.Models;
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

    [Fact]
    public void ResolveUsername_ProfileUsernameWinsOverCredentialUsername()
    {
        var profile = MakeProfile(username: "profile-user");
        var credentials = new SshCredentials("secret", null, null, CredentialUsername: "credential-user");

        Assert.Equal("profile-user", credentials.ResolveUsername(profile));
    }

    [Fact]
    public void ResolveUsername_FallsBackToCredentialUsername()
    {
        var profile = MakeProfile(username: null);
        var credentials = new SshCredentials("secret", null, null, CredentialUsername: "credential-user");

        Assert.Equal("credential-user", credentials.ResolveUsername(profile));
    }

    [Fact]
    public void ResolveUsername_ReturnsNullWhenBothSourcesAreMissing()
    {
        var profile = MakeProfile(username: null);
        var credentials = new SshCredentials("secret", null, null);

        Assert.Null(credentials.ResolveUsername(profile));
    }

    private static ConnectionProfile MakeProfile(string? username) =>
        new()
        {
            NodeId = Guid.NewGuid(),
            Name = "test",
            Protocol = ProtocolType.Ssh,
            Host = "host.example",
            Port = 22,
            Username = username,
        };
}

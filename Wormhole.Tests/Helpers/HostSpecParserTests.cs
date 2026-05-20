using Wormhole.Helpers;
using Xunit;

namespace Wormhole.Tests.Helpers;

public class HostSpecParserTests
{
    [Fact]
    public void Plain_Hostname() => Assert.Equal(
        new HostSpec(null, "example.com", null),
        HostSpecParser.Parse("example.com"));

    [Fact]
    public void Hostname_With_Port() => Assert.Equal(
        new HostSpec(null, "example.com", 2222),
        HostSpecParser.Parse("example.com:2222"));

    [Fact]
    public void User_Host() => Assert.Equal(
        new HostSpec("alice", "example.com", null),
        HostSpecParser.Parse("alice@example.com"));

    [Fact]
    public void User_Host_Port() => Assert.Equal(
        new HostSpec("alice", "example.com", 2222),
        HostSpecParser.Parse("alice@example.com:2222"));

    [Fact]
    public void Trims_Surrounding_Whitespace() => Assert.Equal(
        new HostSpec("alice", "example.com", 22),
        HostSpecParser.Parse("  alice@example.com:22  "));

    [Fact]
    public void Ipv4_Hostname() => Assert.Equal(
        new HostSpec(null, "192.0.2.1", 2222),
        HostSpecParser.Parse("192.0.2.1:2222"));

    // The IPv6 fix — bare bracketless literals must not have their last hextet treated as a port.
    [Fact]
    public void Bracketless_Ipv6_NoPort() => Assert.Equal(
        new HostSpec(null, "2001:db8::1", null),
        HostSpecParser.Parse("2001:db8::1"));

    [Fact]
    public void Bracketless_Ipv6_WithUser() => Assert.Equal(
        new HostSpec("alice", "2001:db8::1", null),
        HostSpecParser.Parse("alice@2001:db8::1"));

    [Fact]
    public void Bracketless_Loopback_Ipv6() => Assert.Equal(
        new HostSpec(null, "::1", null),
        HostSpecParser.Parse("::1"));

    [Fact]
    public void Bracketed_Ipv6_NoPort() => Assert.Equal(
        new HostSpec(null, "2001:db8::1", null),
        HostSpecParser.Parse("[2001:db8::1]"));

    [Fact]
    public void Bracketed_Ipv6_WithPort() => Assert.Equal(
        new HostSpec(null, "2001:db8::1", 2222),
        HostSpecParser.Parse("[2001:db8::1]:2222"));

    [Fact]
    public void User_Bracketed_Ipv6_WithPort() => Assert.Equal(
        new HostSpec("alice", "::1", 22),
        HostSpecParser.Parse("alice@[::1]:22"));

    [Fact]
    public void NonNumeric_Suffix_NotTreatedAsPort() => Assert.Equal(
        new HostSpec(null, "host:noport", null),
        HostSpecParser.Parse("host:noport"));

    [Fact]
    public void Bracketed_TrailingGarbage_Throws()
        => Assert.Throws<System.FormatException>(() => HostSpecParser.Parse("[2001:db8::1]:22x"));

    [Fact]
    public void Bracketed_NonColonSuffix_Throws()
        => Assert.Throws<System.FormatException>(() => HostSpecParser.Parse("[host]abc"));

    [Fact]
    public void Bracketed_OnlyColonSuffix_Throws()
        => Assert.Throws<System.FormatException>(() => HostSpecParser.Parse("[host]:"));
}

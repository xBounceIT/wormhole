using Wormhole.Services.Sftp;
using Xunit;

namespace Wormhole.Tests.Services.Sftp;

public sealed class RemotePathTests
{
    [Theory]
    [InlineData("/", "foo", "/foo")]
    [InlineData("/home", "user", "/home/user")]
    [InlineData("/home/", "user", "/home/user")]
    [InlineData("", "foo", "foo")]
    [InlineData("/foo", "", "/foo")]
    public void Join_NormalizesSeparators(string parent, string child, string expected)
    {
        Assert.Equal(expected, RemotePath.Join(parent, child));
    }

    [Theory]
    [InlineData("/", "/")]
    [InlineData("", "/")]
    [InlineData("/foo", "/")]
    [InlineData("/foo/bar", "/foo")]
    [InlineData("/foo/bar/", "/foo")]
    [InlineData("/foo/bar/baz", "/foo/bar")]
    public void Parent_ReturnsExpected(string path, string expected)
    {
        Assert.Equal(expected, RemotePath.Parent(path));
    }

    [Theory]
    [InlineData("/", "")]
    [InlineData("", "")]
    [InlineData("/foo", "foo")]
    [InlineData("/foo/bar", "bar")]
    [InlineData("/foo/bar/", "bar")]
    public void Leaf_ReturnsExpected(string path, string expected)
    {
        Assert.Equal(expected, RemotePath.Leaf(path));
    }

    [Theory]
    [InlineData("/", true)]
    [InlineData("/foo", true)]
    [InlineData("foo", false)]
    [InlineData("", false)]
    // Backslash and NUL are rejected: SFTP paths must not contain them, and a
    // backslash on Windows would silently corrupt the path if used in code that
    // forgot to route through this helper.
    [InlineData("/foo\\bar", false)]
    [InlineData("/foo\0bar", false)]
    public void IsAbsolute_RejectsBadShapes(string path, bool expected)
    {
        Assert.Equal(expected, RemotePath.IsAbsolute(path));
    }
}

using Wormhole.Services;
using Xunit;

namespace Wormhole.Tests.Services;

public class UpdateChangelogFormatterTests
{
    [Fact]
    public void ToHtmlDocument_RendersMarkdownStructure()
    {
        var html = UpdateChangelogFormatter.ToHtmlDocument(
            """
            # Release 1.2.3

            ## Changes

            - Added **SSH** fixes
            - Improved `update` checks
            """);

        Assert.Contains("<!doctype html>", html);
        Assert.Contains("<h1", html);
        Assert.Contains("Release 1.2.3", html);
        Assert.Contains("<h2", html);
        Assert.Contains("<ul>", html);
        Assert.Contains("<strong>SSH</strong>", html);
        Assert.Contains("<code>update</code>", html);
    }

    [Fact]
    public void ToHtmlDocument_RendersLinksAndCodeBlocks()
    {
        var html = UpdateChangelogFormatter.ToHtmlDocument(
            """
            See [release notes](https://example.com/releases/1.2.3).

            ```powershell
            dotnet test
            ```
            """);

        Assert.Contains("<a href=\"https://example.com/releases/1.2.3\">release notes</a>", html);
        Assert.Contains("<pre><code class=\"language-powershell\">dotnet test", html);
    }

    [Fact]
    public void ToHtmlDocument_UsesExplicitReadableColors()
    {
        var html = UpdateChangelogFormatter.ToHtmlDocument("- Fixed update checks");

        Assert.Contains("--wh-bg: #ffffff;", html);
        Assert.Contains("--wh-text: #1f242b;", html);
        Assert.Contains("@media (prefers-color-scheme: dark)", html);
        Assert.Contains("--wh-bg: #1e1f22;", html);
        Assert.Contains("--wh-text: #f2f5f9;", html);
        Assert.Contains("min-height: 100vh;", html);
        Assert.DoesNotContain("Canvas", html);
        Assert.DoesNotContain("CanvasText", html);
        Assert.DoesNotContain("LinkText", html);
        Assert.DoesNotContain("color-mix", html);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ToHtmlDocument_ReturnsEmptyStringForEmptyNotes(string? notes)
    {
        Assert.Equal(string.Empty, UpdateChangelogFormatter.ToHtmlDocument(notes));
    }

    [Fact]
    public void ToHtmlDocument_DoesNotRenderRawHtmlOrScripts()
    {
        var html = UpdateChangelogFormatter.ToHtmlDocument(
            """
            <script>alert(1)</script>

            <div onclick="alert(1)">unsafe</div>
            """);
        var lower = html.ToLowerInvariant();

        Assert.DoesNotContain("<script", lower);
        Assert.DoesNotContain("<div", lower);
        Assert.Contains("&lt;script", lower);
        Assert.Contains("&lt;div", lower);
    }
}

using System;
using System.IO;
using Xunit;

namespace Wormhole.Tests.Interop.Terminal;

public sealed class TerminalBridgeAssetTests
{
    [Fact]
    public void Bridge_ForwardsOnDataAsBase64RawBytes()
    {
        var js = ReadBridge();

        Assert.Contains("post(\"b:\" + inputToBase64(data));", js);
        Assert.DoesNotContain("post(\"d:\" + data);", js);
    }

    [Fact]
    public void Bridge_ConsumesSharedBuffersForLargeTerminalOutput()
    {
        var js = ReadBridge();

        Assert.Contains("sharedbufferreceived", js);
        Assert.Contains("handleSharedOutputBuffer", js);
        Assert.Contains("new Uint8Array(buffer)", js);
        Assert.Contains("window.chrome.webview.releaseBuffer(buffer);", js);
        Assert.Contains("post(\"a:\" + byteCount + (ackId ? \":\" + ackId : \"\"));", js);
    }

    [Fact]
    public void Bridge_RepaintsAfterCtrlLWithoutSwallowingInput()
    {
        var js = ReadBridge();

        Assert.Contains("postInputBytes(data);", js);
        Assert.Contains("data.indexOf(\"\\x0c\") >= 0", js);
        Assert.Contains("scheduleControlKeyRepaint();", js);
    }

    [Fact]
    public void Bridge_FocusAndAlternateScreenForceGeometryReport()
    {
        var js = ReadBridge();

        Assert.Contains("scheduleFit(0, true, true);", js);
        Assert.Contains("scheduleFit(100, true, true);", js);
        Assert.Contains("scheduleFit(300, true, true);", js);
        Assert.Contains("term.buffer.onBufferChange(function ()", js);
        Assert.Contains("scheduleFit(50, true, true);", js);
    }

    [Fact]
    public void Terminal_UsesDefaultRenderer_NotWebglAddon()
    {
        var html = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Assets", "web", "terminal.html"));
        var js = ReadBridge();

        Assert.DoesNotContain("addon-webgl", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("WebglAddon", js, StringComparison.Ordinal);
        Assert.DoesNotContain("new Webgl", js, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void WebAssetFetch_PrunesRetiredWebglAddon()
    {
        var script = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "scripts", "Fetch-WebAssets.ps1"));

        Assert.DoesNotContain("cdn.jsdelivr.net/npm/@xterm/addon-webgl", script, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ManifestPrefix = \"addon-webgl\\\"", script, StringComparison.Ordinal);
        Assert.Contains("Remove-Item -LiteralPath $retiredPath -Recurse -Force", script, StringComparison.Ordinal);
    }

    private static string ReadBridge()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Assets", "web", "bridge.js");
        return File.ReadAllText(path);
    }
}

namespace Wormhole.Models;

public sealed class AppSettings
{
    public ApplicationTheme Theme { get; set; } = ApplicationTheme.System;
    public bool ConfirmOnTabClose { get; set; } = true;
    public string DefaultSshFont { get; set; } = "Cascadia Mono";
    public int DefaultSshFontSize { get; set; } = 12;
    public bool AutoCopyOnSelect { get; set; } = true;

    public bool AutoCheckForUpdates { get; set; } = true;
    public DateTimeOffset? LastUpdateCheck { get; set; }
    public string? SkippedUpdateVersion { get; set; }

    public int SidebarWidth { get; set; } = 320;

    // In-app MCP server (lets AI agents control already-open SSH sessions). Off by default;
    // the bearer token is stored in Windows Credential Manager, not here.
    public bool EnableMcpServer { get; set; }
    public int McpServerPort { get; set; } = 8765;
    public bool StreamMcpCommandTyping { get; set; } = true;
}

public enum ApplicationTheme
{
    System,
    Light,
    Dark,
}

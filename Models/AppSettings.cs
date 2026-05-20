using System;

namespace Wormhole.Models;

public sealed class AppSettings
{
    public ApplicationTheme Theme { get; set; } = ApplicationTheme.System;
    public bool ConfirmOnTabClose { get; set; } = true;
    public string DefaultSshFont { get; set; } = "Cascadia Mono";
    public int DefaultSshFontSize { get; set; } = 12;

    public bool AutoCheckForUpdates { get; set; } = true;
    public DateTimeOffset? LastUpdateCheck { get; set; }
    public string? SkippedUpdateVersion { get; set; }

    public int SidebarWidth { get; set; } = 320;
}

public enum ApplicationTheme
{
    System,
    Light,
    Dark,
}

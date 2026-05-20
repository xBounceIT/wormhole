namespace Wormhole.Models;

public sealed class AppSettings
{
    public ApplicationTheme Theme { get; set; } = ApplicationTheme.System;
    public bool ConfirmOnTabClose { get; set; } = true;
    public string DefaultSshFont { get; set; } = "Cascadia Mono";
    public int DefaultSshFontSize { get; set; } = 12;
}

public enum ApplicationTheme
{
    System,
    Light,
    Dark,
}

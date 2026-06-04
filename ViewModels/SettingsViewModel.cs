using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Wormhole.Helpers;
using Wormhole.Models;
using Wormhole.Models.Backup;
using Wormhole.Services;
using Wormhole.Services.Mcp;

namespace Wormhole.ViewModels;

public partial class SettingsViewModel : ObservableObject
{
    private readonly IAppSettingsService _settingsService;
    private readonly IDialogService _dialog;
    private readonly ConnectionTreeViewModel _connectionTree;
    private readonly CredentialsViewModel _credentials;
    private readonly TunnelConfigsViewModel _tunnels;
    private readonly IMcpServerHost _mcpHost;
    private readonly ILogger<SettingsViewModel> _logger;

    // Guards against re-entrant OnEnableMcpServerChanged when we revert the toggle after a
    // start failure.
    private bool _suppressMcpToggle;

    [ObservableProperty]
    private ApplicationTheme theme;

    [ObservableProperty]
    private bool confirmOnTabClose;

    [ObservableProperty]
    private bool autoCheckForUpdates;

    [ObservableProperty]
    private bool autoCopyOnSelect;

    [ObservableProperty]
    private bool promptBeforeTunnelConnect;

    [ObservableProperty]
    private bool enableMcpServer;

    [ObservableProperty]
    private bool streamMcpCommandTyping;

    // double (not int) so it binds directly to NumberBox.Value.
    [ObservableProperty]
    private double mcpServerPort;

    [ObservableProperty]
    private string mcpEndpoint = string.Empty;

    [ObservableProperty]
    private string mcpStatus = string.Empty;

    [ObservableProperty]
    private string mcpToken = string.Empty;

    [ObservableProperty]
    private bool isMcpTokenRevealed;

    [ObservableProperty]
    private string mcpConfigJson = string.Empty;

    // 0 = Claude Code CLI, 1 = Claude Desktop, 2 = Codex (matches the ComboBox item order).
    [ObservableProperty]
    private int mcpClientIndex;

    [ObservableProperty]
    private string mcpConfigLabel = "Config";

    [ObservableProperty]
    private string mcpConfigCaption = string.Empty;

    public UpdateViewModel Update { get; }

    public SettingsViewModel(
        IAppSettingsService settingsService,
        UpdateViewModel update,
        IDialogService dialog,
        ConnectionTreeViewModel connectionTree,
        CredentialsViewModel credentials,
        TunnelConfigsViewModel tunnels,
        IMcpServerHost mcpHost,
        ILogger<SettingsViewModel> logger)
    {
        _settingsService = settingsService;
        _dialog = dialog;
        _connectionTree = connectionTree;
        _credentials = credentials;
        _tunnels = tunnels;
        _mcpHost = mcpHost;
        _logger = logger;
        Update = update;
        theme = _settingsService.Current.Theme;
        confirmOnTabClose = _settingsService.Current.ConfirmOnTabClose;
        autoCheckForUpdates = _settingsService.Current.AutoCheckForUpdates;
        autoCopyOnSelect = _settingsService.Current.AutoCopyOnSelect;
        promptBeforeTunnelConnect = _settingsService.Current.PromptBeforeTunnelConnect;
        enableMcpServer = _settingsService.Current.EnableMcpServer;
        streamMcpCommandTyping = _settingsService.Current.StreamMcpCommandTyping;
        mcpServerPort = _settingsService.Current.McpServerPort;
        UpdateMcpStatus();
    }

    partial void OnThemeChanged(ApplicationTheme value)
    {
        _settingsService.Current.Theme = value;
        _settingsService.Save();
    }

    partial void OnConfirmOnTabCloseChanged(bool value)
    {
        _settingsService.Current.ConfirmOnTabClose = value;
        _settingsService.Save();
    }

    partial void OnAutoCheckForUpdatesChanged(bool value)
    {
        _settingsService.Current.AutoCheckForUpdates = value;
        _settingsService.Save();
    }

    partial void OnAutoCopyOnSelectChanged(bool value)
    {
        _settingsService.Current.AutoCopyOnSelect = value;
        _settingsService.Save();
    }

    partial void OnPromptBeforeTunnelConnectChanged(bool value)
    {
        _settingsService.Current.PromptBeforeTunnelConnect = value;
        _settingsService.Save();
    }

    partial void OnStreamMcpCommandTypingChanged(bool value)
    {
        _settingsService.Current.StreamMcpCommandTyping = value;
        _settingsService.Save();
    }

    // === MCP server ========================================================

    partial void OnEnableMcpServerChanged(bool value)
    {
        if (_suppressMcpToggle) return;
        _settingsService.Current.EnableMcpServer = value;
        _settingsService.Save();
        _ = ApplyMcpToggleAsync(value);
    }

    partial void OnMcpServerPortChanged(double value)
    {
        // Port only takes effect on the next start; editing is disabled while the server runs.
        var port = (int)value;
        if (port <= 0 || port > 65535) return;
        _settingsService.Current.McpServerPort = port;
        _settingsService.Save();
        UpdateMcpStatus();
    }

    private async Task ApplyMcpToggleAsync(bool enabled)
    {
        try
        {
            if (enabled)
            {
                await _mcpHost.StartAsync();
            }
            else
            {
                await _mcpHost.StopAsync();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to {Action} the MCP server.", enabled ? "start" : "stop");
            await _dialog.ShowMessageAsync(
                enabled ? "Couldn't start MCP server" : "Couldn't stop MCP server",
                ex.Message);
            if (enabled)
            {
                // Revert the toggle without re-triggering this handler.
                _suppressMcpToggle = true;
                EnableMcpServer = false;
                _suppressMcpToggle = false;
                _settingsService.Current.EnableMcpServer = false;
                _settingsService.Save();
            }
        }
        finally
        {
            UpdateMcpStatus();
        }
    }

    private void UpdateMcpStatus()
    {
        McpEndpoint = _mcpHost.EndpointUrl;
        McpStatus = _mcpHost.IsRunning
            ? $"Running — connect an MCP client to {_mcpHost.EndpointUrl}"
            : "Stopped";
    }

    // Keep the copyable config in sync with the endpoint, the revealed token, and the chosen client.
    partial void OnMcpEndpointChanged(string value) => UpdateMcpConfigJson();

    partial void OnMcpTokenChanged(string value) => UpdateMcpConfigJson();

    partial void OnMcpClientIndexChanged(int value) => UpdateMcpConfigJson();

    private enum McpClient { ClaudeCodeCli = 0, ClaudeDesktop = 1, Codex = 2 }

    private void UpdateMcpConfigJson()
    {
        // Show the real token only once revealed; otherwise a placeholder (Copy config always
        // copies the real token).
        var token = string.IsNullOrEmpty(McpToken) ? "<bearer-token — click Reveal or Copy config>" : McpToken;
        var client = (McpClient)McpClientIndex;
        McpConfigJson = BuildConfig(client, McpEndpoint, token);
        (McpConfigLabel, McpConfigCaption) = client switch
        {
            McpClient.ClaudeDesktop => (
                "Claude Desktop config (claude_desktop_config.json)",
                "Claude Desktop only launches stdio servers, so this bridges through mcp-remote (requires Node.js / npx)."),
            McpClient.Codex => (
                "Codex config (~/.codex/config.toml)",
                "Codex speaks Streamable HTTP directly. Add this to ~/.codex/config.toml — note it's TOML, not JSON."),
            _ => (
                "Claude Code config (.mcp.json)",
                "Claude Code speaks Streamable HTTP directly. Add this to .mcp.json (project) or ~/.claude.json."),
        };
    }

    // The server speaks Streamable HTTP. Each client needs a different shape: Claude Code consumes
    // HTTP natively (JSON), Claude Desktop is stdio-only so it bridges via mcp-remote (JSON), and
    // Codex consumes HTTP natively but is configured in TOML.
    private static string BuildConfig(McpClient client, string endpoint, string token) => client switch
    {
        // Claude Desktop is stdio-only → mcp-remote bridge. Two Windows quirks to dodge:
        //  1. A bare "npx" command is resolved by Claude Desktop to its spaced full path
        //     (C:\Program Files\nodejs\npx.cmd) and run unquoted via cmd /C, which breaks at the
        //     space ("'C:\Program' is not recognized"). Invoking through "cmd /c npx ..." sidesteps
        //     it: cmd.exe has no spaces, and the inner cmd resolves the bare "npx" from PATH.
        //  2. Spaces inside args also get mangled, so the bearer header goes through an env var —
        //     mcp-remote substitutes ${WORMHOLE_MCP_TOKEN} and the space lives in the env value,
        //     never on the command line. (mcp-remote's documented Windows workaround.)
        McpClient.ClaudeDesktop =>
            "{\n" +
            "  \"mcpServers\": {\n" +
            "    \"wormhole\": {\n" +
            "      \"command\": \"cmd\",\n" +
            "      \"args\": [\n" +
            "        \"/c\",\n" +
            "        \"npx\",\n" +
            "        \"mcp-remote@latest\",\n" +
            $"        \"{endpoint}\",\n" +
            "        \"--header\",\n" +
            "        \"Authorization:${WORMHOLE_MCP_TOKEN}\"\n" +
            "      ],\n" +
            "      \"env\": {\n" +
            $"        \"WORMHOLE_MCP_TOKEN\": \"Bearer {token}\"\n" +
            "      }\n" +
            "    }\n" +
            "  }\n" +
            "}",

        // Codex: native Streamable HTTP in TOML with an inline static Authorization header.
        McpClient.Codex =>
            "[mcp_servers.wormhole]\n" +
            $"url = \"{endpoint}\"\n" +
            $"http_headers = {{ Authorization = \"Bearer {token}\" }}\n",

        // Claude Code CLI: native Streamable HTTP JSON.
        _ =>
            "{\n" +
            "  \"mcpServers\": {\n" +
            "    \"wormhole\": {\n" +
            "      \"type\": \"http\",\n" +
            $"      \"url\": \"{endpoint}\",\n" +
            "      \"headers\": {\n" +
            $"        \"Authorization\": \"Bearer {token}\"\n" +
            "      }\n" +
            "    }\n" +
            "  }\n" +
            "}",
    };

    [RelayCommand]
    private async Task RevealMcpTokenAsync()
    {
        if (IsMcpTokenRevealed)
        {
            IsMcpTokenRevealed = false;
            McpToken = string.Empty;
            return;
        }
        try
        {
            McpToken = await _mcpHost.GetOrCreateTokenAsync();
            IsMcpTokenRevealed = true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to read MCP token.");
            await _dialog.ShowMessageAsync("Couldn't read MCP token", ex.Message);
        }
    }

    [RelayCommand]
    private async Task CopyMcpTokenAsync()
    {
        try
        {
            var token = await _mcpHost.GetOrCreateTokenAsync();
            ClipboardHelper.CopyText(token);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to copy MCP token.");
            await _dialog.ShowMessageAsync("Couldn't copy MCP token", ex.Message);
        }
    }

    [RelayCommand]
    private void CopyMcpEndpoint() => ClipboardHelper.CopyText(_mcpHost.EndpointUrl);

    [RelayCommand]
    private async Task CopyMcpConfigAsync()
    {
        try
        {
            // Always copy with the real token so the pasted config works immediately.
            var token = await _mcpHost.GetOrCreateTokenAsync();
            ClipboardHelper.CopyText(BuildConfig((McpClient)McpClientIndex, _mcpHost.EndpointUrl, token));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to copy MCP config.");
            await _dialog.ShowMessageAsync("Couldn't copy MCP config", ex.Message);
        }
    }

    [RelayCommand]
    private async Task RegenerateMcpTokenAsync()
    {
        var confirmed = await _dialog.ConfirmAsync(
            "Regenerate MCP token?",
            "Any MCP client using the current token will stop working until you give it the new token. Continue?",
            "Regenerate", "Cancel");
        if (!confirmed) return;

        try
        {
            McpToken = await _mcpHost.RegenerateTokenAsync();
            IsMcpTokenRevealed = true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to regenerate MCP token.");
            await _dialog.ShowMessageAsync("Couldn't regenerate MCP token", ex.Message);
        }
    }

    [RelayCommand]
    private async Task ExportBackupAsync()
    {
        try
        {
            await _dialog.PromptForBackupExportAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Backup export dialog failed.");
            await _dialog.ShowMessageAsync("Couldn't export backup", ex.Message);
        }
    }

    [RelayCommand]
    private async Task ImportBackupAsync()
    {
        try
        {
            _ = await _dialog.PromptForBackupImportAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Backup import dialog failed.");
            await _dialog.ShowMessageAsync("Couldn't import backup", ex.Message);
        }

        // Always refresh after the dialog closes. BackupService.ImportAsync is non-transactional
        // — a cancellation midway returns a null Result but may have already persisted credentials,
        // tunnels, and some nodes. Without an unconditional refresh, that partial state stays
        // invisible until the next restart, leaving the UI desynced from the DB.
        try
        {
            await _connectionTree.RefreshAsync();
            await _credentials.LoadCommand.ExecuteAsync(null);
            await _tunnels.LoadCommand.ExecuteAsync(null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to refresh views after backup import.");
        }
    }
}

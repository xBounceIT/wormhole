using Wormhole.Models;

namespace Wormhole.Data;

public sealed class InheritanceResolver
{
#pragma warning disable CA1822 // kept instance — registered via DI; see CLAUDE.md (load-bearing)
    public ConnectionProfile Resolve(ConnectionNode node, IReadOnlyDictionary<Guid, ConnectionNode> nodesById)
#pragma warning restore CA1822
    {
        ArgumentNullException.ThrowIfNull(node);
        ArgumentNullException.ThrowIfNull(nodesById);
        if (node.Kind != NodeKind.Connection)
        {
            throw new InvalidOperationException(
                $"InheritanceResolver can only resolve a connection node, but '{node.Name}' is a {node.Kind}.");
        }

        ProtocolType? protocol = null;
        string? host = null;
        int? port = null;
        string? username = null;
        Guid? credentialId = null;
        string? rdpDomain = null;
        string? rdpScreenSize = null;
        bool? rdpFullScreen = null;
        int? rdpColorDepth = null;
        bool? rdpUseAllMonitors = null;
        int? rdpAudioMode = null;
        int? rdpAudioCaptureMode = null;
        int? rdpKeyboardHookMode = null;
        bool? rdpRedirectClipboard = null;
        bool? rdpRedirectPrinters = null;
        bool? rdpRedirectSmartCards = null;
        bool? rdpRedirectPorts = null;
        bool? rdpRedirectDevices = null;
        string? rdpRedirectDrives = null;
        int? rdpConnectionSpeed = null;
        bool? rdpDesktopBackground = null;
        bool? rdpFontSmoothing = null;
        bool? rdpDesktopComposition = null;
        bool? rdpWindowDrag = null;
        bool? rdpMenuAnimation = null;
        bool? rdpVisualStyles = null;
        bool? rdpBitmapCaching = null;
        bool? rdpAutoReconnect = null;
        int? rdpServerAuthentication = null;
        int? rdpGatewayUsageMethod = null;
        string? rdpGatewayHostname = null;
        Guid? rdpGatewayCredentialId = null;
        bool? rdpGatewayBypassLocal = null;
        bool? rdpGatewayUseSameCreds = null;
        bool? rdpUseExternalClient = null;
        string? sshKeyFileName = null;
        string? sshKnownHostFingerprint = null;
        bool? tunnelEnabled = null;
        Guid? tunnelConfigId = null;

        HashSet<Guid>? seen = null;
        var current = node;
        while (true)
        {
            if (seen is not null && !seen.Add(current.Id))
            {
                throw new InvalidOperationException(
                    $"Detected a cycle in the node tree at '{current.Name}' ({current.Id}).");
            }

            protocol ??= current.Protocol;
            host ??= current.Host;
            port ??= current.Port;
            username ??= current.Username;
            credentialId ??= current.CredentialId;
            rdpDomain ??= current.RdpDomain;
            rdpScreenSize ??= current.RdpScreenSize;
            rdpFullScreen ??= current.RdpFullScreen;
            rdpColorDepth ??= current.RdpColorDepth;
            rdpUseAllMonitors ??= current.RdpUseAllMonitors;
            rdpAudioMode ??= current.RdpAudioMode;
            rdpAudioCaptureMode ??= current.RdpAudioCaptureMode;
            rdpKeyboardHookMode ??= current.RdpKeyboardHookMode;
            rdpRedirectClipboard ??= current.RdpRedirectClipboard;
            rdpRedirectPrinters ??= current.RdpRedirectPrinters;
            rdpRedirectSmartCards ??= current.RdpRedirectSmartCards;
            rdpRedirectPorts ??= current.RdpRedirectPorts;
            rdpRedirectDevices ??= current.RdpRedirectDevices;
            rdpRedirectDrives ??= current.RdpRedirectDrives;
            rdpConnectionSpeed ??= current.RdpConnectionSpeed;
            rdpDesktopBackground ??= current.RdpDesktopBackground;
            rdpFontSmoothing ??= current.RdpFontSmoothing;
            rdpDesktopComposition ??= current.RdpDesktopComposition;
            rdpWindowDrag ??= current.RdpWindowDrag;
            rdpMenuAnimation ??= current.RdpMenuAnimation;
            rdpVisualStyles ??= current.RdpVisualStyles;
            rdpBitmapCaching ??= current.RdpBitmapCaching;
            rdpAutoReconnect ??= current.RdpAutoReconnect;
            rdpServerAuthentication ??= current.RdpServerAuthentication;
            rdpGatewayUsageMethod ??= current.RdpGatewayUsageMethod;
            rdpGatewayHostname ??= current.RdpGatewayHostname;
            rdpGatewayCredentialId ??= current.RdpGatewayCredentialId;
            rdpGatewayBypassLocal ??= current.RdpGatewayBypassLocal;
            rdpGatewayUseSameCreds ??= current.RdpGatewayUseSameCreds;
            rdpUseExternalClient ??= current.RdpUseExternalClient;
            sshKeyFileName ??= current.SshKeyFileName;
            sshKnownHostFingerprint ??= current.SshKnownHostFingerprint;
            tunnelEnabled ??= current.TunnelEnabled;
            tunnelConfigId ??= current.TunnelConfigId;

            if (current.ParentId is not Guid parentId) break;
            if (!nodesById.TryGetValue(parentId, out var parent)) break;
            if (seen is null)
            {
                seen = new HashSet<Guid>();
                seen.Add(current.Id);
            }
            current = parent;
        }

        if (protocol is null)
        {
            throw new InvalidOperationException(
                $"Connection '{node.Name}' has no protocol set on itself or any ancestor folder.");
        }
        if (string.IsNullOrWhiteSpace(host))
        {
            throw new InvalidOperationException(
                $"Connection '{node.Name}' has no host set on itself or any ancestor folder.");
        }

        return new ConnectionProfile
        {
            NodeId = node.Id,
            Name = node.Name,
            Protocol = protocol.Value,
            Host = host,
            Port = port ?? DefaultPortFor(protocol.Value),
            Username = username,
            CredentialId = credentialId,
            RdpDomain = rdpDomain,
            RdpScreenSize = rdpScreenSize,
            RdpFullScreen = rdpFullScreen ?? false,
            RdpColorDepth = rdpColorDepth ?? 32,
            RdpUseAllMonitors = rdpUseAllMonitors ?? false,
            RdpAudioMode = rdpAudioMode ?? 0,
            RdpAudioCaptureMode = rdpAudioCaptureMode ?? 0,
            RdpKeyboardHookMode = rdpKeyboardHookMode ?? 2,
            RdpRedirectClipboard = rdpRedirectClipboard ?? true,
            RdpRedirectPrinters = rdpRedirectPrinters ?? false,
            RdpRedirectSmartCards = rdpRedirectSmartCards ?? false,
            RdpRedirectPorts = rdpRedirectPorts ?? false,
            RdpRedirectDevices = rdpRedirectDevices ?? false,
            RdpRedirectDrives = rdpRedirectDrives ?? string.Empty,
            RdpConnectionSpeed = rdpConnectionSpeed ?? 7,
            RdpDesktopBackground = rdpDesktopBackground ?? true,
            RdpFontSmoothing = rdpFontSmoothing ?? true,
            RdpDesktopComposition = rdpDesktopComposition ?? true,
            RdpWindowDrag = rdpWindowDrag ?? true,
            RdpMenuAnimation = rdpMenuAnimation ?? true,
            RdpVisualStyles = rdpVisualStyles ?? true,
            RdpBitmapCaching = rdpBitmapCaching ?? true,
            RdpAutoReconnect = rdpAutoReconnect ?? true,
            RdpServerAuthentication = rdpServerAuthentication ?? 0,
            RdpGatewayUsageMethod = rdpGatewayUsageMethod ?? 0,
            RdpGatewayHostname = rdpGatewayHostname,
            RdpGatewayCredentialId = rdpGatewayCredentialId,
            RdpGatewayBypassLocal = rdpGatewayBypassLocal ?? true,
            RdpGatewayUseSameCreds = rdpGatewayUseSameCreds ?? false,
            RdpUseExternalClient = rdpUseExternalClient ?? false,
            SshKeyFileName = sshKeyFileName,
            SshKnownHostFingerprint = sshKnownHostFingerprint,
            TunnelEnabled = tunnelEnabled ?? false,
            TunnelConfigId = tunnelConfigId,
        };
    }

    private static int DefaultPortFor(ProtocolType protocol) => protocol switch
    {
        ProtocolType.Ssh => 22,
        ProtocolType.Sftp => 22,
        ProtocolType.Rdp => 3389,
        _ => throw new ArgumentOutOfRangeException(nameof(protocol)),
    };
}

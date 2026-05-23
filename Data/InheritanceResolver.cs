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

        var chain = WalkParents(node, nodesById);

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

        foreach (var ancestor in chain)
        {
            protocol ??= ancestor.Protocol;
            host ??= ancestor.Host;
            port ??= ancestor.Port;
            username ??= ancestor.Username;
            credentialId ??= ancestor.CredentialId;
            rdpDomain ??= ancestor.RdpDomain;
            rdpScreenSize ??= ancestor.RdpScreenSize;
            rdpFullScreen ??= ancestor.RdpFullScreen;
            rdpColorDepth ??= ancestor.RdpColorDepth;
            rdpUseAllMonitors ??= ancestor.RdpUseAllMonitors;
            rdpAudioMode ??= ancestor.RdpAudioMode;
            rdpAudioCaptureMode ??= ancestor.RdpAudioCaptureMode;
            rdpKeyboardHookMode ??= ancestor.RdpKeyboardHookMode;
            rdpRedirectClipboard ??= ancestor.RdpRedirectClipboard;
            rdpRedirectPrinters ??= ancestor.RdpRedirectPrinters;
            rdpRedirectSmartCards ??= ancestor.RdpRedirectSmartCards;
            rdpRedirectPorts ??= ancestor.RdpRedirectPorts;
            rdpRedirectDevices ??= ancestor.RdpRedirectDevices;
            rdpRedirectDrives ??= ancestor.RdpRedirectDrives;
            rdpConnectionSpeed ??= ancestor.RdpConnectionSpeed;
            rdpDesktopBackground ??= ancestor.RdpDesktopBackground;
            rdpFontSmoothing ??= ancestor.RdpFontSmoothing;
            rdpDesktopComposition ??= ancestor.RdpDesktopComposition;
            rdpWindowDrag ??= ancestor.RdpWindowDrag;
            rdpMenuAnimation ??= ancestor.RdpMenuAnimation;
            rdpVisualStyles ??= ancestor.RdpVisualStyles;
            rdpBitmapCaching ??= ancestor.RdpBitmapCaching;
            rdpAutoReconnect ??= ancestor.RdpAutoReconnect;
            rdpServerAuthentication ??= ancestor.RdpServerAuthentication;
            rdpGatewayUsageMethod ??= ancestor.RdpGatewayUsageMethod;
            rdpGatewayHostname ??= ancestor.RdpGatewayHostname;
            rdpGatewayCredentialId ??= ancestor.RdpGatewayCredentialId;
            rdpGatewayBypassLocal ??= ancestor.RdpGatewayBypassLocal;
            rdpGatewayUseSameCreds ??= ancestor.RdpGatewayUseSameCreds;
            rdpUseExternalClient ??= ancestor.RdpUseExternalClient;
            sshKeyFileName ??= ancestor.SshKeyFileName;
            sshKnownHostFingerprint ??= ancestor.SshKnownHostFingerprint;
            tunnelEnabled ??= ancestor.TunnelEnabled;
            tunnelConfigId ??= ancestor.TunnelConfigId;
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

    private static IEnumerable<ConnectionNode> WalkParents(
        ConnectionNode start, IReadOnlyDictionary<Guid, ConnectionNode> nodesById)
    {
        var seen = new HashSet<Guid>();
        var current = start;
        while (current is not null)
        {
            if (!seen.Add(current.Id))
            {
                throw new InvalidOperationException(
                    $"Detected a cycle in the node tree at '{current.Name}' ({current.Id}).");
            }
            yield return current;
            if (current.ParentId is null) yield break;
            if (!nodesById.TryGetValue(current.ParentId.Value, out var parent))
            {
                yield break;
            }
            current = parent;
        }
    }

    private static int DefaultPortFor(ProtocolType protocol) => protocol switch
    {
        ProtocolType.Ssh => 22,
        ProtocolType.Sftp => 22,
        ProtocolType.Rdp => 3389,
        _ => throw new ArgumentOutOfRangeException(nameof(protocol)),
    };
}

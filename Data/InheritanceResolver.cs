using Wormhole.Helpers;
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
        // Protocol governing the node `port` came from; compared after the walk to reject a port
        // inherited across a protocol boundary (see the discard rule below).
        ProtocolType? portContextProtocol = null;
        string? username = null;
        Guid? credentialId = null;
        ProtocolType? credentialContextProtocol = null;
        var leafUsesInlinePassword = (node.UseInlinePassword ?? false) &&
            FindResolvedProtocol(node, nodesById) is ProtocolType.Ssh or ProtocolType.Rdp;
        var credentialResolved = leafUsesInlinePassword;
        var credentialIdentityBoundaryReached = false;
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
        bool? sshAutoSudo = null;
        int? serialBaudRate = null;
        int? serialDataBits = null;
        SerialStopBitsMode? serialStopBits = null;
        SerialParityMode? serialParity = null;
        SerialFlowControlMode? serialFlowControl = null;
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
            // Once a port is in hand, track the protocol governing the node it came from — its own, or
            // (if that node inherits its protocol) the first an ancestor defines — for the cross-protocol
            // discard below.
            if (port is not null)
            {
                portContextProtocol ??= current.Protocol;
            }
            if (!credentialIdentityBoundaryReached)
            {
                username ??= current.Username;
                rdpDomain ??= current.RdpDomain;
            }
            if (!credentialResolved)
            {
                var resolvesSavedCredential = false;
                var mode = current.CredentialMode;
                if (mode is null)
                {
                    if (current.CredentialId is { } legacyCredentialId)
                    {
                        credentialId = legacyCredentialId;
                        credentialResolved = true;
                        resolvesSavedCredential = true;
                    }
                }
                else if (mode != CredentialBindingMode.Inherit)
                {
                    credentialResolved = true;
                    credentialId = mode == CredentialBindingMode.Saved ? current.CredentialId : null;
                    resolvesSavedCredential = mode == CredentialBindingMode.Saved && current.CredentialId is not null;
                }

                if (resolvesSavedCredential)
                {
                    // A saved credential is an auth identity boundary. Use this node's own
                    // Username/RdpDomain if it has them, but do not mix its password with
                    // identity fields from more distant ancestors.
                    credentialContextProtocol ??= current.Protocol ?? protocol;
                    credentialIdentityBoundaryReached = true;
                }
            }
            rdpScreenSize ??= current.RdpScreenSize ??
                (current.RdpFullScreen == true ? RdpScreenSizes.FullConnectionContent : null);
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
            sshAutoSudo ??= current.SshAutoSudo;
            serialBaudRate ??= current.SerialBaudRate;
            serialDataBits ??= current.SerialDataBits;
            serialStopBits ??= current.SerialStopBits;
            serialParity ??= current.SerialParity;
            serialFlowControl ??= current.SerialFlowControl;
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

        // A port is only meaningful for the protocol it was configured under. When the inherited port
        // came from an ancestor folder governed by a protocol different from this connection's resolved
        // protocol — e.g. an HTTPS appliance GUI or an SSH host dropped into an mRemoteNG-imported RDP
        // folder (Protocol=Rdp + Port=3389) — the inherited port is wrong (the browser/client would dial
        // :3389) and must not carry over. Discard it and fall back to the resolved protocol's default
        // below. This uses the port owner's *governing* protocol (its own or an ancestor's), so a folder
        // that pins a port but inherits its protocol is still caught. When no node at or above the port
        // owner declares any protocol it is a genuinely protocol-agnostic default and is kept; the leaf's
        // own port always shares the connection's protocol context and is likewise kept.
        if (portContextProtocol is { } portContext && portContext != protocol.Value)
        {
            port = null;
        }

        // Web and serial protocols are credential-less, so they drop inherited credentials and SSH identity
        // material. Saved credentials are only inherited across matching protocol contexts; VNC is
        // password-only in v1, so it also drops inherited username and SSH-key metadata.
        var isWeb = protocol.Value is ProtocolType.Http or ProtocolType.Https;
        var isSerial = protocol.Value == ProtocolType.Serial;
        var isVnc = protocol.Value == ProtocolType.Vnc;
        var isCredentialless = isWeb || isSerial;
        var clearsSshIdentity = isCredentialless || isVnc;
        var useInlinePassword = leafUsesInlinePassword;
        var canUseResolvedCredential = !isCredentialless &&
            !useInlinePassword &&
            (credentialContextProtocol is null || credentialContextProtocol == protocol.Value);
        var parentFolderName = node.ParentId is Guid parentIdForDisplay &&
            nodesById.TryGetValue(parentIdForDisplay, out var parentForDisplay) &&
            parentForDisplay.Kind == NodeKind.Folder &&
            !string.IsNullOrWhiteSpace(parentForDisplay.Name)
                ? parentForDisplay.Name
                : null;

        return new ConnectionProfile
        {
            NodeId = node.Id,
            Name = node.Name,
            ParentFolderName = parentFolderName,
            Protocol = protocol.Value,
            Host = host,
            Port = port ?? DefaultPortFor(protocol.Value),
            Username = clearsSshIdentity ? null : username,
            CredentialId = canUseResolvedCredential ? credentialId : null,
            // Inline password is SSH/RDP-only and strictly per-connection - read from the leaf `node`, never
            // inherited up the folder chain. When set, it suppresses any inherited saved credential.
            UseInlinePassword = useInlinePassword,
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
            RdpServerAuthentication = rdpServerAuthentication ?? 2,
            RdpGatewayUsageMethod = rdpGatewayUsageMethod ?? 0,
            RdpGatewayHostname = rdpGatewayHostname,
            RdpGatewayCredentialId = rdpGatewayCredentialId,
            RdpGatewayBypassLocal = rdpGatewayBypassLocal ?? true,
            RdpGatewayUseSameCreds = rdpGatewayUseSameCreds ?? false,
            RdpUseExternalClient = rdpUseExternalClient ?? false,
            SshKeyFileName = clearsSshIdentity ? null : sshKeyFileName,
            SshKnownHostFingerprint = clearsSshIdentity ? null : sshKnownHostFingerprint,
            SshAutoSudo = clearsSshIdentity ? false : sshAutoSudo ?? false,
            SerialBaudRate = SerialDefaults.NormalizeBaudRate(serialBaudRate),
            SerialDataBits = SerialDefaults.NormalizeDataBits(serialDataBits),
            SerialStopBits = SerialDefaults.NormalizeStopBits(serialStopBits),
            SerialParity = SerialDefaults.NormalizeParity(serialParity),
            SerialFlowControl = SerialDefaults.NormalizeFlowControl(serialFlowControl),
            // Per-connection (leaf-only), like UseInlinePassword — NOT inherited up the folder chain.
            // The editor surfaces it as a 2-state checkbox that can't express "inherit", so inheriting it
            // would let an unrelated edit silently sever an inherited value; and the folder editor
            // exposes no control to set it anyway.
            HttpIgnoreCertErrors = node.HttpIgnoreCertErrors ?? false,
            TunnelEnabled = protocol.Value == ProtocolType.Serial ? false : tunnelEnabled ?? false,
            TunnelConfigId = protocol.Value == ProtocolType.Serial ? null : tunnelConfigId,
        };
    }

    private static int DefaultPortFor(ProtocolType protocol) => protocol switch
    {
        ProtocolType.Ssh => 22,
        ProtocolType.Rdp => 3389,
        ProtocolType.Http => 80,
        ProtocolType.Https => 443,
        ProtocolType.Vnc => 5900,
        ProtocolType.Serial => 0,
        _ => throw new ArgumentOutOfRangeException(nameof(protocol)),
    };

    private static ProtocolType? FindResolvedProtocol(
        ConnectionNode node,
        IReadOnlyDictionary<Guid, ConnectionNode> nodesById)
    {
        HashSet<Guid>? seen = null;
        var current = node;
        while (true)
        {
            if (current.Protocol is { } protocol)
            {
                return protocol;
            }
            if (current.ParentId is not Guid parentId || !nodesById.TryGetValue(parentId, out var parent))
            {
                return null;
            }
            if (seen is null)
            {
                seen = new HashSet<Guid>();
                seen.Add(current.Id);
            }
            if (!seen.Add(parent.Id))
            {
                throw new InvalidOperationException(
                    $"Detected a cycle in the node tree at '{parent.Name}' ({parent.Id}).");
            }
            current = parent;
        }
    }
}

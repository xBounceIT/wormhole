package main

import (
	"fmt"
	"runtime"
	"strings"
)

// Share the active RDP resolution, override, system-client and gateway semantics.
// Runtime readers lend credentials; capture readers supply only identity metadata.
func resolveLegacyRDPProfile(database sqlMetadataReader, nodeID string, manual *rdpManualCredential, forSystemClient bool, credentialIDOverride string,
	readCredential func(string) (bitwardenResolvedCredential, error),
	readInline func(string) (string, bool, error),
	observe func(string, string, bool, rdpProfile, workspaceRdpSettings),
) (rdpProfile, error) {
	chain, err := loadRdpNodeChain(database, nodeID)
	if err != nil {
		return rdpProfile{}, err
	}
	firstString := func(column string) string {
		for _, row := range chain {
			if row[column] != nil {
				return strings.TrimSpace(workspaceNodeValueString(row[column]))
			}
		}
		return ""
	}
	firstInt := func(column string) (int, bool) {
		for _, row := range chain {
			if row[column] == nil {
				continue
			}
			value, ok := workspaceNodeValueInt64(row[column])
			return int(value), ok
		}
		return 0, false
	}
	host, port, err := resolveRdpTargetFromChain(chain)
	if err != nil {
		return rdpProfile{}, err
	}
	settings := workspaceRdpSettingsFromChain(chain)
	username, domain, err := resolveNodeRdpIdentity(database, nodeID)
	if err != nil {
		return rdpProfile{}, err
	}
	profile := rdpProfile{
		NodeID: nodeID, Name: firstString("Name"), Host: host, Port: port,
		Username: username, Domain: domain, ScreenSize: settings.ScreenSize,
		FullScreen: settings.FullScreen, ColorDepth: settings.ColorDepth,
		UseAllMonitors: settings.UseAllMonitors, AudioMode: settings.AudioMode,
		AudioCaptureMode: settings.AudioCaptureMode, KeyboardHookMode: settings.KeyboardHookMode,
		RedirectClipboard: settings.RedirectClipboard, RedirectPrinters: settings.RedirectPrinters,
		RedirectSmartCards: settings.RedirectSmartCards, RedirectPorts: settings.RedirectPorts,
		RedirectDevices: settings.RedirectDevices, RedirectDrives: settings.RedirectDrives,
		ConnectionSpeed: settings.ConnectionSpeed, DesktopBackground: settings.DesktopBackground,
		FontSmoothing: settings.FontSmoothing, DesktopComposition: settings.DesktopComposition,
		WindowDrag: settings.WindowDrag, MenuAnimation: settings.MenuAnimation,
		VisualStyles: settings.VisualStyles, BitmapCaching: settings.BitmapCaching,
		AutoReconnect: settings.AutoReconnect, ServerAuthentication: rdpIntPointer(settings.ServerAuthentication),
		GatewayUsageMethod: settings.GatewayUsageMethod, GatewayHostname: settings.GatewayHostname,
		GatewayBypassLocal: settings.GatewayBypassLocal, GatewayUseSameCreds: settings.GatewayUseSameCreds,
		UseExternalClient: settings.UseExternalClient && runtime.GOOS == "windows",
	}
	if enabled, ok := firstInt("TunnelEnabled"); ok {
		value := enabled != 0
		profile.TunnelEnabled = &value
	}
	profile.TunnelConfigID = normalizeTunnelID(firstString("TunnelConfigId"))
	var credentialID string
	credentialID = normalizeID(credentialIDOverride)
	credentialOverride := credentialID != ""
	if manual != nil {
		profile.Username = strings.TrimSpace(manual.Username)
		profile.Domain = strings.TrimSpace(manual.Domain)
		profile.Password = manual.Password
	} else if credentialID == "" && !profile.UseExternalClient && !forSystemClient {
		credentialID, err = resolveNodeCredentialID(database, nodeID, rdpProtocolValue)
		if err != nil {
			return rdpProfile{}, err
		}
	}
	if !profile.UseExternalClient && !forSystemClient {
		requirement, requirementErr := rdpExternalClientRequirementFromDatabase(database, rdpExternalClientRequirementRequest{
			Username: profile.Username, Domain: profile.Domain, CredentialID: credentialID,
		})
		if requirementErr != nil {
			return rdpProfile{}, requirementErr
		}
		profile.UseExternalClient = requirement.Required
	}
	if profile.UseExternalClient || forSystemClient {
		// The system client has no supported secret-bearing launch contract. Do not resolve or
		// return credentials that mstsc cannot consume; Windows will use its own credential UI.
		clearRdpExternalClientCredentials(&profile)
		if manual == nil && credentialIDOverride == "" && !forSystemClient {
			observe(nodeID, "", false, profile, settings)
		}
		return profile, nil
	}

	if manual == nil {
		inline, _ := workspaceNodeValueInt64(chain[0]["UseInlinePassword"])
		if inline != 0 {
			if secret, found, secretErr := readInline(nodeID); secretErr != nil {
				return rdpProfile{}, fmt.Errorf("inline RDP credential is unavailable: %w", secretErr)
			} else if found {
				profile.Password = secret
			}
		} else if credentialID != "" {
			credential, credentialErr := readCredential(credentialID)
			if credentialErr != nil {
				return rdpProfile{}, credentialErr
			}
			if credentialOverride || profile.Username == "" {
				profile.Username = credential.Username
			}
			if credentialOverride || profile.Domain == "" {
				profile.Domain = credential.Domain
			}
			profile.Password = credential.Password
		}
	}
	if profile.Domain == "" {
		profile.Username, profile.Domain = splitRdpDomainUsername(profile.Username)
	}

	if settings.GatewayUsageMethod != 0 {
		if settings.GatewayUseSameCreds {
			profile.GatewayUsername = profile.Username
			profile.GatewayPassword = profile.Password
		} else if settings.GatewayCredentialID != "" {
			gateway, gatewayErr := readCredential(settings.GatewayCredentialID)
			if gatewayErr != nil {
				return rdpProfile{}, fmt.Errorf("RDP Gateway credential is unavailable: %w", gatewayErr)
			}
			profile.GatewayUsername = gateway.Username
			if gateway.Domain != "" && !strings.Contains(gateway.Username, "\\") {
				profile.GatewayUsername = gateway.Domain + "\\" + gateway.Username
			}
			profile.GatewayPassword = gateway.Password
		}
	}
	if manual == nil && credentialIDOverride == "" {
		inline, _ := workspaceNodeValueInt64(chain[0]["UseInlinePassword"])
		observe(nodeID, credentialID, inline != 0, profile, settings)
	}
	return profile, nil
}

package vault

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var rdpSizePattern = regexp.MustCompile(`^(\d{3,5})[xX](\d{3,5})$`)
var rdpDrivesPattern = regexp.MustCompile(`^[A-Za-z](?:\s*,\s*[A-Za-z])*$`)
var rdpCredentialPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// RDPSettings contains only public protocol options. The settings travel inside
// the authenticated protocol bundle; a renderer projection never authorizes them.
type RDPSettings struct {
	Domain               string `json:"domain"`
	ScreenSize           string `json:"screenSize"`
	FullScreen           bool   `json:"fullScreen"`
	ColorDepth           int    `json:"colorDepth"`
	UseAllMonitors       bool   `json:"useAllMonitors"`
	AudioMode            int    `json:"audioMode"`
	AudioCaptureMode     int    `json:"audioCaptureMode"`
	KeyboardHookMode     int    `json:"keyboardHookMode"`
	RedirectClipboard    bool   `json:"redirectClipboard"`
	RedirectPrinters     bool   `json:"redirectPrinters"`
	RedirectSmartCards   bool   `json:"redirectSmartCards"`
	RedirectPorts        bool   `json:"redirectPorts"`
	RedirectDevices      bool   `json:"redirectDevices"`
	RedirectDrives       string `json:"redirectDrives"`
	ConnectionSpeed      int    `json:"connectionSpeed"`
	DesktopBackground    bool   `json:"desktopBackground"`
	FontSmoothing        bool   `json:"fontSmoothing"`
	DesktopComposition   bool   `json:"desktopComposition"`
	WindowDrag           bool   `json:"windowDrag"`
	MenuAnimation        bool   `json:"menuAnimation"`
	VisualStyles         bool   `json:"visualStyles"`
	BitmapCaching        bool   `json:"bitmapCaching"`
	AutoReconnect        bool   `json:"autoReconnect"`
	ServerAuthentication int    `json:"serverAuthentication"`
	GatewayUsageMethod   int    `json:"gatewayUsageMethod"`
	GatewayHostname      string `json:"gatewayHostname"`
	GatewayCredentialID  string `json:"gatewayCredentialId"`
	GatewayBypassLocal   bool   `json:"gatewayBypassLocal"`
	GatewayUseSameCreds  bool   `json:"gatewayUseSameCreds"`
	UseExternalClient    bool   `json:"useExternalClient"`
}

func DefaultRDPSettings() RDPSettings {
	return RDPSettings{
		ScreenSize: "fitToWindow", ColorDepth: 32, KeyboardHookMode: 2,
		RedirectClipboard: true, ConnectionSpeed: 7, DesktopBackground: true,
		FontSmoothing: true, DesktopComposition: true, WindowDrag: true,
		MenuAnimation: true, VisualStyles: true, BitmapCaching: true,
		AutoReconnect: true, ServerAuthentication: 2, GatewayBypassLocal: true,
	}
}

func NormalizeRDPSettings(value *RDPSettings) (RDPSettings, error) {
	if value == nil {
		return DefaultRDPSettings(), nil
	}
	settings := *value
	settings.Domain = strings.TrimSpace(settings.Domain)
	settings.ScreenSize = strings.TrimSpace(settings.ScreenSize)
	settings.GatewayHostname = strings.TrimSpace(settings.GatewayHostname)
	settings.GatewayCredentialID = strings.ToLower(strings.TrimSpace(settings.GatewayCredentialID))
	settings.RedirectDrives = NormalizeRDPDriveList(settings.RedirectDrives)
	if settings.ScreenSize == "" {
		settings.ScreenSize = "fitToWindow"
	}
	if !ValidRDPScreenSize(settings.ScreenSize) || !ValidRDPText(settings.Domain, 512) ||
		(settings.GatewayHostname != "" && !ValidRDPHost(settings.GatewayHostname)) {
		return RDPSettings{}, errors.New("RDP text settings are invalid")
	}
	if settings.GatewayUsageMethod == 1 && settings.GatewayHostname == "" {
		return RDPSettings{}, errors.New("RDP Gateway hostname is required")
	}
	if settings.GatewayCredentialID != "" && !validRDPCredentialID(settings.GatewayCredentialID) {
		return RDPSettings{}, errors.New("RDP Gateway credential id is invalid")
	}
	if !containsRDPInt([]int{15, 16, 24, 32}, settings.ColorDepth) ||
		settings.AudioMode < 0 || settings.AudioMode > 2 ||
		settings.AudioCaptureMode < 0 || settings.AudioCaptureMode > 1 ||
		settings.KeyboardHookMode < 0 || settings.KeyboardHookMode > 2 ||
		settings.ConnectionSpeed < 1 || settings.ConnectionSpeed > 7 ||
		settings.ServerAuthentication < 0 || settings.ServerAuthentication > 2 ||
		settings.GatewayUsageMethod < 0 || settings.GatewayUsageMethod > 3 {
		return RDPSettings{}, errors.New("RDP numeric settings are invalid")
	}
	if settings.RedirectDrives != "" && settings.RedirectDrives != "all" &&
		(!rdpDrivesPattern.MatchString(settings.RedirectDrives) || len(settings.RedirectDrives) > 128) {
		return RDPSettings{}, errors.New("RDP drive redirection is invalid")
	}
	return settings, nil
}

func ValidRDPText(value string, maximum int) bool {
	return utf8.RuneCountInString(value) <= maximum && !strings.ContainsAny(value, "\r\n\x00")
}

func ValidRDPHost(value string) bool {
	return ValidRDPText(value, 253) && !strings.ContainsFunc(value, func(character rune) bool {
		return unicode.IsControl(character) || unicode.IsSpace(character)
	})
}

func ValidRDPScreenSize(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "fittowindow", "full connection content", "full screen":
		return true
	}
	match := rdpSizePattern.FindStringSubmatch(value)
	if len(match) != 3 {
		return false
	}
	var width, height int
	_, widthErr := fmt.Sscan(match[1], &width)
	_, heightErr := fmt.Sscan(match[2], &height)
	return widthErr == nil && heightErr == nil && width >= 640 && width <= 16384 && height >= 480 && height <= 16384
}

func NormalizeRDPDriveList(value string) string {
	value = strings.TrimSpace(value)
	if strings.EqualFold(value, "all") {
		return "all"
	}
	if value == "" {
		return ""
	}
	parts := strings.Split(value, ",")
	for index := range parts {
		parts[index] = strings.ToUpper(strings.TrimSpace(parts[index]))
	}
	return strings.Join(parts, ",")
}

func containsRDPInt(values []int, candidate int) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func NormalizePersistedRDPSettings(settings RDPSettings) RDPSettings {
	defaults := DefaultRDPSettings()
	if !ValidRDPText(settings.Domain, 512) {
		settings.Domain = defaults.Domain
	}
	if !ValidRDPScreenSize(settings.ScreenSize) {
		settings.ScreenSize = defaults.ScreenSize
	}
	if !containsRDPInt([]int{15, 16, 24, 32}, settings.ColorDepth) {
		settings.ColorDepth = defaults.ColorDepth
	}
	if settings.AudioMode < 0 || settings.AudioMode > 2 {
		settings.AudioMode = defaults.AudioMode
	}
	if settings.AudioCaptureMode < 0 || settings.AudioCaptureMode > 1 {
		settings.AudioCaptureMode = defaults.AudioCaptureMode
	}
	if settings.KeyboardHookMode < 0 || settings.KeyboardHookMode > 2 {
		settings.KeyboardHookMode = defaults.KeyboardHookMode
	}
	if settings.ConnectionSpeed < 1 || settings.ConnectionSpeed > 7 {
		settings.ConnectionSpeed = defaults.ConnectionSpeed
	}
	if settings.ServerAuthentication < 0 || settings.ServerAuthentication > 2 {
		settings.ServerAuthentication = defaults.ServerAuthentication
	}
	if settings.GatewayUsageMethod < 0 || settings.GatewayUsageMethod > 3 ||
		(settings.GatewayUsageMethod == 1 && strings.TrimSpace(settings.GatewayHostname) == "") {
		settings.GatewayUsageMethod = defaults.GatewayUsageMethod
	}
	if settings.GatewayHostname != "" && !ValidRDPHost(settings.GatewayHostname) {
		settings.GatewayHostname = defaults.GatewayHostname
		settings.GatewayUsageMethod = defaults.GatewayUsageMethod
	}
	if settings.GatewayCredentialID != "" && !validRDPCredentialID(settings.GatewayCredentialID) {
		settings.GatewayCredentialID = defaults.GatewayCredentialID
	}
	if settings.RedirectDrives != "" && settings.RedirectDrives != "all" &&
		(!rdpDrivesPattern.MatchString(settings.RedirectDrives) || len(settings.RedirectDrives) > 128) {
		settings.RedirectDrives = defaults.RedirectDrives
	}
	return settings
}

func validRDPCredentialID(id string) bool { return rdpCredentialPattern.MatchString(id) }

// The persisted external-client preference means Windows mstsc. Native FreeRDP
// remains the adapter on other platforms, matching the existing resolver rules.
func RDPSettingsForPlatform(settings RDPSettings, operatingSystem string) RDPSettings {
	if operatingSystem != "windows" {
		settings.UseExternalClient = false
	}
	return settings
}

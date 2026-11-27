package main

import "github.com/godbus/dbus/v5"

const (
	linuxLoginService     = "org.freedesktop.login1"
	linuxLoginSession     = linuxLoginService + ".Session"
	linuxSessionNamespace = "/org/freedesktop/login1/session"
	linuxPropertiesSignal = "org.freedesktop.DBus.Properties.PropertiesChanged"
)

// Some desktops still expose their own ScreenSaver interface. Every accepted
// endpoint is paired with the well-known name that must own its sender.
var linuxScreenSaverPaths = map[string][]dbus.ObjectPath{
	"org.freedesktop.ScreenSaver": {"/org/freedesktop/ScreenSaver", "/ScreenSaver"},
	"org.gnome.ScreenSaver":       {"/org/gnome/ScreenSaver"},
	"org.cinnamon.ScreenSaver":    {"/org/cinnamon/ScreenSaver"},
}

// Returns the service whose ownership must be verified, or "" for a message
// that does not request a lock. Bus and session identity are checked separately.
func linuxVaultLockService(signal *dbus.Signal, system bool) string {
	if signal == nil {
		return ""
	}
	if system {
		switch signal.Name {
		case linuxLoginSession + ".Lock":
			if len(signal.Body) == 0 {
				return linuxLoginService
			}
		case linuxPropertiesSignal:
			if linuxSessionBecameLocked(signal.Body) {
				return linuxLoginService
			}
		}
		return ""
	}
	if len(signal.Body) != 1 || signal.Body[0] != true {
		return ""
	}
	for name, paths := range linuxScreenSaverPaths {
		if signal.Name == name+".ActiveChanged" {
			for _, path := range paths {
				if signal.Path == path {
					return name
				}
			}
		}
	}
	return ""
}

func linuxSessionBecameLocked(body []any) bool {
	if len(body) != 3 || body[0] != linuxLoginSession {
		return false
	}
	changed, ok := body[1].(map[string]dbus.Variant)
	invalidated, namesOK := body[2].([]string)
	if !ok || !namesOK {
		return false
	}
	// If logind invalidates either property, do not assume the old state
	// remains current. Neither an unlock nor an active notification unlocks us.
	for _, name := range invalidated {
		if name == "Active" || name == "LockedHint" {
			return true
		}
	}
	for name, lockValue := range map[string]bool{"Active": false, "LockedHint": true} {
		if field, exists := changed[name]; exists {
			if value, valid := field.Value().(bool); !valid || value == lockValue {
				return true
			}
		}
	}
	return false
}

func linuxLoginOwnerChanged(signal *dbus.Signal) bool {
	if signal == nil || signal.Sender != "org.freedesktop.DBus" || signal.Path != "/org/freedesktop/DBus" ||
		signal.Name != "org.freedesktop.DBus.NameOwnerChanged" || len(signal.Body) != 3 ||
		signal.Body[0] != linuxLoginService {
		return false
	}
	previous, previousOK := signal.Body[1].(string)
	next, nextOK := signal.Body[2].(string)
	return previousOK && nextOK && previous != next
}

package main

import (
	"encoding/json"
	"errors"
)

const lastVisualChangelogVersionKey = "LastVisualChangelogVersion"

func parseVisualChangelogVersion(raw string) (appVersion, bool) {
	version, valid := parseAppVersion(raw)
	return version, valid && version.length == 3 && version.String() == raw
}

// Record stable launches without slides too, so even an unseen older release cannot
// appear after a downgrade. Claims and the version record share one transaction.
func claimVisualChangelog(databasePath, appVersion string, hasChangelog bool) (bool, error) {
	version, valid := parseVisualChangelogVersion(appVersion)
	if !valid {
		return false, nil
	}

	_, settingsPath := authPaths(databasePath)
	claimed := false
	err := updateSettingsDocumentWithOptions(settingsPath, settingsDocumentUpdateOptions{}, func(document map[string]json.RawMessage) (bool, error) {
		if stored, exists := document[lastVisualChangelogVersionKey]; exists {
			var lastVersion string
			if err := json.Unmarshal(stored, &lastVersion); err != nil {
				return false, err
			}
			last, valid := parseVisualChangelogVersion(lastVersion)
			if !valid {
				return false, errors.New("invalid recorded visual changelog version")
			}
			if !last.lessThan(version) {
				return false, nil
			}
		}
		document[lastVisualChangelogVersionKey], _ = json.Marshal(appVersion)
		claimed = hasChangelog && version.components[2] == 0
		return true, nil
	})
	return claimed && err == nil, err
}

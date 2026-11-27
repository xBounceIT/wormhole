package main

import "testing"

func TestLegacySSHUsernamePresenceSurvivesImportRebase(t *testing.T) {
	for _, test := range []struct {
		name, username, parentName, want string
		selected, parentSelected         bool
	}{
		{name: "absent", parentName: "parent-user", want: "parent-user"},
		{name: "explicit-empty", selected: true, parentName: "parent-user"},
		{name: "explicit", selected: true, username: " chosen ", parentName: "parent-user", want: "chosen"},
		{name: "legacy-nonempty", username: " legacy ", parentName: "parent-user", want: "legacy"},
		{name: "parent-explicit-empty", parentSelected: true},
		{name: "parent-absent", want: "grandparent-user"},
	} {
		t.Run(test.name, func(t *testing.T) {
			protocol := int64(0)
			nodes := map[string]*sshNode{
				"root":        {id: "root", parentID: "parent", kind: 1, host: "server.invalid", protocol: &protocol, useInlinePassword: true, username: test.username, usernameSet: test.selected},
				"parent":      {id: "parent", parentID: "grandparent", username: test.parentName, usernameSet: test.parentSelected},
				"grandparent": {id: "grandparent", username: "grandparent-user", usernameSet: true},
			}
			target, inline, err := resolveLegacySSHMetadata(nodes, "root")
			if err != nil || !inline || target.username != test.want {
				t.Fatal("explicit username presence was lost between active SSH and migration capture", target.username, err)
			}
		})
	}
}

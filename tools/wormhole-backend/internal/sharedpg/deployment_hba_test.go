package sharedpg

import (
	"errors"
	"strings"
	"testing"
)

func TestDeploymentHBARules(t *testing.T) {
	const tag = "testscope"
	got, err := DeploymentHBARules("all", tag, testHintID, []string{"192.0.2.9", "192.0.2.9/32", "2001:0db8::/64", "::1"})
	const scope = `"all" /^wh_testscope_`
	want := "hostssl " + scope + " 192.0.2.9/32 scram-sha-256\n" +
		"hostssl " + scope + " 2001:db8::/64 scram-sha-256\n" +
		"hostssl " + scope + " ::1/128 scram-sha-256\n" +
		"host " + scope + " all reject\n"
	if err != nil || !strings.HasSuffix(got, "\n"+want) {
		t.Fatal("unexpected workspace rules", got, err)
	}
	for _, networks := range [][]string{nil, make([]string, 33), {""}, {"192.0.2.17/24"}, {"::1/0"}, {"fe80::1%eth0"}, {"db.example"}, {"127.0.0.1\nhost all all all trust"}} {
		if partial, err := DeploymentHBARules("vault", tag, testHintID, networks); partial != "" || !errors.Is(err, ErrConfiguration) {
			t.Fatal("invalid network list produced a file", networks, err)
		}
	}
	for _, inputs := range [][3]string{{"public,all", tag, testHintID}, {"vault", "foreign.*", testHintID}, {"vault", tag, ""}} {
		if partial, err := DeploymentHBARules(inputs[0], inputs[1], inputs[2], []string{"::1"}); partial != "" || !errors.Is(err, ErrConfiguration) {
			t.Fatal("invalid workspace selectors accepted", inputs)
		}
	}
}

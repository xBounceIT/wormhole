package ospolicy

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestUnixInstallationLayout(t *testing.T) {
	const linux = "/opt/Wormhole"
	const mac = "/Applications/Wormhole.app"
	for _, c := range []struct{ platform, frontend, backend, want string }{
		{"linux", linux + "/wormhole", linux + "/resources/wormhole-backend-arm64", linux},
		{"linux", linux + "/Wormhole", linux + "/resources/wormhole-backend-x64", ""},
		{"linux", linux + "/wormhole", "/different/resources/wormhole-backend-x64", ""},
		{"linux", linux + "/wormhole", linux + "/resources/../resources/wormhole-backend-x64", ""},
		{"linux", "wormhole", linux + "/resources/wormhole-backend-x64", ""},
		{"linux", "/wormhole", "/resources/wormhole-backend-x64", ""},
		{"linux", linux + "/wormhole", linux + "/resources/wormhole-backend-universal", ""},
		{"linux", linux + "/wormhole\x00", linux + "/resources/wormhole-backend-x64", ""},
		{"linux", "/" + strings.Repeat("x", 4096) + "/wormhole", linux + "/resources/wormhole-backend-x64", ""},
		{"darwin", mac + "/Contents/MacOS/Wormhole", mac + "/Contents/Resources/wormhole-backend-universal", mac},
		{"darwin", mac + "/Contents/MacOS/Wormhole", mac + "/Contents/Resources/wormhole-backend-x64", mac},
		{"darwin", mac + "/Contents/Helpers/Wormhole", mac + "/Contents/Resources/wormhole-backend-x64", ""},
		{"darwin", "/opt/Wormhole/Contents/MacOS/Wormhole", "/opt/Wormhole/Contents/Resources/wormhole-backend-x64", ""},
		{"darwin", mac + "/Contents/MacOS/wormhole", mac + "/Contents/Resources/wormhole-backend-x64", ""},
		{"other", linux + "/wormhole", linux + "/resources/wormhole-backend-x64", ""},
	} {
		root, err := unixInstallationRoot(c.platform, c.frontend, c.backend)
		if root != c.want || (err == nil) != (c.want != "") {
			t.Fatalf("layout %q %q %q returned %q %v", c.platform, c.frontend, c.backend, root, err)
		}
	}
}

func TestDarwinACLRejectsMutationAndMalformedSecurityAttributes(t *testing.T) {
	put := binary.NativeEndian.PutUint32
	none := make([]byte, 12)
	put(none, 12)
	acl := func(count uint32, entries ...[2]uint32) []byte {
		t.Helper()
		raw := make([]byte, 12+44+24*len(entries))
		put(raw, uint32(len(raw)))
		put(raw[4:], 8)
		put(raw[8:], uint32(len(raw)-12))
		put(raw[12:], 0x012cc16d)
		put(raw[48:], count)
		for i, entry := range entries {
			put(raw[72+i*24:], entry[0])
			put(raw[76+i*24:], entry[1])
		}
		return raw
	}
	for _, c := range []struct {
		name string
		raw  []byte
		want bool
	}{
		{"none", none, true},
		{"explicitly absent", acl(^uint32(0)), true},
		{"empty", acl(0), true},
		{"read and search", acl(1, [2]uint32{1, (1 << 1) | (1 << 3) | (1 << 24)}), true},
		{"deny writes", acl(1, [2]uint32{2, 1 << 2}), true},
		{"inherit only", acl(1, [2]uint32{1 | (1 << 8), 1 << 4}), true},
		{"grant file mutation", acl(1, [2]uint32{1, 1 << 2}), false},
		{"grant child replacement", acl(1, [2]uint32{1, 1 << 6}), false},
		{"grant writes through generic rights", acl(1, [2]uint32{1, 1 << 23}), false},
		{"grant ownership", acl(1, [2]uint32{1, 1 << 13}), false},
		{"unknown ACE kind", acl(1, [2]uint32{4, 0}), false},
		{"entry count mismatch", acl(2, [2]uint32{2, 1 << 2}), false},
		{"oversize ACL", acl(129), false},
		{"unexpected no-ACL payload", acl(^uint32(0), [2]uint32{2, 1 << 2}), false},
		{"truncated", acl(0)[:55], false},
		{"short header", none[:4], false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if protectedDarwinACL(c.raw) != c.want {
				t.Fatal("unexpected ACL decision")
			}
		})
	}
	bad := acl(0)
	put(bad[4:], ^uint32(0))
	if protectedDarwinACL(bad) {
		t.Fatal("negative reference was accepted")
	}
	bad = acl(0)
	put(bad[12:], 0)
	if protectedDarwinACL(bad) {
		t.Fatal("unexpected filesec magic was accepted")
	}
}

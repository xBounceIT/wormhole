package resolver

import (
	"reflect"
	"strings"
	"testing"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vaultstore"
)

func TestRDPSettingsProjectionPreservesNullFalseAndZeroInheritance(t *testing.T) {
	// Every signed RDP option participates, including fields absent from Plan v1.
	var parent, leaf vaultstore.NodeMetadata
	parentValue, leafValue := reflect.ValueOf(&parent).Elem(), reflect.ValueOf(&leaf).Elem()
	for i := 0; i < parentValue.NumField(); i++ {
		field := parentValue.Type().Field(i)
		if !strings.HasPrefix(field.Name, "RDP") {
			continue
		}
		value := parentValue.Field(i)
		ptr := reflect.New(value.Type().Elem())
		switch ptr.Elem().Kind() {
		case reflect.String:
			ptr.Elem().SetString("parent")
		case reflect.Int:
			ptr.Elem().SetInt(1)
		case reflect.Bool:
			ptr.Elem().SetBool(true)
		}
		value.Set(ptr)
	}
	inherited := ProjectRDPSettings([]vaultstore.NodeMetadata{leaf, parent})
	inheritedValue := reflect.ValueOf(inherited)
	for i := 0; i < parentValue.NumField(); i++ {
		field := parentValue.Type().Field(i)
		if !strings.HasPrefix(field.Name, "RDP") {
			continue
		}
		projected := inheritedValue.FieldByName(strings.TrimPrefix(field.Name, "RDP"))
		if !projected.IsValid() || !reflect.DeepEqual(projected.Interface(), parentValue.Field(i).Elem().Interface()) {
			t.Fatal("RDP option failed inheritance", field.Name)
		}
	}
	for i := 0; i < parentValue.NumField(); i++ {
		field := parentValue.Type().Field(i)
		if strings.HasPrefix(field.Name, "RDP") {
			leafValue.Field(i).Set(reflect.New(leafValue.Field(i).Type().Elem()))
		}
	}
	explicit := ProjectRDPSettings([]vaultstore.NodeMetadata{leaf, parent})
	if explicit != (vault.RDPSettings{}) || inherited.Domain != "parent" || inherited.GatewayHostname != "parent" || !inherited.RedirectClipboard || inherited.ColorDepth != 1 {
		t.Fatal("RDP inheritance lost explicit zero/false/empty")
	}
	if ProjectRDPSettings(nil) != vault.DefaultRDPSettings() {
		t.Fatal("RDP defaults changed")
	}
}

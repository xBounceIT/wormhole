// Package ospolicy reads only machine-managed security policy. User settings,
// environment overrides and subprocess output are never policy authorities.
package ospolicy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"io"

	"github.com/xBounceIT/wormhole/tools/wormhole-backend/internal/vault"
	"howett.net/plist"
)

const maxPolicyBytes = 4096

// ManagedUpdate identifies one exact manifest approved by the administrator.
// An empty digest means no approval is configured.
type ManagedUpdate struct {
	Directory string
	Digest    string
}

func ReadManagedUpdate(ctx context.Context) (ManagedUpdate, error) {
	if err := ctx.Err(); err != nil {
		return ManagedUpdate{}, err
	}
	approval, err := readManagedUpdate(ctx)
	if canceled := ctx.Err(); canceled != nil {
		return ManagedUpdate{}, canceled
	}
	return approval, err
}

func parseManagedUpdateDigest(raw []byte) (string, error) {
	value := string(bytes.TrimSpace(raw))
	digest, err := hex.DecodeString(value)
	if err != nil || len(digest) != sha256.Size {
		return "", vault.ErrPolicy
	}
	return hex.EncodeToString(digest), nil
}

func profile(value string) (vault.Profile, error) {
	switch vault.Profile(value) {
	case vault.Default, vault.Standard, vault.Hardened, vault.Paranoid:
		return vault.Profile(value), nil
	default:
		return "", vault.ErrPolicy
	}
}

func ReadFloor(ctx context.Context) (vault.Profile, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	floor, err := readFloor(ctx)
	if canceled := ctx.Err(); canceled != nil {
		return "", canceled
	}
	return floor, err
}

// The Linux document has exactly one case-sensitive member. A present empty
// object is a malformed policy, not the absence of an administrator's floor.
func parseJSON(raw []byte) (vault.Profile, error) {
	if len(raw) == 0 || len(raw) > maxPolicyBytes {
		return "", vault.ErrPolicy
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return "", vault.ErrPolicy
	}
	name, err := d.Token()
	if err != nil || name != "profile" {
		return "", vault.ErrPolicy
	}
	var value string
	if d.Decode(&value) != nil || d.More() {
		return "", vault.ErrPolicy
	}
	if t, err = d.Token(); err != nil || t != json.Delim('}') {
		return "", vault.ErrPolicy
	}
	if _, err := d.Token(); err != io.EOF {
		return "", vault.ErrPolicy
	}
	return profile(value)
}

// Restrict the binary plist object graph before invoking the general decoder.
// A machine floor has one dictionary entry and two short strings. This also
// prevents duplicate keys, nested containers and oversized length allocations.
func boundedBinaryPolicy(raw []byte) bool {
	if len(raw) < 40 || !bytes.Equal(raw[:8], []byte("bplist00")) {
		return false
	}
	t := raw[len(raw)-32:]
	width, refWidth := int(t[6]), int(t[7])
	count, root, table := binary.BigEndian.Uint64(t[8:]), binary.BigEndian.Uint64(t[16:]), binary.BigEndian.Uint64(t[24:])
	if width < 1 || width > 8 || refWidth < 1 || refWidth > 8 || count != 3 || root >= count || table < 8 || table > uint64(len(raw)-32) || uint64(width)*count != uint64(len(raw)-32)-table {
		return false
	}
	read := func(b []byte) uint64 {
		var result uint64
		for _, v := range b {
			result = result<<8 | uint64(v)
		}
		return result
	}
	seen := make(map[uint64]bool, 3)
	for i := uint64(0); i < count; i++ {
		off := read(raw[table+i*uint64(width) : table+(i+1)*uint64(width)])
		if off < 8 || off >= table || seen[off] {
			return false
		}
		seen[off] = true
		tag := raw[off]
		if i == root {
			if tag != 0xd1 || uint64(1+2*refWidth) > table-off {
				return false
			}
			a, b := read(raw[off+1:off+1+uint64(refWidth)]), read(raw[off+1+uint64(refWidth):off+1+uint64(2*refWidth)])
			if a >= count || b >= count || a == b || a == root || b == root {
				return false
			}
		} else {
			length := uint64(tag & 15)
			if length < 7 || length > 8 || (tag>>4 != 5 && tag>>4 != 6) {
				return false
			}
			if tag>>4 == 6 {
				length *= 2
			}
			if length+1 > table-off {
				return false
			}
		}
	}
	return true
}

func boundedXMLPolicy(raw []byte) bool {
	d := xml.NewDecoder(bytes.NewReader(raw))
	// The exact element order makes duplicate keys and nested values invalid.
	expected := []string{"plist", "dict", "key", "/key", "string", "/string", "/dict", "/plist"}
	index := 0
	for {
		token, err := d.Token()
		if err == io.EOF {
			return index == len(expected)
		}
		if err != nil {
			return false
		}
		var name string
		switch t := token.(type) {
		case xml.StartElement:
			if t.Name.Space != "" || (t.Name.Local != "plist" && len(t.Attr) != 0) {
				return false
			}
			if t.Name.Local == "plist" {
				if len(t.Attr) > 1 || (len(t.Attr) == 1 && (t.Attr[0].Name.Space != "" || t.Attr[0].Name.Local != "version" || t.Attr[0].Value != "1.0")) {
					return false
				}
			}
			name = t.Name.Local
		case xml.EndElement:
			name = "/" + t.Name.Local
		case xml.CharData:
			if index != 3 && index != 5 && len(bytes.TrimSpace(t)) != 0 {
				return false
			}
		case xml.Comment, xml.ProcInst, xml.Directive:
			continue
		default:
			return false
		}
		if name != "" {
			if index >= len(expected) || name != expected[index] {
				return false
			}
			index++
		}
	}
}

func parsePlist(raw []byte) (vault.Profile, error) {
	if len(raw) == 0 || len(raw) > maxPolicyBytes || (!boundedBinaryPolicy(raw) && !boundedXMLPolicy(raw)) {
		return "", vault.ErrPolicy
	}
	var values map[string]any
	if _, err := plist.Unmarshal(raw, &values); err != nil || len(values) != 1 {
		return "", vault.ErrPolicy
	}
	value, ok := values["Profile"].(string)
	if !ok {
		return "", vault.ErrPolicy
	}
	return profile(value)
}

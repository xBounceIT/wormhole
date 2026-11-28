package ospolicy

import "encoding/binary"

// protectedDarwinACL decodes the single ATTR_CMN_EXTENDED_SECURITY result.
// Go's mode bits alone miss macOS ACLs that grant writes to additional users.
func protectedDarwinACL(raw []byte) bool {
	const referenceSize, filesecHeaderSize, aceSize = 12, 44, 24
	const filesecMagic, noACL = 0x012cc16d, ^uint32(0)
	const acePermit, aceDeny, inheritOnly = 1, 2, 1 << 8
	const readRights = (1 << 1) | (1 << 3) | (1 << 7) | (1 << 9) | (1 << 11) | (1 << 20) | (1 << 22) | (1 << 24)
	if len(raw) < referenceSize {
		return false
	}
	read := binary.NativeEndian.Uint32
	size := int64(read(raw))
	if size < referenceSize || size > int64(len(raw)) {
		return false
	}
	offset, length := 4+int64(int32(read(raw[4:]))), int64(read(raw[8:]))
	if length == 0 {
		return size == referenceSize
	}
	if offset != referenceSize || length < filesecHeaderSize || offset+length != size {
		return false
	}
	acl := raw[offset : offset+length]
	if read(acl) != filesecMagic {
		return false
	}
	count := read(acl[36:])
	if count == noACL {
		return length == filesecHeaderSize
	}
	if count > 128 || length != filesecHeaderSize+aceSize*int64(count) {
		return false
	}
	for off := filesecHeaderSize; off < len(acl); off += aceSize {
		flags, rights := read(acl[off+16:]), read(acl[off+20:])
		if flags&inheritOnly != 0 {
			continue // WalkDir verifies the effective grants on each child.
		}
		switch flags & 0xf {
		case aceDeny:
		case acePermit:
			if rights&^uint32(readRights) != 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

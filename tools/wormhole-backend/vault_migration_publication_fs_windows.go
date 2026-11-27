package main

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// NtCreateFile and FileRenameInformation use the already-open directory handle
// for BOTH names. No Win32 absolute path can follow a replaced parent directory.
// WRITE_THROUGH plus FlushFileBuffers retains the native durable-write policy.
func renameLegacyPublicationRootFile(root *os.Root, from, to string, replace bool) error {
	if !legacyPublicationFilename(from) || !legacyPublicationFilename(to) {
		return errVaultSlotStorage
	}
	before, err := root.Lstat(from)
	if err != nil || !before.Mode().IsRegular() {
		return errVaultSlotStorage
	}
	parent, err := root.Open(".")
	if err != nil {
		return err
	}
	defer parent.Close()
	name, err := windows.NewNTUnicodeString(from)
	if err != nil {
		return err
	}
	oa := windows.OBJECT_ATTRIBUTES{RootDirectory: windows.Handle(parent.Fd()), ObjectName: name, Attributes: windows.OBJ_DONT_REPARSE}
	oa.Length = uint32(unsafe.Sizeof(oa))
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.DELETE, &oa, &status, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_WRITE_THROUGH, 0, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(handle), from)
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return errVaultSlotStorage
	}
	target, err := windows.UTF16FromString(to)
	if err != nil {
		return err
	}
	type renameInformation struct {
		Flags         uint32
		RootDirectory windows.Handle
		NameLength    uint32
		Name          [1]uint16
	}
	var layout renameInformation
	nameBytes := (len(target) - 1) * 2
	buffer := make([]byte, int(unsafe.Offsetof(layout.Name))+nameBytes)
	info := (*renameInformation)(unsafe.Pointer(&buffer[0]))
	if replace {
		info.Flags = windows.FILE_RENAME_REPLACE_IF_EXISTS
	}
	info.RootDirectory = windows.Handle(parent.Fd())
	info.NameLength = uint32(nameBytes)
	copy(unsafe.Slice(&info.Name[0], len(target)-1), target[:len(target)-1])
	if err := windows.NtSetInformationFile(handle, &status, &buffer[0], uint32(len(buffer)), windows.FileRenameInformation); err != nil {
		return err
	}
	return file.Sync()
}

func syncLegacyPublicationRoot(*os.Root) error {
	// Directory FlushFileBuffers is unavailable on Windows. Rename's source is
	// opened with FILE_WRITE_THROUGH and explicitly flushed above.
	return nil
}

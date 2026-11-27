package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	processChildProcessPolicy  = 13
	noChildProcessCreation     = 1 << 0
	allowSecureProcessCreation = 1 << 2
)

var (
	vaultChildPolicyKernel = windows.NewLazySystemDLL("kernel32.dll")
	vaultSetChildPolicy    = vaultChildPolicyKernel.NewProc("SetProcessMitigationPolicy")
	vaultGetChildPolicy    = vaultChildPolicyKernel.NewProc("GetProcessMitigationPolicy")
)

func enforceVaultChildProcessPolicy() bool {
	if vaultSetChildPolicy.Find() != nil || vaultGetChildPolicy.Find() != nil {
		return false
	}
	flags := uint32(noChildProcessCreation)
	// A launcher can already have applied the same restriction. Verify the
	// effective kernel policy even if reapplying it fails.
	vaultSetChildPolicy.Call(processChildProcessPolicy, uintptr(unsafe.Pointer(&flags)), unsafe.Sizeof(flags))
	flags = 0
	get, _, _ := vaultGetChildPolicy.Call(uintptr(windows.CurrentProcess()), processChildProcessPolicy, uintptr(unsafe.Pointer(&flags)), unsafe.Sizeof(flags))
	return get != 0 && flags&(noChildProcessCreation|allowSecureProcessCreation) == noChildProcessCreation
}

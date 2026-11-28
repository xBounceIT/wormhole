package main

import "golang.org/x/net/bpf"

const (
	linuxSeccompKillProcess = 0x80000000
	linuxSeccompAllow       = 0x7fff0000
	linuxSeccompDeny        = 0x00050000 | 1  // EPERM
	linuxSeccompUnavailable = 0x00050000 | 38 // ENOSYS
	linuxCloneThread        = 0x00010000
	linuxAuditAMD64         = 0xc000003e
)

type vaultLinuxProcessABI struct {
	arch, clone, clone3 uint32
	execOrFork          []uint32
}

// Use only seccomp_data words shared by the supported little-endian ABIs.
// Offsets 0 and 4 are the syscall number and audit architecture. Offset 16
// reads the low word of the first argument, where clone takes its flags.
func vaultLinuxChildProcessFilter(abi vaultLinuxProcessABI) ([]bpf.RawInstruction, error) {
	filter := []bpf.Instruction{
		bpf.LoadAbsolute{Off: 4, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: abi.arch, SkipTrue: 1},
		bpf.RetConstant{Val: linuxSeccompKillProcess},
		bpf.LoadAbsolute{Off: 0, Size: 4},
	}
	if abi.arch == linuxAuditAMD64 {
		// x32 shares the AMD64 audit architecture. Its syscall bit and the
		// legacy x32-only number range must not reach the native allow path.
		filter = append(filter,
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 1 << 30, SkipFalse: 1},
			bpf.RetConstant{Val: linuxSeccompDeny},
			bpf.JumpIf{Cond: bpf.JumpGreaterOrEqual, Val: 512, SkipFalse: 2},
			bpf.JumpIf{Cond: bpf.JumpLessThan, Val: 548, SkipFalse: 1},
			bpf.RetConstant{Val: linuxSeccompDeny},
		)
	}
	for _, number := range abi.execOrFork {
		filter = append(filter,
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: number, SkipFalse: 1},
			bpf.RetConstant{Val: linuxSeccompDeny},
		)
	}
	// clone3 stores flags behind a pointer. ENOSYS lets thread libraries
	// fall back to clone, whose flags seccomp can inspect.
	return bpf.Assemble(append(filter,
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: abi.clone3, SkipFalse: 1},
		bpf.RetConstant{Val: linuxSeccompUnavailable},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: abi.clone, SkipTrue: 1},
		bpf.RetConstant{Val: linuxSeccompAllow},
		bpf.LoadAbsolute{Off: 16, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: linuxCloneThread, SkipFalse: 1},
		bpf.RetConstant{Val: linuxSeccompAllow},
		bpf.RetConstant{Val: linuxSeccompDeny},
	))
}

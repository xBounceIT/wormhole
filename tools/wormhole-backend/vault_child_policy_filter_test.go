package main

import (
	"encoding/binary"
	"testing"

	"golang.org/x/net/bpf"
)

func TestVaultLinuxChildFilter(t *testing.T) {
	for _, target := range []struct {
		name string
		abi  vaultLinuxProcessABI
	}{
		{"amd64", vaultLinuxProcessABI{0xc000003e, 56, 435, []uint32{57, 58, 59, 322}}},
		{"arm64", vaultLinuxProcessABI{0xc00000b7, 220, 435, []uint32{221, 281}}},
	} {
		t.Run(target.name, func(t *testing.T) {
			raw, err := vaultLinuxChildProcessFilter(target.abi)
			if err != nil {
				t.Fatal(err)
			}
			program, ok := bpf.Disassemble(raw)
			if !ok {
				t.Fatal("invalid instructions")
			}
			machine, err := bpf.NewVM(program)
			if err != nil {
				t.Fatal(err)
			}
			check := func(name string, number, arch, flags, want uint32) {
				t.Helper()
				// The portable VM expects words in network byte order. A
				// Linux seccomp filter reads the same words in native order.
				var input [64]byte
				binary.BigEndian.PutUint32(input[0:], number)
				binary.BigEndian.PutUint32(input[4:], arch)
				binary.BigEndian.PutUint32(input[16:], flags)
				result, err := machine.Run(input[:])
				if err != nil || uint32(result) != want {
					t.Fatalf("%s syscall %d returned %#x, want %#x: %v", name, number, result, want, err)
				}
			}
			arch := target.abi.arch
			check("foreign architecture", 1, 0, 0, linuxSeccompKillProcess)
			check("ordinary operation", 1, arch, 0, linuxSeccompAllow)
			check("thread", target.abi.clone, arch, 0x00010900, linuxSeccompAllow)
			check("separate process", target.abi.clone, arch, 0x00004111, linuxSeccompDeny)
			check("clone3 fallback", target.abi.clone3, arch, 0, linuxSeccompUnavailable)
			for _, number := range target.abi.execOrFork {
				check("process creation or replacement", number, arch, 0, linuxSeccompDeny)
			}
			if target.name == "amd64" {
				check("x32 syscall bit", 0x40000001, arch, 0, linuxSeccompDeny)
				check("first reserved x32 number", 512, arch, 0, linuxSeccompDeny)
				check("last reserved x32 number", 547, arch, 0, linuxSeccompDeny)
				check("end of x32 range", 548, arch, 0, linuxSeccompAllow)
			}
		})
	}
}

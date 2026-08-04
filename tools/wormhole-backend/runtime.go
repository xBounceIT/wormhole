package main

import "runtime"

func goos() string {
	return runtime.GOOS
}

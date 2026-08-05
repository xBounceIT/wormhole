//go:build !windows

package main

import "os"

func replaceAuthFile(source, destination string) error {
	return os.Rename(source, destination)
}

func unqueriedWindowsHelloStatus() authHelloStatus {
	return authHelloStatus{Message: "Windows Hello only works on Windows."}
}

func checkWindowsHello() authHelloStatus {
	return unqueriedWindowsHelloStatus()
}

func verifyWindowsHello(_ authHelloVerifyRequest) authVerificationResponse {
	return authVerificationResponse{Message: "Windows Hello only works on Windows."}
}

func systemIdleSeconds() int64 {
	return 0
}

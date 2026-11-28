//go:build !darwin || !cgo

package main

import "context"

func runSignedTouchIDHelper(context.Context, touchIDOperation, string, string) ([]byte, error) {
	return nil, errTouchIDUnavailable
}

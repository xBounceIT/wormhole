// This installer fixture records the launch options, then waits briefly so
// tests can observe the read locks inherited from the verification process.
package main

import (
	"os"
	"strings"
	"time"
)

func main() {
	if os.Getenv("BW_SESSION") != "" || os.Getenv("WORMHOLE_BW_PASSWORD") != "" {
		os.Exit(1)
	}
	name, err := os.Executable()
	if err != nil {
		os.Exit(1)
	}
	record := name + ".args"
	if err := os.WriteFile(record, []byte(strings.Join(os.Args[1:], " ")), 0600); err != nil {
		os.Exit(1)
	}
	for until := time.Now().Add(5 * time.Second); time.Now().Before(until); {
		if _, err := os.Stat(record); os.IsNotExist(err) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

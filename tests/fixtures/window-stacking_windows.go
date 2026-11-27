// Reports whether the first window is above the second in the native z-order.
package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"syscall"
)

func windowHandle(arg string) uintptr {
	handle, err := strconv.ParseUint(arg, 10, strconv.IntSize)
	if err != nil {
		log.Fatal(err)
	}
	if handle == 0 {
		log.Fatal("expected a nonzero window handle")
	}
	return uintptr(handle)
}

func main() {
	above, current := windowHandle(os.Args[1]), windowHandle(os.Args[2])
	getWindow := syscall.NewLazyDLL("user32.dll").NewProc("GetWindow")
	const gwHwndPrev = 3
	for i := 0; i < 10000; i++ {
		current, _, _ = getWindow.Call(current, gwHwndPrev)
		if current == 0 || current == above {
			fmt.Println(current == above)
			return
		}
	}
	log.Fatal("native window order did not terminate")
}

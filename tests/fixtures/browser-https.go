// Serves a self-signed appliance page until the browser test closes stdin.
package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
)

func main() {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<title>HTTPS appliance</title>")
	}))
	defer server.Close()
	fmt.Println(server.URL)
	io.Copy(io.Discard, os.Stdin)
}

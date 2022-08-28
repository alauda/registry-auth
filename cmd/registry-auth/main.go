package main

import (
	"os"
	"runtime"

	"github.com/alauda/registry-auth/cmd/registry-auth/app"
)

func main() {
	if len(os.Getenv("GOMAXPROCS")) == 0 {
		runtime.GOMAXPROCS(runtime.NumCPU())
	}
	app.NewApp("registry-auth").Run()
}

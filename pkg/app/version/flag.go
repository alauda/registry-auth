package version

import (
	"fmt"
	"os"

	"github.com/spf13/pflag"
)

const flagName = "version"

var printVersion = false

func AddFlags(fs *pflag.FlagSet) {
	fs.BoolVar(&printVersion, flagName, false, "Print version information and quit.")
	// "--version" will be treated as "--version=true"
	fs.Lookup(flagName).NoOptDefVal = "true"
}

// PrintAndExitIfRequested will check if the -version flag was passed and, if so,
// print the version and exit.
func PrintAndExitIfRequested() {
	if printVersion {
		fmt.Println(Get())
		os.Exit(0)
	}
}

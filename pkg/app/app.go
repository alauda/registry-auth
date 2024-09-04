package app

import (
	"fmt"
	"os"

	"github.com/alauda/registry-auth/pkg/app/version"
	"github.com/alauda/registry-auth/pkg/server"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	progressMessage = color.BlueString("==>")
)

type App struct {
	name        string
	basename    string
	description string
	options     Options
	runFunc     RunFunc
	silence     bool
	rootCmd     *cobra.Command
	server      *server.Server
}

// Option defines optional parameters for initializing the application
// structure.
type Option func(*App)

// WithOptions to open the application's function to read from the command line
// or read parameters from the configuration file.
func WithOptions(opt Options) Option {
	return func(a *App) {
		a.options = opt
	}
}

// RunFunc defines the application's startup callback function.
type RunFunc func(basename string) error

func WithRunFunc(run RunFunc) Option {
	return func(a *App) {
		a.runFunc = run
	}
}

// WithDescription is used to set the description of the application.
func WithDescription(desc string) Option {
	return func(a *App) {
		a.description = desc
	}
}

// WithSilence sets the application to silent mode, in which the program startup
// information, configuration information, and version information are not
// printed in the console.
func WithSilence() Option {
	return func(a *App) {
		a.silence = true
	}
}

// NewApp creates a new application instance based on the given application name,
// binary name, and other options.
func NewApp(name string, basename string, opts ...Option) *App {
	a := &App{
		name:     name,
		basename: basename,
		server:   server.New(),
	}

	for _, o := range opts {
		o(a)
	}

	a.initRootCmd()

	return a
}

func (a *App) GetRootCmd() *cobra.Command {
	return a.rootCmd
}

// initRootCmd init the cobra root command
func (a *App) initRootCmd() {
	initFlag()

	cmd := cobra.Command{
		Use:           a.basename,
		Long:          a.description,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.SetOut(os.Stdout)
	cmd.Flags().SortFlags = false

	cmd.Run = a.runCommand

	if a.options != nil {
		if _, ok := a.options.(ConfigurableOptions); ok {
			addConfigFlag(a.basename, cmd.Flags())
		}
		a.options.AddFlags(cmd.Flags())
	}

	version.AddFlags(cmd.Flags())

	a.rootCmd = &cmd
}

// Run is used to launch the application.
func (a *App) Run() {
	if err := a.rootCmd.Execute(); err != nil {
		printError(err)
		os.Exit(1)
	}
}

func (a *App) runCommand(cmd *cobra.Command, args []string) {
	version.PrintAndExitIfRequested()

	if !a.silence {
		fmt.Printf("%v Starting %s...\n", progressMessage, a.name)
	}
	// merge configuration and print it
	if a.options != nil {
		if configurableOptions, ok := a.options.(ConfigurableOptions); ok {
			if errs := configurableOptions.ApplyFlags(); len(errs) > 0 {
				for _, err := range errs {
					printError(err)
				}
				os.Exit(1)
			}
			if !a.silence {
				printConfig()
			}
		}

		if ConfigurableOptions, ok := a.options.(ServerOptions); ok {
			if err := ConfigurableOptions.ApplyToServer(a.server); err != nil {
				printError(err)
				os.Exit(1)
			}
		}
	}
	// run application
	if a.runFunc != nil {
		if !a.silence {
			fmt.Printf("%v Log data will now stream in as it occurs:\n", progressMessage)
		}
		if err := a.runFunc(a.basename); err != nil {
			printError(err)
			os.Exit(1)
		}
	}

	err := a.server.Start(cmd.Context())
	if err != nil {
		printError(err)
		os.Exit(1)
	}
}

func printError(err error) {
	fmt.Printf("%v %v\n", color.RedString("Error:"), err)
}

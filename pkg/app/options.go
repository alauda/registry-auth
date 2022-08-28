package app

import (
	"github.com/alauda/registry-auth/pkg/server"
	"github.com/spf13/pflag"
)

// Options abstracts configuration options for reading parameters from the
// command line.
type Options interface {
	// AddFlags adds flags to the specified FlagSet object.
	AddFlags(fs *pflag.FlagSet)
}

// ConfigurableOptions abstracts configuration options for reading parameters
// from a configuration file.
type ConfigurableOptions interface {
	// ApplyFlags parsing parameters from the command line or configuration file
	// to the options instance.
	ApplyFlags() []error
}

type ServerOptions interface {
	ApplyToServer(server *server.Server) error
}

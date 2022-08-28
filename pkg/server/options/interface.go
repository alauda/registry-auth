package options

import (
	"github.com/alauda/registry-auth/pkg/app"
	"github.com/alauda/registry-auth/pkg/server"
	"github.com/spf13/pflag"
)

// Optioner interface for all options
type Optioner interface {
	AddFlags(*pflag.FlagSet)
	ApplyFlags() []error
}

// Options multiple options aggregator
type Options struct {
	Options []Optioner
}

// With create a multiple options handler
func With(opts ...Optioner) *Options {
	return &Options{
		Options: opts,
	}
}

// Unshift add optioners to the beginning of the options slice
func (o *Options) Unshift(opts ...Optioner) *Options {
	o.Options = append(opts, o.Options...)
	return o
}

// Add add new options to the recommended options
func (o *Options) Add(opts ...Optioner) *Options {
	o.Options = append(o.Options, opts...)
	return o
}

// AddFlags add flags for all recommended options
func (o *Options) AddFlags(pf *pflag.FlagSet) {
	for _, opts := range o.Options {
		opts.AddFlags(pf)
	}
}

// ApplyFlags apply flags as configuration and return errors if any
func (o *Options) ApplyFlags() []error {
	var errs []error
	for _, opts := range o.Options {
		errs = append(errs, opts.ApplyFlags()...)
	}
	return errs
}

// ApplyToServer apply configuration to server instance
func (o *Options) ApplyToServer(sv *server.Server) (err error) {
	for _, opts := range o.Options {
		if serverOptions, ok := opts.(app.ServerOptions); ok {
			err = serverOptions.ApplyToServer(sv)
			if err != nil {
				return
			}
		}
	}
	return
}

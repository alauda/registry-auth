package options

import (
	"gomod.alauda.cn/alauda-backend/pkg/server/options"
)

// Options options for alauda-console
type Options struct {
	options.Optioner
}

// NewOptions new options for alauda-console
func NewOptions(name string) *Options {
	return &Options{
		Optioner: options.With(
			options.NewLogOptions(),
			options.NewClientOptions(),
			options.NewMetricsOptions(),
			options.NewErrorOptions(),
			NewServerOptions(),
		),
	}
}

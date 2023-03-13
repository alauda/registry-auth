package app

import (
	"github.com/alauda/registry-auth/pkg/app"
	serverOptions "github.com/alauda/registry-auth/pkg/server/options"
)

// NewApp creates a new alauda-console app
func NewApp(basename string) *app.App {
	opts := serverOptions.With(
		serverOptions.NewLogOptions(),
		serverOptions.NewServerOptions(),
		serverOptions.NewMetricsOptions(),
		serverOptions.NewBasicOptions(),
	)
	return app.NewApp("registry auth", basename, app.WithOptions(opts))
}

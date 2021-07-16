package app

import (
	"fmt"
	"net/http"

	"gomod.alauda.cn/alauda-backend/pkg/server"
	"gomod.alauda.cn/app"
	"gomod.alauda.cn/registry-auth/cmd/registry-auth/app/options"
)

const commandDesc = `The application will help to add node for edge clusters.`

// NewApp creates a new alauda-console app
func NewApp(name string) *app.App {
	opts := options.NewOptions(name)
	application := app.NewApp("Edge Node Manager",
		name,
		app.WithOptions(opts),
		app.WithDescription(commandDesc),
		app.WithRunFunc(run(opts)),
	)
	return application
}

func run(opts *options.Options) app.RunFunc {
	return func(basename string) error {
		srv := server.New(basename)
		err := opts.ApplyToServer(srv)
		if err != nil {
			return err
		}

		v, _ := srv.GetValue("ServerOptions")
		serverOptions := v.(*options.ServerOptions)

		addr := fmt.Sprintf("%s:%d", serverOptions.BindAddress, serverOptions.Port)
		handler := srv.Container()

		if serverOptions.TLSCertFile != "" && serverOptions.TLSKeyFile != "" {
			return http.ListenAndServeTLS(addr, serverOptions.TLSCertFile, serverOptions.TLSKeyFile, handler)
		}
		return http.ListenAndServe(addr, handler)
	}
}

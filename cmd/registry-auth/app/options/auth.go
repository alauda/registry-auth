package options

import (
	"fmt"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"gomod.alauda.cn/alauda-backend/pkg/server"
	"gomod.alauda.cn/registry-auth/pkg/registryauth"
)

const (
	flagAuthPrivateKeyFile      = "auth-private-key-file"
	flagAuthPublicCertFile      = "auth-public-cert-file"
	flagAuthIssuer              = "auth-issuer"
	flagAuthConfigFile          = "auth-config-file"
	flagAuthConfigNamespace     = "auth-config-namespace"
	flagAuthConfigLabelSelector = "auth-config-selector"
	flagAuthTokenDuration       = "auth-token-duration"
	flagRegistryBackend         = "registry-backend"

	configAuthPrivateKeyFile      = "auth.private_key_file"
	configAuthPublicCertFile      = "auth.public_cert_file"
	configAuthIssuer              = "auth.issuer"
	configAuthConfigFile          = "auth.config_file"
	configAuthConfigNamespace     = "auth.config_namespace"
	configAuthConfigLabelSelector = "auth.config_selector"
	configAuthTokenDuration       = "auth.token_duration"
	configRegistryBackend         = "registry.backend"
)

// ServerOptions contains configuration for server
type ServerOptions struct {
	*registryauth.Server
}

// NewConsoleOptions creates a ConsoleOptions object with default parameters.
func NewServerOptions() *ServerOptions {
	s := registryauth.New()
	return &ServerOptions{
		Server: s,
	}
}

// AddFlags adds flags for console to the specified FlagSet object.
func (o *ServerOptions) AddFlags(fs *pflag.FlagSet) {
	fs.String(flagAuthPrivateKeyFile, "",
		"The private key for sign JWT token.")
	_ = viper.BindPFlag(configAuthPrivateKeyFile, fs.Lookup(flagAuthPrivateKeyFile))

	fs.String(flagAuthPublicCertFile, "",
		"The public certificate for sign JWT token.")
	_ = viper.BindPFlag(configAuthPublicCertFile, fs.Lookup(flagAuthPublicCertFile))

	fs.String(flagAuthIssuer, "registry-token-issuer",
		"The issuer for sign JWT token.")
	_ = viper.BindPFlag(configAuthIssuer, fs.Lookup(flagAuthIssuer))

	fs.String(flagAuthConfigFile, "",
		"The static auth config file.")
	_ = viper.BindPFlag(configAuthConfigFile, fs.Lookup(flagAuthConfigFile))

	fs.String(flagAuthConfigNamespace, "",
		"The secret auth config namespace.")
	_ = viper.BindPFlag(configAuthConfigNamespace, fs.Lookup(flagAuthConfigNamespace))

	fs.String(flagAuthConfigLabelSelector, "registry-auth-config=true",
		"The secrelt auth config labelselecotr.")
	_ = viper.BindPFlag(configAuthConfigLabelSelector, fs.Lookup(flagAuthConfigLabelSelector))

	fs.Int(flagAuthTokenDuration, 600,
		"The token duration in seconds.")
	_ = viper.BindPFlag(configAuthTokenDuration, fs.Lookup(flagAuthTokenDuration))

	fs.String(flagRegistryBackend, "127.0.0.1:5000",
		"The backend registry address.")
	_ = viper.BindPFlag(configRegistryBackend, fs.Lookup(flagRegistryBackend))

}

// ApplyFlags parsing parameters from the command line or configuration file
// to the options instance.
func (o *ServerOptions) ApplyFlags() []error {
	var errs []error

	o.AuthConfigFile = viper.GetString(configAuthConfigFile)
	o.AuthConfigNamespace = viper.GetString(configAuthConfigNamespace)
	o.AuthConfigLabelSelector = viper.GetString(configAuthConfigLabelSelector)
	o.AuthTokenDuration = viper.GetInt(configAuthTokenDuration)

	o.RegistryBackend = viper.GetString(configRegistryBackend)

	for _, it := range []struct {
		Var    *string
		Config string
		Flag   string
	}{
		{Var: &o.AuthPrivateKeyFile, Config: configAuthPrivateKeyFile, Flag: flagAuthPrivateKeyFile},
		{Var: &o.AuthPublicCertFile, Config: configAuthPublicCertFile, Flag: flagAuthPublicCertFile},
		{Var: &o.AuthIssuer, Config: configAuthIssuer, Flag: flagAuthIssuer},
	} {
		*it.Var = viper.GetString(it.Config)
		if *it.Var == "" {
			errs = append(errs, fmt.Errorf("--%s must be specified", it.Flag))
		}
	}

	return errs
}

// ApplyToServer apply options on server
func (o *ServerOptions) ApplyToServer(srv server.Server) error {
	o.Server.Server = srv
	o.Server.ClientManger = srv.GetManager()
	return o.Server.ApplyToServer(srv)
}

package options

import (
	"fmt"

	"github.com/alauda/registry-auth/pkg/server"
	"github.com/alauda/registry-auth/pkg/server/config"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	flagAuthPrivateKeyFile      = "auth-private-key-file"
	flagAuthPublicCertFile      = "auth-public-cert-file"
	flagAuthIssuer              = "auth-issuer"
	flagAuthConfigFile          = "auth-config-file"
	flagAuthConfigNamespace     = "auth-config-namespace"
	flagAuthConfigLabelSelector = "auth-config-selector"
	flagAuthTokenDuration       = "auth-token-duration"
	flagAuthThirdpartyServer    = "auth-thirdparty-server"
	flagRegistryBackend         = "registry-backend"
	flagAuthService             = "service"
	flagKubeConfig              = "kubeconfig"

	configAuthPrivateKeyFile      = "auth.private_key_file"
	configAuthPublicCertFile      = "auth.public_cert_file"
	configAuthIssuer              = "auth.issuer"
	configAuthConfigFile          = "auth.config_file"
	configAuthConfigNamespace     = "auth.config_namespace"
	configAuthConfigLabelSelector = "auth.config_selector"
	configAuthTokenDuration       = "auth.token_duration"
	configAuthThirdpartyServer    = "auth.thirdparty_server"
	configRegistryBackend         = "registry.backend"
	configAuthService             = "auth.service"
	configKubeconfig              = "server.kubeconfig"
)

// BasicOptions contains configuration for server
type BasicOptions struct {
	config.BasicConfig
}

//// NewConsoleOptions creates a ConsoleOptions object with default parameters.
func NewBasicOptions() *BasicOptions {
	return &BasicOptions{}
}

// AddFlags adds flags for console to the specified FlagSet object.
func (o *BasicOptions) AddFlags(fs *pflag.FlagSet) {

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

	fs.String(flagAuthService, "token-service",
		"The registry service type.")
	_ = viper.BindPFlag(configAuthService, fs.Lookup(flagAuthService))

	fs.String(flagAuthThirdpartyServer, "", "The thirdparty server address.")
	_ = viper.BindPFlag(configAuthThirdpartyServer, fs.Lookup(flagAuthThirdpartyServer))

	fs.String(flagKubeConfig, "", "The kubeconfig path")
	_ = viper.BindPFlag(configKubeconfig, fs.Lookup(flagKubeConfig))

}

// ApplyFlags parsing parameters from the command line or configuration file
// to the options instance.
func (o *BasicOptions) ApplyFlags() []error {
	var errs []error

	o.Kubeconfig = viper.GetString(configKubeconfig)
	o.AuthConfigFile = viper.GetString(configAuthConfigFile)
	o.AuthConfigNamespace = viper.GetString(configAuthConfigNamespace)
	o.AuthConfigLabelSelector = viper.GetString(configAuthConfigLabelSelector)
	o.AuthTokenDuration = viper.GetInt(configAuthTokenDuration)
	o.AuthThirdpartyServer = viper.GetString(configAuthThirdpartyServer)

	o.RegistryBackend = viper.GetString(configRegistryBackend)
	o.AuthService = viper.GetString(configAuthService)
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
func (o *BasicOptions) ApplyToServer(server *server.Server) error {
	server.BasicConfig.AuthConfigFile = o.AuthConfigFile
	server.BasicConfig.AuthConfigNamespace = o.AuthConfigNamespace
	server.BasicConfig.AuthConfigLabelSelector = o.AuthConfigNamespace
	server.BasicConfig.AuthTokenDuration = o.AuthTokenDuration
	server.BasicConfig.AuthThirdpartyServer = o.AuthThirdpartyServer
	server.BasicConfig.RegistryBackend = o.RegistryBackend
	server.BasicConfig.AuthService = o.AuthService
	server.BasicConfig.AuthPrivateKeyFile = o.AuthPrivateKeyFile
	server.BasicConfig.AuthPublicCertFile = o.AuthPublicCertFile
	server.BasicConfig.AuthIssuer = o.AuthIssuer
	server.BasicConfig.Kubeconfig = o.Kubeconfig
	return server.ApplyToServer()
}

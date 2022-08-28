package options

import (
	"fmt"
	"net"

	"github.com/alauda/registry-auth/pkg/server"
	"github.com/alauda/registry-auth/pkg/server/config"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	flagServerBindAddress = "server-bind-address"
	flagServerPort        = "server-port"
	flagServerTLSCertFile = "server-tls-cert-file"
	flagServerTLSKeyFile  = "server-tls-key-file"

	configServerBindAddress = "server.bind_address"
	configServerPort        = "server.port"
	configServerTLSCertFile = "server.tls_cert_file"
	configServerTLSKeyFile  = "server.tls_key_file"
)

func NewServerOptions() Optioner {
	return &ServerOptions{}
}

type ServerOptions struct {
	config.ServerConfig
}

func (o *ServerOptions) AddFlags(fs *pflag.FlagSet) {
	fs.String(flagServerBindAddress, "",
		"The listening IP address.")
	_ = viper.BindPFlag(configServerBindAddress, fs.Lookup(flagServerBindAddress))

	fs.Int(flagServerPort, 8080,
		"The listening port.")
	_ = viper.BindPFlag(configServerPort, fs.Lookup(flagServerPort))

	fs.String(flagServerTLSCertFile, "",
		"The tls certificate for server.")
	_ = viper.BindPFlag(configServerTLSCertFile, fs.Lookup(flagServerTLSCertFile))

	fs.String(flagServerTLSKeyFile, "",
		"The tls key for server.")
	_ = viper.BindPFlag(configServerTLSKeyFile, fs.Lookup(flagServerTLSKeyFile))
}

func (o *ServerOptions) ApplyFlags() []error {

	var errs []error

	o.BindAddress = viper.GetString(configServerBindAddress)
	if o.BindAddress != "" && net.ParseIP(o.BindAddress) == nil {
		errs = append(errs, fmt.Errorf("--%s must be IP", flagServerBindAddress))
	}

	o.Port = viper.GetInt(configServerPort)
	if o.Port < 0 {
		errs = append(errs, fmt.Errorf("--%s must >= 0", flagServerPort))
	}

	o.TLSCertFile = viper.GetString(configServerTLSCertFile)
	o.TLSKeyFile = viper.GetString(configServerTLSKeyFile)

	if (o.TLSCertFile == "" && o.TLSKeyFile != "") || (o.TLSCertFile != "" && o.TLSKeyFile == "") {
		errs = append(errs, fmt.Errorf("--%s must config with --%s together", configServerTLSCertFile, configServerTLSKeyFile))
	}

	return errs
}

func (o *ServerOptions) ApplyToServer(server *server.Server) error {
	server.ServerConfig.BindAddress = o.BindAddress
	server.ServerConfig.Port = o.Port
	server.ServerConfig.TLSCertFile = o.TLSCertFile
	server.ServerConfig.TLSKeyFile = o.TLSKeyFile
	return nil
}

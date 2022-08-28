package config

type BasicConfig struct {
	AuthConfigFile          string
	AuthPrivateKeyFile      string
	AuthPublicCertFile      string
	AuthConfigNamespace     string
	AuthConfigLabelSelector string
	AuthTokenDuration       int
	AuthIssuer              string
	AuthThirdpartyServer    string
	RegistryBackend         string
	AuthService             string
	Kubeconfig              string
}

type ServerConfig struct {
	BindAddress string
	Port        int
	TLSCertFile string
	TLSKeyFile  string
}

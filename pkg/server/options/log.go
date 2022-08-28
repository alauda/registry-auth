package options

import (
	"github.com/alauda/registry-auth/pkg/server"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var levelMap = map[string]zapcore.Level{
	"debug": zap.DebugLevel,
	"info":  zapcore.InfoLevel,
	"warn":  zapcore.WarnLevel,
	"error": zapcore.ErrorLevel,
	"panic": zapcore.PanicLevel,
	"fatal": zapcore.FatalLevel,
}

func LogFromLevel(level string, opts ...zap.Option) (*zap.Logger, error) {
	var zapLevel = zap.NewAtomicLevel()
	if logLevel, ok := levelMap[level]; ok {
		zapLevel = zap.NewAtomicLevelAt(logLevel)
	}

	config := zap.Config{
		Level:       zapLevel,
		Development: false,
		Sampling: &zap.SamplingConfig{
			Initial:    100,
			Thereafter: 100,
		},
		Encoding:         "json",
		EncoderConfig:    zap.NewProductionEncoderConfig(),
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
	}

	return config.Build(opts...)
}

const (
	flagLogLevel = "log-level"

	configLogLevel = "server.log_level"
)

func NewLogOptions() Optioner {
	return &DefaultLogOptions{}
}

type DefaultLogOptions struct {
	logLevel string
}

func (d *DefaultLogOptions) AddFlags(fs *pflag.FlagSet) {
	fs.String(flagLogLevel, "info", "The server log level.")
	_ = viper.BindPFlag(configLogLevel, fs.Lookup(flagLogLevel))
}

func (d *DefaultLogOptions) ApplyFlags() []error {
	d.logLevel = viper.GetString(configLogLevel)
	return []error{}
}

func (d *DefaultLogOptions) ApplyToServer(server *server.Server) error {
	logger, err := LogFromLevel(d.logLevel)
	if err != nil {
		return err
	}

	server.Log = logger
	return nil
}

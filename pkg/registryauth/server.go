package registryauth

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/emicklei/go-restful"
	"k8s.io/client-go/kubernetes"

	"go.uber.org/zap"
	"gomod.alauda.cn/alauda-backend/pkg/client"
	"gomod.alauda.cn/alauda-backend/pkg/decorator"
	"gomod.alauda.cn/alauda-backend/pkg/server"
)

// Server conole data
type Server struct {
	server.Server
	AuthConfigFile          string
	AuthPrivateKeyFile      string
	AuthPublicCertFile      string
	AuthConfigNamespace     string
	AuthConfigLabelSelector string
	AuthTokenDuration       int
	AuthIssuer              string
	ClientManger            client.Manager
	client                  kubernetes.Interface
	processor               *AuthProcessor
	stop                    <-chan struct{}
}

var logger *zap.Logger

// New creates new instance
func New() *Server {
	return &Server{}
}

func getStopSignal() <-chan struct{} {
	shutdownHandler := make(chan os.Signal, 2)

	ctx, cancel := context.WithCancel(context.Background())
	signal.Notify(shutdownHandler, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-shutdownHandler
		cancel()
		<-shutdownHandler
		os.Exit(1) // second signal. Exit directly.
	}()
	return ctx.Done()
}

// ApplyToServer apply to server
func (s *Server) ApplyToServer(srv server.Server) error {
	gen := decorator.NewWSGenerator()
	ws := gen.New(srv)
	logger = srv.L().Named("registry-auth")
	ws.Doc("Registry Auth")
	ws.Path("/auth")
	ws.ApiVersion("v1")

	ws.Route(
		ws.GET("/token").
			To(s.HandleAuth).
			Doc("Handle registry auth"),
	)

	srv.Container().Add(ws)

	ws = gen.New(srv)
	ws.Path("/health")
	ws.Route(
		ws.GET("").
			To(func(req *restful.Request, res *restful.Response) {
				res.Write([]byte("OK"))
			}),
	)
	srv.Container().Add(ws)

	var err error

	s.stop = getStopSignal()
	s.processor, err = NewAuthProcessor(s.AuthPrivateKeyFile, s.AuthPublicCertFile, s.AuthIssuer, s.AuthTokenDuration)
	if err != nil {
		return err
	}

	if s.AuthConfigFile != "" {
		if err := WatchConfigFile(s.AuthConfigFile, s.stop, s.processor); err != nil {
			return err
		}
	}

	if s.AuthConfigNamespace != "" {
		s.client, err = s.ClientManger.InsecureClient()
		if err != nil {
			return err
		}

		if err := WatchSecret(s.client, s.AuthConfigNamespace, s.AuthConfigLabelSelector, s.stop, s.processor); err != nil {
			return err
		}
	}
	return nil
}

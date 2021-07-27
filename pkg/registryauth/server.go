package registryauth

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/emicklei/go-restful"
	"k8s.io/client-go/kubernetes"

	"github.com/cssivision/reverseproxy"
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
	RegistryBackend         string
	proxy                   *reverseproxy.ReverseProxy
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
	ws.ApiVersion("v1")

	ws.Route(
		ws.GET("/auth/token").
			To(s.HandleAuth).
			Doc("Handle registry auth"),
	)

	srv.Container().Add(ws)
	srv.Container().ServeMux.Handle("/v2/", http.HandlerFunc(s.HandleProxy))

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

	if s.RegistryBackend != "" {
		s.proxy = &reverseproxy.ReverseProxy{
			Director: func(req *http.Request) {},
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return (&net.Dialer{
						Timeout:   30 * time.Second,
						KeepAlive: 30 * time.Second,
						DualStack: true,
					}).DialContext(ctx, "tcp", s.RegistryBackend)
				},
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		}

		s.proxy.ModifyResponse = func(res *http.Response) error {
			if location := res.Header.Get("Location"); location != "" {
				if loc, err := url.Parse(location); err == nil {
					loc.Host = ""
					loc.Scheme = ""
					location = loc.String()
					res.Header.Set("Location", location)
				}
			}
			return nil
		}
	}

	return nil
}

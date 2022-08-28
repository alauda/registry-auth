package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alauda/registry-auth/pkg/server/config"
	"github.com/emicklei/go-restful"
	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// Server conole data
type Server struct {
	BasicConfig  config.BasicConfig
	ServerConfig config.ServerConfig
	proxy        *httputil.ReverseProxy
	client       kubernetes.Interface
	processor    *AuthProcessor
	stop         <-chan struct{}
	container    *restful.Container
	Log          *zap.Logger
}

var logger *zap.Logger

// New creates new instance
func New() *Server {
	return &Server{
		container: restful.NewContainer(),
	}
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

func newWebService() *restful.WebService {
	ws := new(restful.WebService)
	ws.Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON).
		Param(restful.HeaderParameter("Authorization", "Given Bearer token will use this as authorization for the API"))

	return ws
}

func (s *Server) L() *zap.Logger {
	return s.Log
}

func (s *Server) Container() *restful.Container {
	return s.container
}

// ApplyToServer apply to server
func (s *Server) ApplyToServer() error {
	ws := newWebService()
	logger = s.L().Named("registry-auth")
	ws.Doc("Registry Auth")
	ws.ApiVersion("v1")

	ws.Route(
		ws.GET("/auth/token").
			To(s.HandleAuth).
			Doc("Handle registry auth"),
	)

	s.container.Add(ws)
	s.container.ServeMux.Handle("/v2/", http.HandlerFunc(s.HandleProxy))

	ws = newWebService()
	ws.Path("/health")
	ws.Route(
		ws.GET("").
			To(func(req *restful.Request, res *restful.Response) {
				res.Write([]byte("OK"))
			}),
	)
	s.container.Add(ws)

	var err error

	s.stop = getStopSignal()
	s.processor, err = NewAuthProcessor(s.BasicConfig.AuthPrivateKeyFile, s.BasicConfig.AuthPublicCertFile, s.BasicConfig.AuthIssuer, s.BasicConfig.AuthTokenDuration)
	if err != nil {
		return err
	}

	if s.BasicConfig.AuthConfigFile != "" {
		if err := WatchConfigFile(s.BasicConfig.AuthConfigFile, s.stop, s.processor); err != nil {
			return err
		}
	}

	if s.BasicConfig.AuthConfigNamespace != "" {
		kubeconfig, err := clientcmd.BuildConfigFromFlags("", s.BasicConfig.Kubeconfig)
		if err != nil {
			return err
		}
		s.client, err = kubernetes.NewForConfig(kubeconfig)
		if err != nil {
			return err
		}

		if err := WatchSecret(s.client, s.BasicConfig.AuthConfigNamespace, s.BasicConfig.AuthConfigLabelSelector, s.stop, s.processor); err != nil {
			return err
		}
	}

	if s.BasicConfig.AuthThirdpartyServer != "" {
		if err := NewThirdpartyAuth(logger, s.BasicConfig.AuthThirdpartyServer, s.processor); err != nil {
			return err
		}
	}

	if s.BasicConfig.RegistryBackend != "" {
		s.proxy = &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.URL.Scheme = "http"
			},
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return (&net.Dialer{
						Timeout:   30 * time.Second,
						KeepAlive: 30 * time.Second,
						DualStack: true,
					}).DialContext(ctx, "tcp", s.BasicConfig.RegistryBackend)
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

func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.ServerConfig.BindAddress, s.ServerConfig.Port)
	handler := s.Container()

	if s.ServerConfig.TLSCertFile != "" && s.ServerConfig.TLSKeyFile != "" {
		return http.ListenAndServeTLS(addr, s.ServerConfig.TLSCertFile, s.ServerConfig.TLSKeyFile, handler)
	}
	return http.ListenAndServe(addr, handler)
}

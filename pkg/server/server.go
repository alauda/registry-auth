package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
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

func (s *Server) Start(ctx context.Context) error {
	var addrs []string
	if s.ServerConfig.BindAddress == "" {
		addrs = append(addrs, ":"+strconv.Itoa(s.ServerConfig.Port))
	} else {
		for _, addr := range strings.Split(s.ServerConfig.BindAddress, ",") {
			if ip := net.ParseIP(addr); ip != nil && ip.To4() == nil {
				addr = "[" + addr + "]"
			}
			addrs = append(addrs, addr+":"+strconv.Itoa(s.ServerConfig.Port))
		}
	}

	handler := s.Container()

	connState := func(conn net.Conn, state http.ConnState) {
		if state == http.StateNew {
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				err := tcpConn.SetKeepAlive(true)
				if err != nil {
					logger.Error(fmt.Sprintf("failed to set keepalive, err: %v", err), zap.String("func", "connState"))
					return
				}

				err = tcpConn.SetKeepAlivePeriod(time.Second * 30)
				if err != nil {
					logger.Error(fmt.Sprintf("failed to set keepalive period, err: %v", err), zap.String("func", "connState"))
					return
				}
			}
		}
	}

	if s.ServerConfig.TLSCertFile != "" && s.ServerConfig.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(s.ServerConfig.TLSCertFile, s.ServerConfig.TLSKeyFile)
		if err != nil {
			return err
		}

		config := tls.Config{
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			},
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		}
		for _, addr := range addrs {
			go func(addr string) {
				listener, err := tls.Listen("tcp", addr, &config)
				if err != nil {
					logger.Fatal(fmt.Sprintf("failed to listen %s, err: %v", addr, err), zap.String("func", "Start"))
					return
				}

				srv := http.Server{Handler: handler, ConnState: connState}
				if err := srv.Serve(listener); err != nil {
					logger.Fatal(fmt.Sprintf("failed to serve at %s, err: %v", addr, err), zap.String("func", "Start"))
				}
			}(addr)
		}
	} else {
		for _, addr := range addrs {
			go func(addr string) {
				srv := http.Server{Addr: addr, Handler: handler, ConnState: connState}
				if err := srv.ListenAndServe(); err != nil {
					logger.Fatal(fmt.Sprintf("failed to listen and serve at %s, err: %v", addr, err), zap.String("func", "Start"))
				}
			}(addr)
		}
	}

	<-ctx.Done()
	return nil
}

package server

import (
	"errors"
	"fmt"
	"go.uber.org/zap"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/emicklei/go-restful"
)

func (s *Server) signToken(req *restful.Request, decodeScopeFunc ScopeDecoder, isActionMatchFunc ScopeMatcher) (token *Token, status int, err error) {
	var scope, resultScope AccessScope
	status = 200

	scopeArg := req.QueryParameter("scope")

	clientIP := getClientIP(req.Request)
	defer func() {
		if err != nil && !errors.Is(err, ErrNotHandleAuthHeader) {
			info := fmt.Sprintf("%s | scope %s | resultScope %v | %d | %v", clientIP, scopeArg, resultScope, status, err)
			logger.Error(info, zap.String("func", "signToken"))
		} else {
			info := fmt.Sprintf("%s |scope %s | resultScope %v | %d", clientIP, scopeArg, resultScope, status)
			logger.Info(info, zap.String("func", "signToken"))
		}
	}()
	user, err := s.processor.Authenticate(req.HeaderParameter("Authorization"))
	if err != nil {
		status = http.StatusUnauthorized
		return
	}
	scope, err = decodeScopeFunc(req.Request)
	if err != nil {
		status = http.StatusBadRequest
		return
	}
	resultScope = s.processor.Authorize(user, scope)
	if len(resultScope) == 0 {
		resultScope = s.processor.Authorize(AnonymousUser, scope)
	}

	if isActionMatchFunc != nil {
		if !isActionMatchFunc(req.Request, resultScope, scope) {
			err = ErrNotHandleAuthHeader
			return
		}
	}
	authService := req.QueryParameter("service")
	if authService == "" {
		authService = s.BasicConfig.AuthService
	}
	token, err = s.processor.Sign(user, authService, resultScope)
	if err != nil {
		status = http.StatusInternalServerError
		return
	}

	return
}

// HandleAuth handle registry auth
func (s *Server) HandleAuth(req *restful.Request, res *restful.Response) {
	var err error
	var status int

	now := time.Now()

	defer func() {
		if err != nil {
			res.WriteErrorString(status, err.Error())
		}
		ms := time.Since(now).Milliseconds()

		info := fmt.Sprintf("%s %s %d ms", req.Request.Method, req.Request.URL.String(), ms)
		logger.Debug(info, zap.String("func", "HandleAuth"))
	}()

	token, status, err := s.signToken(req, DecodeScope, nil)
	if err != nil {
		return
	}
	_ = req.QueryParameter("client_id")
	_ = req.QueryParameter("offline_token")
	res.WriteAsJson(token)
}

func (s *Server) HandleProxy(res http.ResponseWriter, req *http.Request) {
	now := time.Now()

	clientIP := getClientIP(req)
	if s.BasicConfig.RegistryBackend == "" {
		res.WriteHeader(http.StatusNotFound)
		res.Write([]byte("no registry-backend config"))
		return
	}

	status, err := handleAuthorizationHeader(s, req)
	if err != nil {
		res.WriteHeader(status)
		res.Write([]byte(err.Error()))
		return
	}
	req.Header.Add("Host", req.Host)

	defer func() {
		ms := time.Since(now).Milliseconds()
		info := fmt.Sprintf("%s | %s %s => %s %d ms", clientIP, req.Method, req.URL.Path, s.BasicConfig.RegistryBackend, ms)
		logger.Info(info, zap.String("func", "HandleProxy"))
	}()

	req.URL.Host = req.Host

	s.proxy.ServeHTTP(res, req)
}

func handleAuthorizationHeader(server *Server, req *http.Request) (int, error) {
	authHeader := req.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, BasicPrefix) {
		token, status, err := server.signToken(restful.NewRequest(req), DecodeScopeFromUrl, IsScopeActionMatch)
		if err == nil {
			logger.Debug(fmt.Sprintf("%v | sign token successfully, set Authorization header", getClientIP(req)), zap.String("func", "handleAuthorizationHeader"))
			req.Header.Set("Authorization", BearerPrefix+token.Token)
		} else if !errors.Is(err, ErrNotHandleAuthHeader) {
			return status, err
		}
	}

	return http.StatusOK, nil
}

func getClientIP(req *http.Request) string {
	realIP := req.Header.Get("X-Real-Ip")
	if realIP != "" {
		return realIP
	}
	forwarded := req.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		return strings.Split(forwarded, ",")[0]
	}
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err == nil {
		return ip
	}
	return req.RemoteAddr
}

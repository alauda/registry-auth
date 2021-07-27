package registryauth

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/emicklei/go-restful"
	"gomod.alauda.cn/log"
)

// HandleAuth handle registry auth
func (s *Server) HandleAuth(req *restful.Request, res *restful.Response) {
	var err error
	var resultScope AccessScope

	now := time.Now()
	status := 200

	accountArg := req.QueryParameter("account")
	scopeArg := req.QueryParameter("scope")

	clientIP := getClientIP(req.Request)

	defer func() {
		if err != nil {
			res.WriteErrorString(status, err.Error())
		}
		ms := time.Since(now).Milliseconds()
		debug := fmt.Sprintf("%s %s %d %v in %d ms", clientIP, req.Request.URL.String(), status, err, ms)
		logger.Debug(debug, log.String("func", "HandleAuth"))

		info := fmt.Sprintf("%s | %s | %s | %v | %d | %v | %d ms", clientIP, accountArg, scopeArg, resultScope, status, err, ms)
		logger.Info(info, log.String("func", "HandleAuth"))
	}()
	user, err := s.processor.Authenticate(req.HeaderParameter("Authorization"))
	if err != nil {
		status = http.StatusUnauthorized
		return
	}
	scope, err := DecodeScope(scopeArg)
	if err != nil {
		status = http.StatusBadRequest
		return
	}
	resultScope = s.processor.Authorize(user, scope)
	if len(resultScope) == 0 {
		resultScope = s.processor.Authorize(AnonymousUser, scope)
	}
	token, err := s.processor.Sign(user, req.QueryParameter("service"), resultScope)
	if err != nil {
		status = http.StatusInternalServerError
		return
	}
	_ = req.QueryParameter("client_id")
	_ = req.QueryParameter("offline_token")
	res.WriteAsJson(token)
}

func (s *Server) HandleProxy(res http.ResponseWriter, req *http.Request) {
	now := time.Now()

	clientIP := getClientIP(req)

	if s.RegistryBackend == "" {
		res.Write([]byte("no registry-backend config"))
		res.WriteHeader(http.StatusNotFound)
	}

	req.Header.Add("Host", req.Host)

	defer func() {
		ms := time.Since(now).Milliseconds()
		info := fmt.Sprintf("%s | %s %s => %s %d ms", clientIP, req.Method, req.URL.Path, s.RegistryBackend, ms)
		logger.Info(info, log.String("func", "HandleProxy"))
	}()

	req.URL.Host = req.Host

	s.proxy.ServeHTTP(res, req)
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

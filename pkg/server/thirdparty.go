package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"

	"go.uber.org/zap"
)

type ThirdpartyAuth interface {
	Login(username, password string) (string, error)
	UserAuthorization(username string) ([]Authorization, bool)
}

type thirdpartyClient struct {
	ctx        context.Context
	logger     *zap.Logger
	endpoint   *url.URL
	httpclient *http.Client
	lock       sync.RWMutex
	auths      map[string][]Authorization
}

func NewThirdpartyAuth(logger *zap.Logger, thirdpartyServer string, p *AuthProcessor) error {
	if len(thirdpartyServer) == 0 {
		return fmt.Errorf("url empty")
	}
	client := http.DefaultClient
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	u, err := url.ParseRequestURI(thirdpartyServer)
	if err != nil {
		return err
	}

	tp := &thirdpartyClient{
		ctx:        context.Background(),
		logger:     logger,
		endpoint:   u,
		httpclient: client,
		auths:      make(map[string][]Authorization),
	}
	p.ThirdpartyAuth = tp
	return nil
}

func (c *thirdpartyClient) Login(username, password string) (string, error) {

	req, err := http.NewRequestWithContext(c.ctx, "POST", c.endpoint.String(), nil)
	if err != nil {
		return "", err
	}

	req.SetBasicAuth(username, password)

	auths := &[]Authorization{}
	err = c.Request(req, auths)
	if err != nil {
		return "", err
	}

	c.logger.Debug("Login", zap.Any("auths", auths), zap.Any("user", username))

	c.lock.Lock()
	c.auths[username] = *auths
	c.lock.Unlock()
	return username, nil
}

func (c *thirdpartyClient) UserAuthorization(username string) ([]Authorization, bool) {
	c.lock.Lock()
	defer c.lock.Unlock()
	auths, ok := c.auths[username]
	if !ok {
		return nil, false
	}
	return auths, true
}

func (c *thirdpartyClient) Request(req *http.Request, res interface{}) error {
	req.Header.Add("Accept", "application/json, */*")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpclient.Do(req)
	if err != nil {
		return err
	}
	defer closeResp(resp)

	c.logger.Debug("thirdpary: response status code", zap.Any("code", resp.StatusCode))
	if res != nil {
		resbody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		c.logger.Debug("thirdpary: response body", zap.Any("body", string(resbody)))
		if err := json.Unmarshal(resbody, res); err != nil {
			return err
		}
		return nil
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusServiceUnavailable:
		return fmt.Errorf("service is not available: %s", resp.Status)
	case http.StatusInternalServerError:
		return fmt.Errorf("internal server error: %s", resp.Status)
	default:
		return fmt.Errorf("unknown response status: %s", resp.Status)
	}
}

func closeResp(r *http.Response) {
	io.Copy(ioutil.Discard, r.Body)
	r.Body.Close()
}

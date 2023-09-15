package server

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/thoas/go-funk"

	"github.com/docker/libtrust"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/util/keyutil"
)

const (
	RepositoryAccessType = "repository"
	RegistryAccessType   = "registry"
	PullAction           = "pull"
	PushAction           = "push"
	CatalogAction        = "*"
	DeleteAction         = "delete"
	AnonymousUser        = "_anonymous"
	BasicPrefix          = "Basic "
	BearerPrefix         = "Bearer "
	PBKDF2Prefix         = "PBKDF2:"
	SecretKey            = "config"
)

var (
	ErrAuthFailed          = fmt.Errorf("wrong username or password")
	ErrNotHandleAuthHeader = fmt.Errorf("no need to process authorization header")
	resourceNameReg        = regexp.MustCompile("^/v2((?:/[a-z0-9._-]+)*/[a-z0-9._-]+)/(?:tags|blobs).*$")
)

type Authorization struct {
	Type      string   `json:"type" yaml:"type"`
	Target    string   `json:"target" yaml:"target"`
	UseRegexp bool     `json:"useRegexp" yaml:"useRegexp"`
	Actions   []string `json:"actions" yaml:"actions"`
	regexp    *regexp.Regexp
}

type UserAuthorization struct {
	Authorization
	User string `json:"user"`
}

type ClaimAccess struct {
	Type    string
	Name    string
	Actions []string
}

type AccessScope []ClaimAccess

type AuthProcessor struct {
	lock           sync.RWMutex
	Issuer         string
	TokenDuration  time.Duration
	StaticUsers    map[string]string
	SecretUsers    map[string]string
	StaticAuths    map[string][]Authorization
	SecretAuths    map[string][]Authorization
	ThirdpartyAuth ThirdpartyAuth

	signer jose.Signer
	kid    string
}

type ConfigFile struct {
	Users map[string]string          `json:"users" yaml:"users"`
	Auths map[string][]Authorization `json:"auths" yaml:"auths"`
}

type Token struct {
	Token string `json:"token"`
}
type Claims struct {
	Issuer    string           `json:"iss,omitempty"`
	Subject   string           `json:"sub,omitempty"`
	Audience  string           `json:"aud,omitempty"`
	Expiry    *jwt.NumericDate `json:"exp,omitempty"`
	NotBefore *jwt.NumericDate `json:"nbf,omitempty"`
	IssuedAt  *jwt.NumericDate `json:"iat,omitempty"`
	ID        string           `json:"jti,omitempty"`
	Access    []ClaimAccess    `json:"access"`
}

type ScopeDecoder func(r *http.Request) (AccessScope, error)
type ScopeMatcher func(req *http.Request, result AccessScope, request AccessScope) bool

func (ca *ClaimAccess) String() string {
	return strings.Join([]string{
		ca.Type, ca.Name, strings.Join(ca.Actions, ","),
	}, ":")
}

func (s AccessScope) String() string {
	t := make([]string, len(s))
	for i, it := range s {
		t[i] = it.String()
	}
	return strings.Join(t, " ")
}

func getActionFromHttpReq(req *http.Request) []string {
	if req.URL.Path == "/v2/" {
		return []string{}
	} else if req.URL.Path == "/v2/_catalog" {
		return []string{CatalogAction}
	}

	result := make([]string, 0)
	switch req.Method {
	case http.MethodGet, http.MethodHead:
		result = append(result, PullAction)
	case http.MethodPut, http.MethodPatch, http.MethodPost:
		result = append(result, PushAction)
	case http.MethodDelete:
		result = append(result, DeleteAction)
	default:
	}
	return result
}

func DecodeScopeFromUrl(req *http.Request) (AccessScope, error) {
	var r AccessScope
	var claimAccessName, claimAccessType string
	if req.URL.Path == "/v2/_catalog" {
		claimAccessName = "catalog"
		claimAccessType = RegistryAccessType
	} else if req.URL.Path == "/v2/" {
		return r, nil
		// When processing /v2/<name>/manifests/<reference>, special processing is required to prevent tags from being manifests, tags or blobs
	} else if pathParams := strings.Split(req.URL.Path, "/"); len(pathParams) >= 5 && pathParams[len(pathParams)-2] == "manifests" {
		claimAccessName = strings.Join(pathParams[2:len(pathParams)-2], "/")
		claimAccessType = RepositoryAccessType
	} else {
		nameArr := resourceNameReg.FindStringSubmatch(req.URL.Path)
		if len(nameArr) != 2 {
			return r, fmt.Errorf("invalid request url")
		}
		claimAccessName = nameArr[1][1:]
		claimAccessType = RepositoryAccessType
	}

	r = append(r, ClaimAccess{
		Type:    claimAccessType,
		Name:    claimAccessName,
		Actions: getActionFromHttpReq(req),
	})
	return r, nil
}

func DecodeScope(req *http.Request) (AccessScope, error) {
	var r AccessScope
	scope := req.FormValue("scope")
	if scope == "" {
		return r, nil
	}
	for _, it := range strings.Split(scope, " ") {
		access := strings.Split(it, ":")
		if len(access) != 3 {
			return nil, fmt.Errorf(`wrong scope format, original valule is "%s"`, scope)
		}
		ca := ClaimAccess{
			Type:    access[0],
			Name:    access[1],
			Actions: strings.Split(access[2], ","),
		}
		r = append(r, ca)
	}
	return r, nil
}

func NewAuthProcessor(privateKeyFile, publicCertFile, issuer string, tokenDuration int) (*AuthProcessor, error) {
	a := &AuthProcessor{
		Issuer:        issuer,
		TokenDuration: time.Second * time.Duration(tokenDuration),
	}
	if err := a.getKid(publicCertFile); err != nil {
		return nil, err
	}

	if err := a.generateSigner(privateKeyFile); err != nil {
		return nil, err
	}

	return a, nil
}

func (a *AuthProcessor) getKid(publicCertFile string) error {
	data, err := ioutil.ReadFile(publicCertFile)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("failed to parse certificate '%s' PEM", publicCertFile)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate '%s' error: %v ", publicCertFile, err)
	}

	pubKey, err := libtrust.FromCryptoPublicKey(crypto.PublicKey(cert.PublicKey))
	if err != nil {
		return fmt.Errorf("parse public key '%s' error: %v ", publicCertFile, err)
	}

	a.kid = pubKey.KeyID()
	return nil
}

func (a *AuthProcessor) generateSigner(privateKeyFile string) error {
	data, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return err
	}
	privKey, err := keyutil.ParsePrivateKeyPEM(data)
	if err != nil {
		return err
	}

	rsaPrivKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("the private key is not in RSA format")
	}

	op := &jose.SignerOptions{}

	a.signer, err = jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       rsaPrivKey,
	}, op.WithHeader(jose.HeaderKey("kid"), a.kid))
	return err
}

func (a *AuthProcessor) loadConfig(data []byte) (*ConfigFile, error) {
	c := ConfigFile{}
	if err := json.Unmarshal(data, &c); err != nil {
		return &c, yaml.Unmarshal(data, &c)
	}
	return &c, nil
}

func (a *AuthProcessor) parseAuths(auths map[string][]Authorization) {
	for _, auth := range auths {
		for i := range auth {
			if auth[i].Type == "" {
				auth[i].Type = RepositoryAccessType
			}
			if auth[i].UseRegexp {
				var err error
				auth[i].regexp, err = regexp.Compile(auth[i].Target)
				if err != nil {
					logger.Error(fmt.Sprintf("compile regexp '%s' error: %v", auth[i].Target, err), zap.String("func", "parseRegexp"))
				}
			}
		}
	}
}

func (a *AuthProcessor) LoadFromFile(data []byte) error {
	a.lock.Lock()
	defer a.lock.Unlock()
	c, err := a.loadConfig(data)
	if err != nil {
		return err
	}
	a.StaticUsers = c.Users
	a.StaticAuths = c.Auths
	a.parseAuths(a.StaticAuths)
	return nil
}

func (a *AuthProcessor) LoadFromSecret(dataOld, dataNew map[string][]byte) error {
	a.lock.Lock()
	defer a.lock.Unlock()
	if dataOld != nil {
		c, err := a.loadConfig(dataOld[SecretKey])
		if err != nil {
			return err
		}
		for u := range c.Users {
			delete(a.SecretUsers, u)
		}
		for u := range c.Auths {
			delete(a.SecretAuths, u)
		}
	}
	if dataNew != nil {
		c, err := a.loadConfig(dataOld[SecretKey])
		if err != nil {
			return err
		}
		if a.SecretUsers == nil {
			a.SecretUsers = make(map[string]string)
		}
		for u, it := range c.Users {
			a.SecretUsers[u] = it
		}
		if a.SecretAuths == nil {
			a.SecretAuths = make(map[string][]Authorization)
		}
		for u, it := range c.Auths {
			a.SecretAuths[u] = it
		}
	}
	a.parseAuths(a.SecretAuths)
	return nil
}

func (a *AuthProcessor) verifyPassword(password, hash string) bool {
	if strings.HasPrefix(hash, "PBKDF2:") {
		// to do
	} else if strings.HasPrefix(hash, "$") {
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil {
			return true
		}
	}
	return password == hash
}

func (a *AuthProcessor) Authenticate(header string) (string, error) {
	if header == "" {
		return AnonymousUser, nil
	}
	header = strings.TrimPrefix(header, BasicPrefix)
	decoded, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return "", errors.Wrap(err, "decode Basic token")
	}
	userpwd := strings.SplitN(string(decoded), ":", 2)
	if len(userpwd) != 2 {
		return "", fmt.Errorf("wrong user:password format")
	}
	username := userpwd[0]
	password := userpwd[1]
	a.lock.RLock()
	defer a.lock.RUnlock()
	hash, ok := a.SecretUsers[username]
	if !ok {
		hash, ok = a.StaticUsers[username]
	}
	if ok {
		if a.verifyPassword(password, hash) {
			return username, nil
		}
	} else if a.ThirdpartyAuth != nil {
		if _, err := a.ThirdpartyAuth.Login(username, password); err == nil {
			return username, nil
		}
	}
	return "", ErrAuthFailed
}

func (a *AuthProcessor) Authorize(user string, scope AccessScope) AccessScope {
	a.lock.RLock()
	defer a.lock.RUnlock()
	auth, ok := a.SecretAuths[user]
	if !ok {
		auth, ok = a.StaticAuths[user]
	}
	if !ok && a.ThirdpartyAuth != nil {
		auth, ok = a.ThirdpartyAuth.UserAuthorization(user)
		if ok {
			auths := map[string][]Authorization{
				user: auth,
			}
			a.parseAuths(auths)
			auth = auths[user]
		}
	}
	if !ok {
		return nil
	}

	var r AccessScope
	for _, it := range auth {
		for _, s := range scope {
			if s.Type != it.Type {
				continue
			}
			match := false
			if it.UseRegexp && it.regexp != nil {
				match = it.regexp.Match([]byte(s.Name))
			} else {
				match = s.Name == it.Target
			}
			if match {
				r = append(r, ClaimAccess{
					Type:    s.Type,
					Name:    s.Name,
					Actions: it.Actions,
				})
			}
		}
	}
	return r
}

func (a *AuthProcessor) Sign(user, service string, scope AccessScope) (*Token, error) {
	now := time.Now()
	claims := Claims{
		ID:        uuid.New().String(),
		Issuer:    a.Issuer,
		Subject:   user,
		Audience:  service,
		IssuedAt:  jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(now.Add(a.TokenDuration)),
		NotBefore: jwt.NewNumericDate(now),
		Access:    scope,
	}
	token, err := jwt.Signed(a.signer).Claims(claims).CompactSerialize()
	if err != nil {
		return nil, err
	}
	return &Token{
		Token: token,
	}, nil
}

func IsScopeActionMatch(req *http.Request, resultScope AccessScope, requestScope AccessScope) bool {
	if req.URL.Path == "/v2/" {
		return true
	}

	for _, resultAccess := range resultScope {
		for _, requestAccess := range requestScope {
			if requestAccess.Type != resultAccess.Type {
				continue
			}
			if !funk.Subset(requestAccess.Actions, resultAccess.Actions) {
				return false
			}
		}
	}

	return true
}

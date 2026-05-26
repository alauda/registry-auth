package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	jose "gopkg.in/go-jose/go-jose.v2"
	"gopkg.in/go-jose/go-jose.v2/jwt"
)

func TestMain(m *testing.M) {
	// parseAuths / file watch paths call logger.Error on errors; make it a no-op for tests.
	logger = zap.NewNop()
	os.Exit(m.Run())
}

func generateCertPair(t *testing.T, dir string) (certPath, keyPath string, cert *x509.Certificate) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "registry-auth-test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	certPath = filepath.Join(dir, "token.crt")
	keyPath = filepath.Join(dir, "token.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return
}

func newTestProcessor(t *testing.T) *AuthProcessor {
	t.Helper()
	certPath, keyPath, _ := generateCertPair(t, t.TempDir())
	p, err := NewAuthProcessor(keyPath, certPath, "test-issuer", 600)
	if err != nil {
		t.Fatalf("NewAuthProcessor: %v", err)
	}
	return p
}

// TestSign_EmitsX5cHeaderAndVerifies is the key regression test for the v3 compatibility
// change: tokens must carry an `x5c` JWS header (and no `kid`) so that both distribution
// v2.8.1 (parseAndVerifyCertChain) and v3.0.0 (verifyCertChain) verify them against the
// rootcertbundle.
func TestSign_EmitsX5cHeaderAndVerifies(t *testing.T) {
	certPath, keyPath, cert := generateCertPair(t, t.TempDir())
	p, err := NewAuthProcessor(keyPath, certPath, "iss", 600)
	if err != nil {
		t.Fatalf("NewAuthProcessor: %v", err)
	}

	scope := AccessScope{{Type: RepositoryAccessType, Name: "foo/bar", Actions: []string{PullAction}}}
	tok, err := p.Sign("alice", "svc", scope)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// 1. Raw protected header must carry x5c (and must not carry kid).
	parts := strings.Split(tok.Token, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected JWT segment count: %d", len(parts))
	}
	rawHdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if !strings.Contains(string(rawHdr), `"x5c":`) {
		t.Fatalf("expected x5c header, got %s", rawHdr)
	}
	if strings.Contains(string(rawHdr), `"kid":`) {
		t.Fatalf("unexpected kid header: %s", rawHdr)
	}

	// 2. Reparse and verify the cert chain against the cert as root — mirrors the
	//    distribution v2/v3 verify path.
	jws, err := jose.ParseSigned(tok.Token)
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	h := jws.Signatures[0].Header
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	chains, err := h.Certificates(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		t.Fatalf("Header.Certificates verify: %v", err)
	}
	if len(chains) == 0 || len(chains[0]) == 0 {
		t.Fatal("no verified chain returned")
	}

	// 3. Validate signature and check claim contents.
	parsed, err := jwt.ParseSigned(tok.Token)
	if err != nil {
		t.Fatalf("ParseSigned (jwt): %v", err)
	}
	var claims Claims
	if err := parsed.Claims(cert.PublicKey, &claims); err != nil {
		t.Fatalf("Claims verify: %v", err)
	}
	if claims.Issuer != "iss" {
		t.Fatalf("iss = %q", claims.Issuer)
	}
	if claims.Subject != "alice" {
		t.Fatalf("sub = %q", claims.Subject)
	}
	if claims.Audience != "svc" {
		t.Fatalf("aud = %q", claims.Audience)
	}
	if len(claims.Access) != 1 || claims.Access[0].Name != "foo/bar" {
		t.Fatalf("access = %+v", claims.Access)
	}
}

func basicHeader(user, pass string) string {
	return BasicPrefix + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func TestAuthenticate_EmptyHeaderIsAnonymous(t *testing.T) {
	p := newTestProcessor(t)
	user, err := p.Authenticate("")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if user != AnonymousUser {
		t.Fatalf("want %q, got %q", AnonymousUser, user)
	}
}

func TestAuthenticate_Plaintext(t *testing.T) {
	p := newTestProcessor(t)
	p.StaticUsers = map[string]string{"alice": "wonderland"}
	got, err := p.Authenticate(basicHeader("alice", "wonderland"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "alice" {
		t.Fatalf("got %q", got)
	}
}

func TestAuthenticate_Bcrypt(t *testing.T) {
	p := newTestProcessor(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	p.StaticUsers = map[string]string{"bob": string(hash)}
	got, err := p.Authenticate(basicHeader("bob", "s3cret"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "bob" {
		t.Fatalf("got %q", got)
	}
}

func TestAuthenticate_WrongPassword(t *testing.T) {
	p := newTestProcessor(t)
	p.StaticUsers = map[string]string{"alice": "wonderland"}
	if _, err := p.Authenticate(basicHeader("alice", "nope")); err != ErrAuthFailed {
		t.Fatalf("want ErrAuthFailed, got %v", err)
	}
}

func TestAuthenticate_UnknownUserNoThirdparty(t *testing.T) {
	p := newTestProcessor(t)
	if _, err := p.Authenticate(basicHeader("ghost", "x")); err != ErrAuthFailed {
		t.Fatalf("want ErrAuthFailed, got %v", err)
	}
}

func TestLoadFromFile_YAMLAndAuthorize(t *testing.T) {
	p := newTestProcessor(t)
	cfg := []byte(`users:
  alice: pwd1
auths:
  alice:
  - target: foo/bar
    actions: [pull]
  - target: "team/.*"
    useRegexp: true
    actions: [pull, push]
  _anonymous:
  - target: "public/.*"
    useRegexp: true
    actions: [pull]
`)
	if err := p.LoadFromFile(cfg); err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}

	if p.StaticUsers["alice"] != "pwd1" {
		t.Fatalf("users: %+v", p.StaticUsers)
	}

	// Default Type filled in by parseAuths.
	if p.StaticAuths["alice"][0].Type != RepositoryAccessType {
		t.Fatalf("expected default repository type, got %q", p.StaticAuths["alice"][0].Type)
	}
	// Regex compiled.
	if p.StaticAuths["alice"][1].regexp == nil {
		t.Fatalf("expected regexp compiled for team/.*")
	}

	// Literal match.
	got := p.Authorize("alice", AccessScope{{Type: RepositoryAccessType, Name: "foo/bar"}})
	if len(got) != 1 || got[0].Actions[0] != PullAction {
		t.Fatalf("literal authorize: %+v", got)
	}

	// Regex match.
	got = p.Authorize("alice", AccessScope{{Type: RepositoryAccessType, Name: "team/svc"}})
	if len(got) != 1 || len(got[0].Actions) != 2 {
		t.Fatalf("regex authorize: %+v", got)
	}

	// No matching rule for user → nil.
	if got := p.Authorize("alice", AccessScope{{Type: RepositoryAccessType, Name: "other/repo"}}); got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}

	// Anonymous fallback rule reachable for public/* with the "_anonymous" key.
	got = p.Authorize(AnonymousUser, AccessScope{{Type: RepositoryAccessType, Name: "public/x"}})
	if len(got) != 1 || got[0].Actions[0] != PullAction {
		t.Fatalf("anonymous authorize: %+v", got)
	}
}

func TestDecodeScope_FromQuery(t *testing.T) {
	req := httptest.NewRequest("GET", "http://x/auth/token?service=svc&scope=repository:foo/bar:pull,push", nil)
	got, err := DecodeScope(req)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries", len(got))
	}
	if got[0].Type != RepositoryAccessType || got[0].Name != "foo/bar" {
		t.Fatalf("got %+v", got[0])
	}
	if len(got[0].Actions) != 2 || got[0].Actions[0] != PullAction || got[0].Actions[1] != PushAction {
		t.Fatalf("actions: %+v", got[0].Actions)
	}
}

func TestDecodeScope_Empty(t *testing.T) {
	req := httptest.NewRequest("GET", "http://x/auth/token", nil)
	got, err := DecodeScope(req)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil scope, got %+v", got)
	}
}

func TestDecodeScope_Malformed(t *testing.T) {
	req := httptest.NewRequest("GET", "http://x/auth/token?scope=garbage", nil)
	if _, err := DecodeScope(req); err == nil {
		t.Fatal("expected error for malformed scope")
	}
}

func TestDecodeScopeFromUrl(t *testing.T) {
	cases := []struct {
		name       string
		method     string
		path       string
		wantType   string
		wantName   string
		wantAction string
		wantErr    bool
	}{
		{"base", "GET", "/v2/", "", "", "", false},
		{"catalog", "GET", "/v2/_catalog", RegistryAccessType, "catalog", CatalogAction, false},
		{"manifest_pull", "GET", "/v2/foo/bar/manifests/v1.0.0", RepositoryAccessType, "foo/bar", PullAction, false},
		{"manifest_push", "PUT", "/v2/foo/bar/manifests/v1", RepositoryAccessType, "foo/bar", PushAction, false},
		{"blob_pull", "GET", "/v2/foo/bar/blobs/sha256:deadbeef", RepositoryAccessType, "foo/bar", PullAction, false},
		{"blob_push", "POST", "/v2/foo/bar/blobs/uploads/", RepositoryAccessType, "foo/bar", PushAction, false},
		{"tags_list", "GET", "/v2/foo/bar/tags/list", RepositoryAccessType, "foo/bar", PullAction, false},
		{"manifest_delete", "DELETE", "/v2/foo/bar/manifests/sha256:abc", RepositoryAccessType, "foo/bar", DeleteAction, false},
		{"unknown", "GET", "/v2/foo/bar/weird/x", "", "", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(c.method, "http://x"+c.path, nil)
			got, err := DecodeScopeFromUrl(req)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if c.path == "/v2/" {
				if got != nil {
					t.Fatalf("base path: expected nil, got %+v", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("got %d entries", len(got))
			}
			if got[0].Type != c.wantType {
				t.Fatalf("type: want %q, got %q", c.wantType, got[0].Type)
			}
			if got[0].Name != c.wantName {
				t.Fatalf("name: want %q, got %q", c.wantName, got[0].Name)
			}
			if len(got[0].Actions) != 1 || got[0].Actions[0] != c.wantAction {
				t.Fatalf("actions: want [%s], got %+v", c.wantAction, got[0].Actions)
			}
		})
	}
}

func TestIsScopeActionMatch(t *testing.T) {
	// /v2/ always matches (auth bypass for the ping endpoint).
	if !IsScopeActionMatch(
		httptest.NewRequest("GET", "http://x/v2/", nil),
		nil, nil,
	) {
		t.Fatal("/v2/ should always match")
	}

	// Requested actions are a subset of result → match.
	if !IsScopeActionMatch(
		httptest.NewRequest("GET", "http://x/v2/foo/manifests/v1", nil),
		AccessScope{{Type: RepositoryAccessType, Name: "foo", Actions: []string{PullAction, PushAction}}},
		AccessScope{{Type: RepositoryAccessType, Name: "foo", Actions: []string{PullAction}}},
	) {
		t.Fatal("subset should match")
	}

	// Requested includes push but result only has pull → no match.
	if IsScopeActionMatch(
		httptest.NewRequest("PUT", "http://x/v2/foo/blobs/uploads/x", nil),
		AccessScope{{Type: RepositoryAccessType, Name: "foo", Actions: []string{PullAction}}},
		AccessScope{{Type: RepositoryAccessType, Name: "foo", Actions: []string{PushAction}}},
	) {
		t.Fatal("non-subset should not match")
	}
}

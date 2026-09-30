package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeIdP is a minimal OpenID Provider: discovery, JWKS with one RS256 key,
// and a token endpoint minting an ID token for a fixed identity.
type fakeIdP struct {
	srv      *httptest.Server
	key      *rsa.PrivateKey
	audience string
	issuer   string
	nonce    string // the nonce the flow started with
}

func newFakeIdP(t *testing.T, audience string) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	p := &fakeIdP{key: key, audience: audience}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		base := p.srv.URL
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 base,
			"authorization_endpoint": base + "/authorize",
			"token_endpoint":         base + "/token",
			"jwks_uri":               base + "/jwks.json",
		})
	})
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		pub := &key.PublicKey
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": "test-key", "alg": "RS256", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(bigEndian(pub.E)),
			}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.Form.Get("code") == "" {
			w.WriteHeader(400)
			return
		}
		now := time.Now().Unix()
		nonce := p.nonce
		idt := p.sign(map[string]any{
			"iss": p.srv.URL, "aud": p.audience, "sub": "user-1",
			"email": "ada@example.com", "email_verified": true,
			"name": "Ada", "groups": []string{"soc-team"},
			"nonce": nonce, "iat": now, "exp": now + 300,
		})
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": idt, "access_token": "at", "token_type": "Bearer"})
	})
	p.srv = httptest.NewServer(mux)
	p.issuer = p.srv.URL
	t.Cleanup(p.srv.Close)
	return p
}

func bigEndian(i int) []byte {
	b := make([]byte, 0)
	if i == 0 {
		return []byte{0}
	}
	for i > 0 {
		b = append([]byte{byte(i & 0xff)}, b...)
		i >>= 8
	}
	return b
}

func (p *fakeIdP) sign(claims map[string]any) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test-key"})
	payload, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, sum[:])
	if err != nil {
		panic(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestDiscoverAndExchange(t *testing.T) {
	p := newFakeIdP(t, "aegis-client")
	c := &Client{}
	ctx := context.Background()
	pc, err := c.Discover(ctx, p.srv.URL)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if pc.TokenEndpoint == "" || pc.JWKSURI == "" {
		t.Fatalf("discovery incomplete: %+v", pc)
	}
	state, _ := NewState()
	nonce, _ := NewState()
	p.nonce = nonce
	claims, err := c.Exchange(ctx, pc, "aegis-client", "secret", "the-code", "https://aegis.example.com/api/v1/auth/oidc/callback", nonce)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if claims.Email != "ada@example.com" || claims.Subject != "user-1" {
		t.Fatalf("claims: %+v", claims)
	}
	found := false
	for _, g := range claims.Groups {
		if g == "soc-team" {
			found = true
		}
	}
	if !found {
		t.Fatalf("groups missing: %+v", claims.Groups)
	}
	_ = state
}

func TestVerifyRejectsWrongAudience(t *testing.T) {
	p := newFakeIdP(t, "aegis-client")
	c := &Client{}
	pc, _ := c.Discover(context.Background(), p.srv.URL)
	// Token signed for a different client id.
	idt := p.sign(map[string]any{
		"iss": p.srv.URL, "aud": "someone-else", "sub": "u",
		"email": "x@example.com", "exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := c.VerifyIDToken(context.Background(), pc, "aegis-client", idt, ""); err == nil {
		t.Fatal("expected audience mismatch error")
	}
}

func TestVerifyRejectsTamperedToken(t *testing.T) {
	p := newFakeIdP(t, "aegis-client")
	c := &Client{}
	pc, _ := c.Discover(context.Background(), p.srv.URL)
	idt := p.sign(map[string]any{
		"iss": p.srv.URL, "aud": "aegis-client", "sub": "u",
		"email": "x@example.com", "exp": time.Now().Add(time.Hour).Unix(),
	})
	parts := strings.Split(idt, ".")
	parts[2] = parts[2][:len(parts[2])-2] + "AA"
	if _, err := c.VerifyIDToken(context.Background(), pc, "aegis-client", strings.Join(parts, "."), ""); err == nil {
		t.Fatal("tampered signature must fail")
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	p := newFakeIdP(t, "aegis-client")
	c := &Client{}
	pc, _ := c.Discover(context.Background(), p.srv.URL)
	idt := p.sign(map[string]any{
		"iss": p.srv.URL, "aud": "aegis-client", "sub": "u",
		"email": "x@example.com", "exp": time.Now().Add(-time.Hour).Unix(),
	})
	if _, err := c.VerifyIDToken(context.Background(), pc, "aegis-client", idt, ""); err == nil {
		t.Fatal("expired token must fail")
	}
}

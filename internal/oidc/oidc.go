// Package oidc implements the small slice of OpenID Connect the platform
// needs for F4: discovery, the authorization-code flow, and RS256/ES256
// ID-token verification against the issuer's published JWKS. One provider
// per organization; local break-glass accounts stay password-based.
package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ProviderConfig is the discovery document subset the flow needs.
type ProviderConfig struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// Audience accepts both JWT forms of "aud": a single string (the common
// case for id_token) or an array.
type Audience []string

func (a *Audience) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*a = Audience{s}
		return nil
	}
	var arr []string
	if err := json.Unmarshal(b, &arr); err != nil {
		return err
	}
	*a = arr
	return nil
}

// IDClaims is the verified ID-token payload.
type IDClaims struct {
	Subject       string   `json:"sub"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Name          string   `json:"name"`
	Groups        []string `json:"groups"`
	Nonce         string   `json:"nonce"`
	Audience      Audience `json:"aud"`
	Issuer        string   `json:"iss"`
	Expiry        int64    `json:"exp"`
}

// Client performs discovery, code exchange and ID-token verification.
type Client struct {
	HTTP *http.Client
	Now  func() time.Time

	mu   sync.Mutex
	jwks map[string]jwksEntry
}

type jwksEntry struct {
	keys    map[string]jwkKey
	fetched time.Time
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`

	rsaKey *rsa.PublicKey
	ecKey  *ecdsa.PublicKey
}

var (
	ErrInvalidToken = errors.New("oidc: invalid id_token")
	ErrBadIssuer    = errors.New("oidc: issuer mismatch")
)

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Discover fetches and sanity-checks the provider's discovery document.
func (c *Client) Discover(ctx context.Context, issuer string) (*ProviderConfig, error) {
	issuer = strings.TrimSuffix(issuer, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	var pc ProviderConfig
	if err := c.doJSON(req, &pc); err != nil {
		return nil, err
	}
	if pc.AuthorizationEndpoint == "" || pc.TokenEndpoint == "" || pc.JWKSURI == "" {
		return nil, errors.New("oidc: discovery document is missing endpoints")
	}
	if strings.TrimSuffix(pc.Issuer, "/") != issuer {
		return nil, fmt.Errorf("%w: discovered %q, expected %q", ErrBadIssuer, pc.Issuer, issuer)
	}
	return &pc, nil
}

// AuthURL builds the authorization redirect.
func AuthURL(pc *ProviderConfig, clientID, redirectURI, state, nonce string) string {
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"scope":         {"openid email profile"},
		"state":         {state},
		"nonce":         {nonce},
	}
	return pc.AuthorizationEndpoint + "?" + q.Encode()
}

// Exchange swaps the authorization code for tokens and verifies the ID
// token (signature, iss, aud, exp, nonce) before returning its claims.
func (c *Client) Exchange(ctx context.Context, pc *ProviderConfig, clientID, clientSecret, code, redirectURI, nonce string) (*IDClaims, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pc.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var tokenResp struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
		Desc    string `json:"error_description"`
	}
	if err := c.doJSON(req, &tokenResp); err != nil {
		return nil, err
	}
	if tokenResp.IDToken == "" {
		return nil, fmt.Errorf("oidc: token endpoint error: %s %s", tokenResp.Error, tokenResp.Desc)
	}
	return c.VerifyIDToken(ctx, pc, clientID, tokenResp.IDToken, nonce)
}

// VerifyIDToken checks the JWS signature against the issuer's JWKS and the
// standard claims.
func (c *Client) VerifyIDToken(ctx context.Context, pc *ProviderConfig, clientID, idToken, nonce string) (*IDClaims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, ErrInvalidToken
	}
	key, err := c.verifyKey(ctx, pc.JWKSURI, header.Kid, header.Alg)
	if err != nil {
		return nil, err
	}
	signed := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalidToken
	}
	sum := sha256.Sum256([]byte(signed))
	switch {
	case header.Alg == "RS256" && key.rsaKey != nil:
		if err := rsa.VerifyPKCS1v15(key.rsaKey, crypto.SHA256, sum[:], sig); err != nil {
			return nil, ErrInvalidToken
		}
	case header.Alg == "ES256" && key.ecKey != nil:
		if len(sig) != 64 {
			return nil, ErrInvalidToken
		}
		var r, s big.Int
		r.SetBytes(sig[:32])
		s.SetBytes(sig[32:])
		if !ecdsa.Verify(key.ecKey, sum[:], &r, &s) {
			return nil, ErrInvalidToken
		}
	default:
		return nil, fmt.Errorf("oidc: unsupported alg %q or no matching key", header.Alg)
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var claims IDClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, ErrInvalidToken
	}
	if claims.Expiry > 0 && c.now().Unix() > claims.Expiry {
		return nil, errors.New("oidc: id_token expired")
	}
	if claims.Issuer != "" && strings.TrimSuffix(claims.Issuer, "/") != strings.TrimSuffix(pc.Issuer, "/") {
		return nil, ErrBadIssuer
	}
	if len(claims.Audience) > 0 {
		audOK := false
		for _, a := range claims.Audience {
			if a == clientID {
				audOK = true
				break
			}
		}
		if !audOK {
			return nil, errors.New("oidc: id_token audience mismatch")
		}
	}
	if nonce != "" && claims.Nonce != nonce {
		return nil, errors.New("oidc: nonce mismatch")
	}
	if claims.Email == "" && claims.Subject == "" {
		return nil, errors.New("oidc: id_token carries neither email nor sub")
	}
	return &claims, nil
}

// NewState returns a random URL-safe value for state/nonce.
func NewState() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (c *Client) verifyKey(ctx context.Context, jwksURI, kid, alg string) (*jwkKey, error) {
	if keys := c.cachedJWKS(jwksURI); keys != nil {
		if k := pickKey(keys, kid, alg); k != nil {
			return k, nil
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, err
	}
	var set struct {
		Keys []jwkKey `json:"keys"`
	}
	if err := c.doJSON(req, &set); err != nil {
		return nil, err
	}
	parsed := map[string]jwkKey{}
	for _, k := range set.Keys {
		if err := k.parse(); err != nil {
			continue
		}
		parsed[k.Kid] = k
	}
	c.mu.Lock()
	if c.jwks == nil {
		c.jwks = map[string]jwksEntry{}
	}
	c.jwks[jwksURI] = jwksEntry{keys: parsed, fetched: c.now()}
	c.mu.Unlock()
	if k := pickKey(parsed, kid, alg); k != nil {
		return k, nil
	}
	return nil, errors.New("oidc: no matching signing key")
}

func pickKey(keys map[string]jwkKey, kid, alg string) *jwkKey {
	if k, ok := keys[kid]; ok && algMatches(k, alg) {
		return &k
	}
	if kid == "" && len(keys) == 1 {
		for _, k := range keys {
			if algMatches(k, alg) {
				kk := k
				return &kk
			}
		}
	}
	return nil
}

func algMatches(k jwkKey, alg string) bool {
	if k.Alg == "" {
		return true
	}
	return k.Alg == alg
}

func (k *jwkKey) parse() error {
	switch k.Kty {
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return err
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return err
		}
		eInt := int(new(big.Int).SetBytes(e).Int64())
		if eInt < 1 {
			return errors.New("oidc: bad exponent")
		}
		k.rsaKey = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: eInt}
	case "EC":
		if k.Crv != "P-256" {
			return errors.New("oidc: unsupported curve " + k.Crv)
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return err
		}
		y, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return err
		}
		k.ecKey = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	default:
		return errors.New("oidc: unsupported key type " + k.Kty)
	}
	return nil
}

func (c *Client) cachedJWKS(uri string) map[string]jwkKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.jwks[uri]; ok && c.now().Sub(e.fetched) < 10*time.Minute {
		return e.keys
	}
	return nil
}

func (c *Client) doJSON(req *http.Request, out any) error {
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("oidc: endpoint returned status %d", resp.StatusCode)
	}
	return json.Unmarshal(data, out)
}

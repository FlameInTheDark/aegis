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
	"testing"
	"time"
)

func TestDebugSig(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		pub := &key.PublicKey
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "kid": "k1", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(bigEndian(pub.E)),
			}},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1"})
	payload, _ := json.Marshal(map[string]any{"sub": "u", "exp": time.Now().Add(time.Hour).Unix()})
	si := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(si))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	token := si + "." + base64.RawURLEncoding.EncodeToString(sig)

	c := &Client{}
	pc := &ProviderConfig{Issuer: "x", JWKSURI: srv.URL + "/jwks.json"}
	k, err := c.verifyKey(context.Background(), pc.JWKSURI, "k1", "RS256")
	if err != nil {
		t.Fatalf("verifyKey: %v", err)
	}
	if k.rsaKey == nil {
		t.Fatal("rsa key nil")
	}
	claims, err := c.VerifyIDToken(context.Background(), pc, "aud", token, "")
	t.Logf("claims=%+v err=%v", claims, err)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
}

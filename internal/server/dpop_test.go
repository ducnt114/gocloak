package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ducnt114/gocloak/internal/jwt"
	"github.com/ducnt114/gocloak/internal/service"
)

// dpopSigner makes DPoP proofs with an EC key.
type dpopSigner struct {
	key *jwt.Key
	jwk jwt.JWK
}

func newDPoPSigner(t *testing.T) *dpopSigner {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k := &jwt.Key{Alg: "ES256", Private: priv, Public: &priv.PublicKey}
	j, _ := k.JWK()
	j.Kid = ""
	return &dpopSigner{key: k, jwk: j}
}

func (s *dpopSigner) proof(method, u, accessToken string) string {
	h, _ := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": s.jwk})
	c := jwt.Claims{"jti": service.NewID(), "htm": method, "htu": u, "iat": time.Now().Unix()}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		c["ath"] = b64u.EncodeToString(sum[:])
	}
	p, _ := json.Marshal(c)
	signing := b64u.EncodeToString(h) + "." + b64u.EncodeToString(p)
	sum := sha256.Sum256([]byte(signing))
	r, sv, _ := ecdsa.Sign(rand.Reader, s.key.Private.(*ecdsa.PrivateKey), sum[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sv.FillBytes(sig[32:])
	return signing + "." + b64u.EncodeToString(sig)
}

func TestDPoP(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	e.expect(e.do(nil, "POST", "/admin/realms/demo/clients", admin, map[string]any{"clientId": "spa", "publicClient": true,
		"directAccessGrantsEnabled": true, "attributes": map[string]string{"dpop.bound.access.tokens": "true"}}, nil), 201)
	tokenURL := e.srv.URL + "/realms/demo/protocol/openid-connect/token"
	userinfoURL := e.srv.URL + "/realms/demo/protocol/openid-connect/userinfo"
	signer := newDPoPSigner(t)
	jkt, _ := signer.jwk.Thumbprint()

	post := func(form url.Values, proof string) *response {
		req, _ := http.NewRequest("POST", tokenURL, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if proof != "" {
			req.Header.Set("DPoP", proof)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return &response{status: resp.StatusCode, header: resp.Header, body: body}
	}
	grant := url.Values{"grant_type": {"password"}, "client_id": {"spa"}, "username": {"alice"}, "password": {"wonderland"}, "scope": {"openid"}}

	// the client requires proofs
	if r := post(grant, ""); r.status != 400 || !strings.Contains(string(r.body), "invalid_dpop_proof") {
		t.Fatalf("no proof: %d %s", r.status, r.body)
	}
	if r := post(grant, signer.proof("POST", "https://elsewhere/token", "")); r.status != 400 {
		t.Fatalf("wrong htu: %d", r.status)
	}
	var tk struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
	}
	e.expect(post(grant, signer.proof("POST", tokenURL, "")), 200).json(&tk)
	if tk.TokenType != "DPoP" || service.BoundKey(claims(t, tk.AccessToken)) != jkt || service.BoundKey(claims(t, tk.RefreshToken)) != jkt {
		t.Fatalf("bound tokens: %+v", tk)
	}

	userinfo := func(scheme, proof string) int {
		req, _ := http.NewRequest("GET", userinfoURL, nil)
		req.Header.Set("Authorization", scheme+" "+tk.AccessToken)
		if proof != "" {
			req.Header.Set("DPoP", proof)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	p := signer.proof("GET", userinfoURL, tk.AccessToken)
	if st := userinfo("DPoP", p); st != 200 {
		t.Fatalf("userinfo with proof: %d", st)
	}
	if st := userinfo("DPoP", p); st != 401 {
		t.Fatalf("replayed proof: %d", st)
	}
	if st := userinfo("Bearer", ""); st != 401 {
		t.Fatalf("bound token as bearer: %d", st)
	}
	other := newDPoPSigner(t)
	if st := userinfo("DPoP", other.proof("GET", userinfoURL, tk.AccessToken)); st != 401 {
		t.Fatalf("proof of another key: %d", st)
	}
	if st := userinfo("DPoP", signer.proof("GET", userinfoURL, "another-token")); st != 401 {
		t.Fatalf("wrong ath: %d", st)
	}

	// the bound refresh token needs a proof of the same key
	refresh := url.Values{"grant_type": {"refresh_token"}, "client_id": {"spa"}, "refresh_token": {tk.RefreshToken}}
	if r := post(refresh, other.proof("POST", tokenURL, "")); r.status != 400 || !strings.Contains(string(r.body), "invalid_dpop_proof") {
		t.Fatalf("refresh with another key: %d %s", r.status, r.body)
	}
	e.expect(post(refresh, signer.proof("POST", tokenURL, "")), 200)
}

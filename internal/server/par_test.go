package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ducnt114/gocloak/internal/jwt"
)

func TestPushedAuthorizationRequests(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	par := func(form url.Values) *response {
		return e.do(nil, "POST", "/realms/demo/protocol/openid-connect/ext/par/request", "", nil, form)
	}
	base := url.Values{"client_id": {"web"}, "client_secret": {"web-secret"}, "response_type": {"code"}, "scope": {"openid"},
		"redirect_uri": {"http://app.test/cb"}, "state": {"st"}, "nonce": {"n1"}}
	var pr struct {
		RequestURI string `json:"request_uri"`
		ExpiresIn  int    `json:"expires_in"`
	}
	e.expect(par(base), 201).json(&pr)
	if !strings.HasPrefix(pr.RequestURI, "urn:ietf:params:oauth:request_uri:") || pr.ExpiresIn != 60 {
		t.Fatalf("PAR response: %+v", pr)
	}
	browser := newBrowser()
	auth := "/realms/demo/protocol/openid-connect/auth?" + url.Values{"client_id": {"web"}, "request_uri": {pr.RequestURI}}.Encode()
	r := e.expect(e.do(browser, "GET", auth, "", nil, nil), 200)
	r = e.do(browser, "POST", formAction(t, r.body), "", nil, url.Values{"username": {"alice"}, "password": {"wonderland"}})
	loc, _ := url.Parse(r.header.Get("Location"))
	if loc.Query().Get("state") != "st" {
		t.Fatalf("pushed state lost: %s", loc)
	}
	tk := e.exchangeCode(codeOf(t, r))
	if claims(t, tk.IDToken).String("nonce") != "n1" {
		t.Fatal("pushed nonce lost")
	}
	// request URIs are used once, and only by their client
	e.expect(e.do(newBrowser(), "GET", auth, "", nil, nil), 400)
	e.expect(par(base), 201).json(&pr)
	e.expect(e.do(nil, "POST", "/admin/realms/demo/clients", admin, map[string]any{"clientId": "other", "secret": "s",
		"redirectUris": []string{"http://app.test/*"}, "attributes": map[string]string{"require.pushed.authorization.requests": "true"}}, nil), 201)
	e.expect(e.do(newBrowser(), "GET", "/realms/demo/protocol/openid-connect/auth?"+url.Values{"client_id": {"other"},
		"request_uri": {pr.RequestURI}}.Encode(), "", nil, nil), 400)

	// errors of the PAR endpoint
	for name, tc := range map[string]struct {
		form   url.Values
		status int
		desc   string
	}{
		"bad secret":   {withParam(base, "client_secret", "x"), 401, "Authentication failed."},
		"bad redirect": {withParam(base, "redirect_uri", "http://evil/"), 400, "Invalid parameter: redirect_uri"},
		"request_uri":  {withParam(base, "request_uri", "https://x"), 400, "It is not allowed to include request_uri to PAR."},
		"bad scope":    {withParam(base, "scope", "openid nope"), 400, "Invalid scopes: openid nope"},
	} {
		r := par(tc.form)
		if r.status != tc.status || !strings.Contains(string(r.body), tc.desc) {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
	// a client requiring PAR refuses plain requests
	r = e.expect(e.do(newBrowser(), "GET", "/realms/demo/protocol/openid-connect/auth?"+url.Values{"client_id": {"other"}, "response_type": {"code"},
		"redirect_uri": {"http://app.test/cb"}}.Encode(), "", nil, nil), 302)
	if !strings.Contains(r.header.Get("Location"), "Pushed+Authorization+Request+is+only+allowed") {
		t.Fatalf("require PAR: %s", r.header.Get("Location"))
	}
}

func withParam(v url.Values, k, val string) url.Values {
	out := url.Values{}
	for key, vals := range v {
		out[key] = vals
	}
	out.Set(k, val)
	return out
}

func TestRequestObjects(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key := &jwt.Key{Alg: "ES256", Private: priv, Public: &priv.PublicKey, Kid: "k1"}
	pub, _ := key.JWK()
	jwks, _ := json.Marshal(map[string]any{"keys": []any{pub}})
	var objects = map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(objects[r.URL.Path])) }))
	defer srv.Close()
	e.expect(e.do(nil, "POST", "/admin/realms/demo/clients", admin, map[string]any{"clientId": "ro", "secret": "a-long-client-secret-for-hmac-256-keys",
		"redirectUris": []string{"http://app.test/*"}, "attributes": map[string]string{"use.jwks.string": "true", "jwks.string": string(jwks),
			"request.uris": srv.URL + "/ok/*"}}, nil), 201)

	now := time.Now().Unix()
	obj := jwt.Claims{"iss": "ro", "aud": e.srv.URL + "/realms/demo", "client_id": "ro", "response_type": "code", "scope": "openid",
		"redirect_uri": "http://app.test/obj", "state": "from-object", "nonce": "obj-nonce", "iat": now, "exp": now + 60}
	es256, _ := jwt.Sign(obj, key)
	hs256, _ := jwt.Sign(obj, &jwt.Key{Alg: "HS256", Secret: []byte("a-long-client-secret-for-hmac-256-keys")})
	wrong, _ := jwt.Sign(obj, &jwt.Key{Alg: "HS256", Secret: []byte("another-secret-another-secret-another")})
	b, _ := json.Marshal(obj)
	none := "eyJhbGciOiJub25lIn0." + b64u.EncodeToString(b) + "."
	objects["/ok/1"] = es256

	login := func(q url.Values) *response {
		q.Set("client_id", "ro")
		return e.do(newBrowser(), "GET", "/realms/demo/protocol/openid-connect/auth?"+q.Encode(), "", nil, nil)
	}
	for name, q := range map[string]url.Values{
		"signed with the client key":  {"request": {es256}, "redirect_uri": {"http://app.test/query"}},
		"HMAC with the client secret": {"request": {hs256}},
		"unsigned":                    {"request": {none}},
		"by reference":                {"request_uri": {srv.URL + "/ok/1"}},
	} {
		r := login(q)
		if r.status != 200 || !strings.Contains(string(r.body), `name="password"`) {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
	for name, q := range map[string]url.Values{
		"wrong HMAC key":         {"request": {wrong}},
		"garbage":                {"request": {"abc"}},
		"unregistered reference": {"request_uri": {srv.URL + "/other"}},
	} {
		if r := login(q); r.status != 400 || !strings.Contains(string(r.body), "Invalid Request") {
			t.Errorf("%s: %d", name, r.status)
		}
	}

	// the object's parameters win: its redirect URI and state are used
	browser := newBrowser()
	r := e.expect(e.do(browser, "GET", "/realms/demo/protocol/openid-connect/auth?"+url.Values{"client_id": {"ro"}, "request": {es256},
		"redirect_uri": {"http://app.test/query"}, "state": {"from-query"}}.Encode(), "", nil, nil), 200)
	r = e.expect(e.do(browser, "POST", formAction(t, r.body), "", nil, url.Values{"username": {"alice"}, "password": {"wonderland"}}), 302)
	if loc := r.header.Get("Location"); !strings.HasPrefix(loc, "http://app.test/obj?") || !strings.Contains(loc, "state=from-object") {
		t.Fatalf("redirect: %s", loc)
	}

	// an algorithm can be required
	id := clientUUID(e, admin, "ro")
	var rep map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/clients/"+id, admin, nil, nil), 200).json(&rep)
	rep["attributes"] = map[string]string{"request.object.signature.alg": "ES256", "request.object.required": "request or request_uri"}
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/clients/"+id, admin, rep, nil), 204)
	if r := login(url.Values{"request": {none}}); r.status != 400 {
		t.Fatalf("unsigned object with ES256 required: %d", r.status)
	}
	if r := login(url.Values{"request": {es256}}); r.status != 200 {
		t.Fatalf("ES256 object: %d", r.status)
	}
	r = login(url.Values{"response_type": {"code"}, "redirect_uri": {"http://app.test/cb"}})
	if r.status != 302 || !strings.Contains(r.header.Get("Location"), "error=invalid_request") {
		t.Fatalf("object required: %d %s", r.status, r.header.Get("Location"))
	}
}

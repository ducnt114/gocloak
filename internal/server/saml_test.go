package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"html"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	crewsaml "github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"

	"github.com/ducnt114/gocloak/internal/saml"
)

// testSP is a crewjam/saml service provider (the reference SP of the
// SAML acceptance tests) running against a gocloak realm.
type testSP struct {
	srv *httptest.Server
	mw  *samlsp.Middleware
	key *rsa.PrivateKey
}

func newKeyPair(t *testing.T, cn string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}

// newTestSP starts a service provider trusting the demo realm. Its page
// /hello requires a SAML session and prints the session attributes.
func newTestSP(t *testing.T, e *env) *testSP {
	t.Helper()
	sp := &testSP{}
	var mu sync.Mutex
	mux := http.NewServeMux()
	sp.srv = httptest.NewServer(mux)
	t.Cleanup(sp.srv.Close)

	desc := e.expect(e.do(nil, "GET", "/realms/demo/protocol/saml/descriptor", "", nil, nil), 200)
	md, err := samlsp.ParseMetadata(desc.body)
	if err != nil {
		t.Fatalf("parse IdP metadata: %v\n%s", err, desc.body)
	}
	key, cert := newKeyPair(t, "sp")
	sp.key = key
	root, _ := url.Parse(sp.srv.URL)
	sp.mw, err = samlsp.New(samlsp.Options{URL: *root, Key: key, Certificate: cert, IDPMetadata: md, SignRequest: true})
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/saml/", sp.mw)
	mux.Handle("/hello", sp.mw.RequireAccount(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		s := samlsp.SessionFromContext(r.Context()).(samlsp.JWTSessionClaims)
		_ = json.NewEncoder(w).Encode(map[string]any{"subject": s.Subject, "attributes": s.Attributes})
	})))
	return sp
}

// register creates the SAML client from the SP metadata through the
// client description converter, as the console's "Import client" does.
func (sp *testSP) register(t *testing.T, e *env, admin string, attrs map[string]string, mappers []map[string]any) string {
	t.Helper()
	meta, err := xml.Marshal(sp.mw.ServiceProvider.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", e.srv.URL+"/admin/realms/demo/client-description-converter", strings.NewReader(string(meta)))
	req.Header.Set("Authorization", "Bearer "+admin)
	req.Header.Set("Content-Type", "application/xml")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var rep map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil || resp.StatusCode != 200 {
		t.Fatalf("convert metadata: %d %v", resp.StatusCode, err)
	}
	if rep["clientId"] != sp.srv.URL+"/saml/metadata" || rep["protocol"] != "saml" {
		t.Fatalf("converted client: %v", rep)
	}
	a := rep["attributes"].(map[string]any)
	if a["saml_assertion_consumer_url_post"] != sp.srv.URL+"/saml/acs" || a["saml.client.signature"] != "true" || a["saml.signing.certificate"] == "" {
		t.Fatalf("converted attributes: %v", a)
	}
	for k, v := range attrs {
		a[k] = v
	}
	rep["protocolMappers"] = mappers
	return idFromLocation(t, e.expect(e.do(nil, "POST", "/admin/realms/demo/clients", admin, rep, nil), 201))
}

var hiddenInputRe = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)"`)

// postForm submits the auto-posting form of a page (the HTTP-POST binding).
func postForm(t *testing.T, e *env, browser *http.Client, page *response) *response {
	t.Helper()
	fields := url.Values{}
	for _, m := range hiddenInputRe.FindAllSubmatch(page.body, -1) {
		fields.Set(string(m[1]), html.UnescapeString(string(m[2])))
	}
	return e.do(browser, "POST", formAction(t, page.body), "", nil, fields)
}

func formField(t *testing.T, page *response, name string) string {
	t.Helper()
	for _, m := range hiddenInputRe.FindAllSubmatch(page.body, -1) {
		if string(m[1]) == name {
			return html.UnescapeString(string(m[2]))
		}
	}
	t.Fatalf("no %s field in %s", name, page.body)
	return ""
}

// login runs an SP initiated login and returns the SP session.
func (sp *testSP) login(t *testing.T, e *env, browser *http.Client, user, pass string) map[string]any {
	t.Helper()
	r := e.expect(e.do(browser, "GET", sp.srv.URL+"/hello", "", nil, nil), 302)
	loc := r.header.Get("Location")
	if !strings.HasPrefix(loc, e.srv.URL+"/realms/demo/protocol/saml?SAMLRequest=") || !strings.Contains(loc, "&Signature=") {
		t.Fatalf("not sent to the IdP with a signed request: %s", loc)
	}
	r = e.do(browser, "GET", loc, "", nil, nil)
	if r.status == 200 && strings.Contains(string(r.body), `name="password"`) {
		r = e.do(browser, "POST", formAction(t, r.body), "", nil, url.Values{"username": {user}, "password": {pass}})
	}
	e.expect(r, 200)
	if formAction(t, r.body) != sp.srv.URL+"/saml/acs" {
		t.Fatalf("response not posted to the ACS: %s", r.body)
	}
	r = e.expect(postForm(t, e, browser, r), 302)
	r = e.expect(e.do(browser, "GET", sp.srv.URL+r.header.Get("Location"), "", nil, nil), 200)
	var session map[string]any
	r.json(&session)
	return session
}

func attrValues(session map[string]any, name string) []string {
	attrs, _ := session["attributes"].(map[string]any)
	return strs(attrs[name])
}

func TestSAMLLoginWithServiceProvider(t *testing.T) {
	for _, tc := range []struct {
		name  string
		attrs map[string]string
	}{
		{"signed response", map[string]string{"saml.encrypt": "false"}},
		{"signed encrypted assertion", map[string]string{"saml.server.signature": "false", "saml.assertion.signature": "true"}},
		// (the other algorithms are covered by the saml package tests: crewjam
		// only decrypts AES-128-GCM and RSA-OAEP-MGF1P)
		{"aes-gcm and email name id", map[string]string{"saml.encryption.algorithm": saml.EncAES128GCM,
			"saml_name_id_format": "email", "saml_force_name_id_format": "true"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			admin, _ := e.setupDemo()
			sp := newTestSP(t, e)
			sp.register(t, e, admin, tc.attrs, []map[string]any{
				{"name": "email", "protocol": "saml", "protocolMapper": "saml-user-property-mapper",
					"config": map[string]string{"user.attribute": "email", "attribute.name": "email", "attribute.nameformat": "Basic"}},
				{"name": "groups", "protocol": "saml", "protocolMapper": "saml-group-membership-mapper",
					"config": map[string]string{"attribute.name": "member", "full.path": "true", "single": "true"}},
			})
			browser := newBrowser()
			session := sp.login(t, e, browser, "alice", "wonderland")
			if sub, _ := session["subject"].(string); sub == "" || (tc.attrs["saml_name_id_format"] == "email" && sub != "alice@example.com") {
				t.Fatalf("subject: %v", session)
			}
			if !slices.Contains(attrValues(session, "Role"), "editor") || !slices.Equal(attrValues(session, "member"), []string{"/staff"}) ||
				!slices.Equal(attrValues(session, "email"), []string{"alice@example.com"}) {
				t.Fatalf("attributes: %v", session)
			}

			// a second SP login is answered from the SSO session
			browser2Cookies := browser.Jar
			sp2 := newTestSP(t, e)
			sp2.register(t, e, admin, map[string]string{"saml.encrypt": "false"}, nil)
			if s := sp2.login(t, e, &http.Client{Jar: browser2Cookies, CheckRedirect: browser.CheckRedirect}, "", ""); s["subject"] == "" {
				t.Fatalf("SSO login: %v", s)
			}
		})
	}
}

func TestSAMLRequestValidation(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	sp := newTestSP(t, e)
	sp.register(t, e, admin, map[string]string{"saml.encrypt": "false"}, nil)
	browser := newBrowser()
	r := e.expect(e.do(browser, "GET", sp.srv.URL+"/hello", "", nil, nil), 302)
	loc := r.header.Get("Location")

	// a tampered signature is rejected
	bad := regexp.MustCompile(`Signature=[^&]+`).ReplaceAllString(loc, "Signature=AAAA")
	if r := e.do(browser, "GET", bad, "", nil, nil); r.status != 400 || !strings.Contains(string(r.body), "Invalid requester") {
		t.Fatalf("bad signature: %d %s", r.status, r.body)
	}
	// so is an unsigned request
	unsigned := regexp.MustCompile(`&(SigAlg|Signature)=[^&]+`).ReplaceAllString(loc, "")
	if r := e.do(browser, "GET", unsigned, "", nil, nil); r.status != 400 {
		t.Fatalf("unsigned: %d", r.status)
	}
	// garbage
	for _, q := range []string{"SAMLRequest=%%%", "SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("<x/>"))), ""} {
		if r := e.do(browser, "GET", "/realms/demo/protocol/saml?"+q, "", nil, nil); r.status != 400 || !strings.Contains(string(r.body), "Invalid Request") {
			t.Fatalf("%q: %d", q, r.status)
		}
	}
	// the original request still works
	r = e.expect(e.do(browser, "GET", loc, "", nil, nil), 200)
	if !strings.Contains(string(r.body), `name="password"`) {
		t.Fatalf("login page: %s", r.body)
	}
}

func TestSAMLLogout(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()

	// SP 1 logs out with a LogoutRequest (HTTP-POST binding)
	sp := newTestSP(t, e)
	sp.register(t, e, admin, map[string]string{"saml.encrypt": "false"}, nil)
	// SP 2 is logged out through the browser, SP 3 from the server
	sp2 := newTestSP(t, e)
	sp2.register(t, e, admin, map[string]string{"saml.encrypt": "false", "saml_name_id_format": "email", "saml_force_name_id_format": "true"}, nil)
	var mu sync.Mutex
	var backchannel []string
	sp3 := newTestSP(t, e)
	sp3.srv.Config.Handler.(*http.ServeMux).HandleFunc("/backchannel", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		b, _ := base64.StdEncoding.DecodeString(r.PostFormValue("SAMLRequest"))
		backchannel = append(backchannel, string(b))
	})
	id3 := sp3.register(t, e, admin, map[string]string{"saml.encrypt": "false", "saml_single_logout_service_url_post": sp3.srv.URL + "/backchannel"}, nil)
	var rep map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/clients/"+id3, admin, nil, nil), 200).json(&rep)
	if rep["frontchannelLogout"] != true {
		t.Fatalf("SAML clients default to front-channel logout: %v", rep["frontchannelLogout"])
	}
	rep["frontchannelLogout"] = false
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/clients/"+id3, admin, rep, nil), 204)

	browser := newBrowser()
	s1 := sp.login(t, e, browser, "alice", "wonderland")
	sp2.login(t, e, browser, "", "")
	sp3.login(t, e, browser, "", "")

	form, err := sp.mw.ServiceProvider.MakePostLogoutRequest(s1["subject"].(string), "bye")
	if err != nil {
		t.Fatal(err)
	}
	// the IdP first sends the browser to SP 2 with a signed LogoutRequest
	r := e.expect(postForm(t, e, browser, &response{status: 200, body: form}), 200)
	if formAction(t, r.body) != sp2.srv.URL+"/saml/slo" {
		t.Fatalf("not sent to SP 2: %s", r.body)
	}
	lr, err := saml.Parse(mustDecode(t, formField(t, r, "SAMLRequest")))
	if err != nil || lr.Name != "LogoutRequest" || lr.NameID != "alice@example.com" || len(lr.SessionIndexes) != 1 {
		t.Fatalf("logout request to SP 2: %+v %v", lr, err)
	}
	if !lr.HasSignature {
		t.Fatal("logout request not signed")
	}
	mu.Lock()
	if len(backchannel) != 1 || !strings.Contains(backchannel[0], "<samlp:LogoutRequest") {
		t.Fatalf("back-channel logout of SP 3: %v", backchannel)
	}
	mu.Unlock()
	// SP 2 answers, then SP 1 gets its LogoutResponse
	resp2, err := sp2.mw.ServiceProvider.MakeLogoutResponse(e.srv.URL+"/realms/demo/protocol/saml", lr.ID)
	if err != nil {
		t.Fatal(err)
	}
	r = e.expect(postForm(t, e, browser, &response{status: 200, body: resp2.Post(formField(t, r, "RelayState"))}), 200)
	if formAction(t, r.body) != sp.srv.URL+"/saml/slo" || formField(t, r, "RelayState") != "bye" {
		t.Fatalf("not answered to SP 1: %s", r.body)
	}
	if err := sp.mw.ServiceProvider.ValidateLogoutResponseForm(formField(t, r, "SAMLResponse")); err != nil {
		t.Fatalf("logout response: %v", err)
	}
	// the SSO session is gone
	r = e.expect(e.do(browser, "GET", sp.srv.URL+"/hello", "", nil, nil), 302)
	r = e.expect(e.do(browser, "GET", r.header.Get("Location"), "", nil, nil), 200)
	if !strings.Contains(string(r.body), `name="password"`) {
		t.Fatal("still logged in")
	}
}

func TestSAMLLogoutFromOIDCAndAdmin(t *testing.T) {
	e := newEnv(t)
	admin, aliceID := e.setupDemo()
	sp := newTestSP(t, e)
	sp.register(t, e, admin, map[string]string{"saml.encrypt": "false"}, nil)
	browser := newBrowser()
	sp.login(t, e, browser, "alice", "wonderland")

	// RP initiated (OIDC) logout visits the SAML client first
	r := e.expect(e.do(browser, "GET", "/realms/demo/protocol/openid-connect/auth?"+url.Values{"client_id": {"web"}, "response_type": {"code"},
		"scope": {"openid"}, "redirect_uri": {"http://app.test/cb"}}.Encode(), "", nil, nil), 302)
	tk := e.exchangeCode(codeOf(t, r))
	r = e.expect(e.do(browser, "GET", "/realms/demo/protocol/openid-connect/logout?"+url.Values{"id_token_hint": {tk.IDToken},
		"post_logout_redirect_uri": {"http://app.test/cb"}, "state": {"s1"}}.Encode(), "", nil, nil), 200)
	if formAction(t, r.body) != sp.srv.URL+"/saml/slo" {
		t.Fatalf("SAML client not logged out: %s", r.body)
	}
	lr, err := saml.Parse(mustDecode(t, formField(t, r, "SAMLRequest")))
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := sp.mw.ServiceProvider.MakeLogoutResponse(e.srv.URL+"/realms/demo/protocol/saml", lr.ID)
	r = e.expect(postForm(t, e, browser, &response{status: 200, body: resp.Post(formField(t, r, "RelayState"))}), 302)
	if loc := r.header.Get("Location"); loc != "http://app.test/cb?state=s1" {
		t.Fatalf("final redirect: %s", loc)
	}

	// an administrator logout reaches back-channel clients
	var got []string
	var mu sync.Mutex
	sp.srv.Config.Handler.(*http.ServeMux).HandleFunc("/bc", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, r.Header.Get("Content-Type"))
	})
	id := clientUUID(e, admin, sp.srv.URL+"/saml/metadata")
	var rep map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/clients/"+id, admin, nil, nil), 200).json(&rep)
	rep["frontchannelLogout"] = false
	rep["attributes"].(map[string]any)["saml_single_logout_service_url_soap"] = sp.srv.URL + "/bc"
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/clients/"+id, admin, rep, nil), 204)
	sp.login(t, e, newBrowser(), "alice", "wonderland")
	e.expect(e.do(nil, "POST", "/admin/realms/demo/users/"+aliceID+"/logout", admin, nil, nil), 204)
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || !strings.HasPrefix(got[0], "text/xml") {
		t.Fatalf("SOAP back-channel logout: %v", got)
	}
}

func TestSAMLIdPInitiatedAndPassive(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	sp := newTestSP(t, e)
	sp.mw.ServiceProvider.AllowIDPInitiated = true
	sp.register(t, e, admin, map[string]string{"saml.encrypt": "false", "saml_idp_initiated_sso_url_name": "sp-app"}, nil)
	browser := newBrowser()
	r := e.expect(e.do(browser, "GET", "/realms/demo/protocol/saml/clients/sp-app", "", nil, nil), 200)
	r = e.expect(e.do(browser, "POST", formAction(t, r.body), "", nil, url.Values{"username": {"alice"}, "password": {"wonderland"}}), 200)
	resp := mustDecode(t, formField(t, r, "SAMLResponse"))
	if strings.Contains(string(resp), "InResponseTo") {
		t.Fatalf("IdP initiated response answers a request: %s", resp)
	}
	r = e.expect(postForm(t, e, browser, r), 302)

	// IsPassive without a session: NoPassive
	md, _ := samlsp.ParseMetadata(e.expect(e.do(nil, "GET", "/realms/demo/protocol/saml/descriptor", "", nil, nil), 200).body)
	sp.mw.ServiceProvider.IDPMetadata = md
	req, err := sp.mw.ServiceProvider.MakeAuthenticationRequest(e.srv.URL+"/realms/demo/protocol/saml", crewsaml.HTTPRedirectBinding, crewsaml.HTTPPostBinding)
	if err != nil {
		t.Fatal(err)
	}
	passive := true
	req.IsPassive = &passive
	u, err := req.Redirect("", &sp.mw.ServiceProvider)
	if err != nil {
		t.Fatal(err)
	}
	r = e.expect(e.do(newBrowser(), "GET", u.String(), "", nil, nil), 200)
	if b := string(mustDecode(t, formField(t, r, "SAMLResponse"))); !strings.Contains(b, saml.StatusNoPassive) {
		t.Fatalf("passive response: %s", b)
	}
}

func TestSAMLDescriptorAndInstallation(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	r := e.expect(e.do(nil, "GET", "/realms/demo/protocol/saml/descriptor", "", nil, nil), 200)
	if ct := r.header.Get("Content-Type"); !strings.HasPrefix(ct, "application/xml") {
		t.Fatalf("content type %s", ct)
	}
	md, err := samlsp.ParseMetadata(r.body)
	if err != nil || md.EntityID != e.srv.URL+"/realms/demo" || len(md.IDPSSODescriptors[0].KeyDescriptors) == 0 {
		t.Fatalf("descriptor: %v %s", err, r.body)
	}
	id := idFromLocation(t, e.expect(e.do(nil, "POST", "/admin/realms/demo/clients", admin, map[string]any{
		"clientId": "urn:sp", "protocol": "saml", "attributes": map[string]string{"saml_assertion_consumer_url_post": "https://sp/acs"}}, nil), 201))
	var rep map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/clients/"+id, admin, nil, nil), 200).json(&rep)
	a := rep["attributes"].(map[string]any)
	if a["saml.signing.certificate"] == "" || a["saml.server.signature"] != "true" || a["saml_name_id_format"] != "username" ||
		!slices.Equal(strs(rep["defaultClientScopes"]), []string{"role_list"}) || rep["frontchannelLogout"] != true {
		t.Fatalf("SAML client defaults: %v", rep)
	}
	r = e.expect(e.do(nil, "GET", "/admin/realms/demo/clients/"+id+"/installation/providers/saml-sp-descriptor", admin, nil, nil), 200)
	if !strings.Contains(string(r.body), `entityID="urn:sp"`) || !strings.Contains(string(r.body), `Location="https://sp/acs"`) {
		t.Fatalf("SP descriptor: %s", r.body)
	}
	r = e.expect(e.do(nil, "GET", "/admin/realms/demo/clients/"+clientUUID(e, admin, "web")+"/installation/providers/keycloak-oidc-keycloak-json", admin, nil, nil), 200)
	var kj map[string]any
	r.json(&kj)
	if kj["resource"] != "web" || kj["realm"] != "demo" {
		t.Fatalf("keycloak.json: %s", r.body)
	}
	// OIDC clients keep their OIDC scopes
	e.expect(e.do(nil, "GET", "/admin/realms/demo/clients/"+clientUUID(e, admin, "web"), admin, nil, nil), 200).json(&rep)
	if slices.Contains(strs(rep["defaultClientScopes"]), "role_list") {
		t.Fatalf("OIDC client got SAML scopes: %v", rep["defaultClientScopes"])
	}
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

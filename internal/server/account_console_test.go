package server

import (
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestLocales(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	page := e.expect(e.do(nil, "GET", demoAuth+"&ui_locales=vi", "", nil, nil), 200)
	if !strings.Contains(string(page.body), "Sign in to your account") {
		t.Fatal("i18n disabled: the default locale must be used")
	}
	e.putRealm(admin, map[string]any{"internationalizationEnabled": true, "supportedLocales": []string{"en", "vi"}, "defaultLocale": "en"})
	page = e.expect(e.do(nil, "GET", demoAuth+"&ui_locales=vi", "", nil, nil), 200)
	if !strings.Contains(string(page.body), "Đăng nhập vào tài khoản của bạn") || !strings.Contains(string(page.body), `lang="vi"`) {
		t.Fatalf("expected Vietnamese: %s", page.body)
	}
	if !strings.Contains(string(page.body), "kc_locale=en") {
		t.Fatal("no language selector")
	}
	req, _ := http.NewRequest("GET", e.srv.URL+demoAuth, nil)
	req.Header.Set("Accept-Language", "vi-VN,vi;q=0.9,en;q=0.5")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.Header.Get("Content-Language") != "vi" {
		t.Fatalf("Accept-Language ignored: %s", resp.Header.Get("Content-Language"))
	}
	// kc_locale is remembered in a cookie
	browser := newBrowser()
	e.expect(e.do(browser, "GET", demoAuth+"&kc_locale=vi", "", nil, nil), 200)
	page = e.expect(e.do(browser, "GET", demoAuth, "", nil, nil), 200)
	r := e.do(browser, "POST", formAction(t, page.body), "", nil, url.Values{"username": {"alice"}, "password": {"wrong"}})
	if !strings.Contains(string(r.body), "Tên đăng nhập hoặc mật khẩu không đúng.") {
		t.Fatalf("error not translated: %s", r.body)
	}
	// unsupported locales fall back to the default
	page = e.expect(e.do(nil, "GET", demoAuth+"&ui_locales=xx", "", nil, nil), 200)
	if !strings.Contains(string(page.body), "Sign in to your account") {
		t.Fatal("fallback to the default locale failed")
	}
}

func TestCustomTheme(t *testing.T) {
	dir := t.TempDir()
	write := func(p, content string) {
		full := filepath.Join(dir, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("acme/login/theme.properties", "parent=keycloak\nstyles=css/acme.css\n")
	write("acme/login/messages/messages_en.properties", "doLogIn=Let me in\nloginAccountTitle=Welcome to {0}\n")
	write("acme/login/resources/css/acme.css", "body{background:hotpink}")
	write("acme/login/login-otp.html", `{{template "header" .}}<p id="acme-otp">ACME OTP</p>{{template "footer" .}}`)
	write("acme/email/messages/messages_en.properties", "passwordResetSubject=ACME password reset\n")
	e := newEnvWith(t, func(c *Config) { c.ThemesDir = dir })
	admin, _ := e.setupDemo()
	e.putRealm(admin, map[string]any{"loginTheme": "acme", "emailTheme": "acme"})
	page := e.expect(e.do(nil, "GET", demoAuth, "", nil, nil), 200)
	body := string(page.body)
	if !strings.Contains(body, "Let me in") || !strings.Contains(body, "/resources/acme/login/css/acme.css") {
		t.Fatalf("theme not applied: %s", body)
	}
	if !strings.Contains(body, "Password") {
		t.Fatal("messages must fall back to the parent theme")
	}
	css := e.expect(e.do(nil, "GET", "/resources/acme/login/css/acme.css", "", nil, nil), 200)
	if string(css.body) != "body{background:hotpink}" || !strings.HasPrefix(css.header.Get("Content-Type"), "text/css") {
		t.Fatalf("resource = %q %s", css.body, css.header.Get("Content-Type"))
	}
	e.expect(e.do(nil, "GET", "/resources/acme/login/../../../etc/passwd", "", nil, nil), 404)

	mail := startSMTP(t)
	e.putRealm(admin, map[string]any{"resetPasswordAllowed": true, "smtpServer": mail.settings()})
	browser := newBrowser()
	page = e.expect(e.do(browser, "GET", demoAuth, "", nil, nil), 200)
	reset := regexp.MustCompile(`href="([^"]+reset-credentials[^"]+)"`).FindSubmatch(page.body)
	page = e.expect(e.do(browser, "GET", strings.ReplaceAll(string(reset[1]), "&amp;", "&"), "", nil, nil), 200)
	e.expect(e.do(browser, "POST", formAction(t, page.body), "", nil, url.Values{"username": {"alice"}}), 200)
	if !strings.Contains(mail.last(t), "Subject: ACME password reset") || !strings.Contains(mail.last(t), "This link and code will expire within 5 minutes") {
		t.Fatalf("email theme not applied: %s", mail.last(t))
	}
}

func TestVietnameseEmail(t *testing.T) {
	e := newEnv(t)
	admin, aliceID := e.setupDemo()
	mail := startSMTP(t)
	e.putRealm(admin, map[string]any{"internationalizationEnabled": true, "supportedLocales": []string{"en", "vi"}, "smtpServer": mail.settings()})
	var profile map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users/profile", admin, nil, nil), 200).json(&profile)
	profile["attributes"] = append(profile["attributes"].([]any), map[string]any{"name": "locale",
		"permissions": map[string]any{"view": []string{"admin", "user"}, "edit": []string{"admin", "user"}}})
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/users/profile", admin, profile, nil), 200)
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/users/"+aliceID, admin, map[string]any{"attributes": map[string][]string{"locale": {"vi"}}}, nil), 204)
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/users/"+aliceID+"/execute-actions-email", admin, []string{"UPDATE_PASSWORD"}, nil), 204)
	msg := mail.last(t)
	subject := regexp.MustCompile(`(?m)^Subject: (.*)\r?$`).FindStringSubmatch(msg)
	decoded, _ := new(mime.WordDecoder).DecodeHeader(strings.TrimSpace(subject[1]))
	if decoded != "Cập nhật tài khoản của bạn" || !strings.Contains(msg, "Cập nhật mật khẩu") || !strings.Contains(msg, "12 giờ") {
		t.Fatalf("expected a Vietnamese email (subject %q): %s", decoded, msg)
	}
}

var stateCheckerRe = regexp.MustCompile(`name="stateChecker" value="([^"]+)"`)

func TestAccountConsole(t *testing.T) {
	e := newEnv(t)
	e.setupDemo()
	browser := newBrowser()
	const acc = "/realms/demo/account/"
	r := e.expect(e.do(browser, "GET", acc, "", nil, nil), 302)
	loginURL := r.header.Get("Location")
	if !strings.Contains(loginURL, "client_id=account") {
		t.Fatalf("expected the account login, got %s", loginURL)
	}
	page := e.expect(e.do(browser, "GET", loginURL, "", nil, nil), 200)
	r = e.expect(e.do(browser, "POST", formAction(t, page.body), "", nil, url.Values{"username": {"alice"}, "password": {"wonderland"}}), 302)
	r = e.expect(e.do(browser, "GET", r.header.Get("Location"), "", nil, nil), 302) // drops ?code=
	page = e.expect(e.do(browser, "GET", r.header.Get("Location"), "", nil, nil), 200)
	body := string(page.body)
	if !strings.Contains(body, `value="alice"`) || !strings.Contains(body, "Personal info") {
		t.Fatalf("personal info page: %s", body)
	}
	state := string(stateCheckerRe.FindSubmatch(page.body)[1])

	// forms need the state checker
	e.expect(e.do(browser, "POST", acc, "", nil, url.Values{"firstName": {"Al"}}), 400)
	r = e.expect(e.do(browser, "POST", acc, "", nil, url.Values{"stateChecker": {state}, "email": {"alice@example.com"}, "firstName": {"Alicia"}, "lastName": {"L"}}), 303)
	page = e.expect(e.do(browser, "GET", r.header.Get("Location"), "", nil, nil), 200)
	if !strings.Contains(string(page.body), `value="Alicia"`) || !strings.Contains(string(page.body), "Your account has been updated.") {
		t.Fatalf("update not shown: %s", page.body)
	}
	page = e.expect(e.do(browser, "POST", acc, "", nil, url.Values{"stateChecker": {state}, "email": {"bad"}, "firstName": {"A"}, "lastName": {"L"}}), 400)
	if !strings.Contains(string(page.body), "Invalid email address.") {
		t.Fatalf("validation error not shown: %s", page.body)
	}

	page = e.expect(e.do(browser, "GET", acc+"security", "", nil, nil), 200)
	setup := regexp.MustCompile(`href="([^"]+kc_action=CONFIGURE_TOTP[^"]*)"`).FindSubmatch(page.body)
	if setup == nil {
		t.Fatalf("no OTP setup link: %s", page.body)
	}
	// application initiated action: the SSO session goes straight to the setup page
	page = e.expect(e.do(browser, "GET", strings.ReplaceAll(string(setup[1]), "&amp;", "&"), "", nil, nil), 200)
	if !strings.Contains(string(page.body), "kc-totp-secret-key") {
		t.Fatalf("expected the OTP setup page: %s", page.body)
	}
	// a second session in another browser, then sign out the others
	other := newBrowser()
	codeOf(t, e.login(other, "alice", "wonderland"))
	page = e.expect(e.do(browser, "GET", acc+"device-activity", "", nil, nil), 200)
	if strings.Count(string(page.body), `name="session"`) != 2 || !strings.Contains(string(page.body), "Current session") {
		t.Fatalf("sessions page: %s", page.body)
	}
	e.expect(e.do(browser, "POST", acc+"device-activity/sign-out", "", nil, url.Values{"stateChecker": {state}}), 303)
	page = e.expect(e.do(browser, "GET", acc+"device-activity", "", nil, nil), 200)
	if strings.Count(string(page.body), `name="session"`) != 1 {
		t.Fatalf("other sessions not signed out: %s", page.body)
	}
	e.expect(e.do(other, "GET", acc, "", nil, nil), 302) // signed out
	page = e.expect(e.do(browser, "GET", acc+"applications", "", nil, nil), 200)
	if !strings.Contains(string(page.body), "account") {
		t.Fatalf("applications: %s", page.body)
	}
	e.expect(e.do(browser, "GET", acc+"groups", "", nil, nil), 403) // no view-groups role
}

func TestAccountAPI(t *testing.T) {
	e := newEnv(t)
	admin, aliceID := e.setupDemo()
	tok, r := e.passwordGrant("demo", "web", "web-secret", "alice", "wonderland")
	e.expect(r, 200)
	const acc = "/realms/demo/account"
	get := func(path string) *response {
		req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
		req.Header.Set("Accept", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b := new(strings.Builder)
		buf := make([]byte, 4096)
		for {
			n, err := resp.Body.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				break
			}
		}
		return &response{status: resp.StatusCode, header: resp.Header, body: []byte(b.String())}
	}
	var me map[string]any
	e.expect(get(acc+"?userProfileMetadata=true"), 200).json(&me)
	if me["username"] != "alice" || me["id"] != aliceID || me["userProfileMetadata"] == nil {
		t.Fatalf("account = %v", me)
	}
	e.expect(e.do(nil, "POST", acc, tok.AccessToken, map[string]any{"email": "alice@example.com", "firstName": "Al", "lastName": "L"}, nil), 204)
	var body map[string]any
	e.expect(e.do(nil, "POST", acc, tok.AccessToken, map[string]any{"email": "nope", "firstName": "Al", "lastName": "L"}, nil), 400).json(&body)
	if body["errorMessage"] != "error-invalid-email" {
		t.Fatalf("error = %v", body)
	}
	var sessions []map[string]any
	e.expect(get(acc+"/sessions"), 200).json(&sessions)
	if len(sessions) != 1 || sessions[0]["current"] != true {
		t.Fatalf("sessions = %v", sessions)
	}
	var creds []map[string]any
	e.expect(get(acc+"/credentials"), 200).json(&creds)
	if len(creds) != 4 || creds[0]["type"] != "password" || len(creds[0]["userCredentialMetadatas"].([]any)) != 1 {
		t.Fatalf("credentials = %v", creds)
	}
	var apps []map[string]any
	e.expect(get(acc+"/applications"), 200).json(&apps)
	if len(apps) != 1 || apps[0]["clientId"] != "web" || apps[0]["inUse"] != true {
		t.Fatalf("applications = %v", apps)
	}
	e.expect(get(acc+"/groups"), 403)
	e.expect(e.do(nil, "DELETE", acc+"/sessions?current=true", tok.AccessToken, nil, nil), 204)
	e.expect(get(acc), 401) // the token's session is gone

	// users without account roles are refused
	e.expect(e.do(nil, "POST", "/admin/realms/demo/users", admin, map[string]any{"username": "norole", "email": "norole@example.com",
		"firstName": "N", "lastName": "R", "enabled": true, "credentials": []any{map[string]any{"value": "pw"}}}, nil), 201)
	var users []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users?username=norole&exact=true", admin, nil, nil), 200).json(&users)
	var def map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/roles/default-roles-demo", admin, nil, nil), 200).json(&def)
	e.expect(e.do(nil, "DELETE", "/admin/realms/demo/users/"+users[0]["id"].(string)+"/role-mappings/realm", admin, []any{def}, nil), 204)
	tok, r = e.passwordGrant("demo", "web", "web-secret", "norole", "pw")
	e.expect(r, 200)
	e.expect(get(acc), 403)
}

package server

import (
	"encoding/base32"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ducnt114/gocloak/internal/otp"
)

const demoAuth = "/realms/demo/protocol/openid-connect/auth?client_id=web&response_type=code&redirect_uri=http%3A%2F%2Fapp.test%2Fcb"

// login opens the login page in browser and submits the credentials,
// returning the response to the form post.
func (e *env) login(browser *http.Client, user, pass string) *response {
	e.t.Helper()
	page := e.expect(e.do(browser, "GET", demoAuth, "", nil, nil), 200)
	return e.do(browser, "POST", formAction(e.t, page.body), "", nil, url.Values{"username": {user}, "password": {pass}})
}

// codeOf asserts a redirect back to the client with a code.
func codeOf(t *testing.T, r *response) string {
	t.Helper()
	if r.status != 302 {
		t.Fatalf("expected redirect to the client, got %d: %s", r.status, r.body)
	}
	loc, _ := url.Parse(r.header.Get("Location"))
	if loc.Query().Get("code") == "" {
		t.Fatalf("no code in %s", loc)
	}
	return loc.Query().Get("code")
}

func TestUserProfileAdmin(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	const R = "/admin/realms/demo"
	var body map[string]any
	e.expect(e.do(nil, "POST", R+"/users", admin, map[string]any{"username": "bademail", "email": "nope", "enabled": true}, nil), 400).json(&body)
	if body["field"] != "email" || body["errorMessage"] != "error-invalid-email" {
		t.Fatalf("single error = %v", body)
	}
	e.expect(e.do(nil, "POST", R+"/users", admin, map[string]any{"username": "ab", "email": "nope"}, nil), 400).json(&body)
	if errs, _ := body["errors"].([]any); len(errs) != 2 {
		t.Fatalf("multiple errors = %v", body)
	}
	// admins may create users without email or names
	e.expect(e.do(nil, "POST", R+"/users", admin, map[string]any{"username": "minimal", "enabled": true}, nil), 201)

	var profile map[string]any
	e.expect(e.do(nil, "GET", R+"/users/profile", admin, nil, nil), 200).json(&profile)
	attrs := profile["attributes"].([]any)
	profile["attributes"] = append(attrs, map[string]any{"name": "phone", "required": map[string]any{"roles": []string{"admin"}},
		"permissions": map[string]any{"view": []string{"admin", "user"}, "edit": []string{"admin", "user"}},
		"validations": map[string]any{"pattern": map[string]any{"pattern": `^\+[0-9]+$`, "error-message": "bad phone"}}})
	e.expect(e.do(nil, "PUT", R+"/users/profile", admin, profile, nil), 200)
	e.expect(e.do(nil, "POST", R+"/users", admin, map[string]any{"username": "nophone"}, nil), 400).json(&body)
	if body["errorMessage"] != "error-user-attribute-required" {
		t.Fatalf("required phone = %v", body)
	}
	e.expect(e.do(nil, "POST", R+"/users", admin, map[string]any{"username": "badphone", "attributes": map[string][]string{"phone": {"123"}}}, nil), 400).json(&body)
	if body["errorMessage"] != "bad phone" {
		t.Fatalf("pattern error = %v", body)
	}
	e.expect(e.do(nil, "POST", R+"/users", admin, map[string]any{"username": "goodphone", "attributes": map[string][]string{"phone": {"+84123"}}}, nil), 201)
	var md map[string]any
	e.expect(e.do(nil, "GET", R+"/users/profile/metadata", admin, nil, nil), 200).json(&md)
	if len(md["attributes"].([]any)) != 5 {
		t.Fatalf("metadata = %v", md)
	}
	e.expect(e.do(nil, "PUT", R+"/users/profile", admin, map[string]any{"attributes": []any{map[string]any{"name": "email"}}}, nil), 400)

	// the master realm requires nothing from users
	e.expect(e.do(nil, "GET", "/admin/realms/master/users/profile", admin, nil, nil), 200).json(&profile)
	for _, a := range profile["attributes"].([]any) {
		if a.(map[string]any)["required"] != nil {
			t.Fatalf("master profile requires %v", a)
		}
	}
}

func TestVerifyProfile(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	e.expect(e.do(nil, "POST", "/admin/realms/demo/users", admin, map[string]any{"username": "dave", "enabled": true,
		"credentials": []any{map[string]any{"value": "pw"}}}, nil), 201)
	_, r := e.passwordGrant("demo", "web", "web-secret", "dave", "pw")
	if r.status != 400 || !strings.Contains(string(r.body), "not fully set up") {
		t.Fatalf("expected incomplete profile error, got %d %s", r.status, r.body)
	}
	browser := newBrowser()
	page := e.expect(e.login(browser, "dave", "pw"), 200)
	if !strings.Contains(string(page.body), `name="firstName"`) {
		t.Fatalf("expected the profile form, got %s", page.body)
	}
	page = e.expect(e.do(browser, "POST", formAction(t, page.body), "", nil, url.Values{"email": {"not-an-email"}, "firstName": {"Dave"}, "lastName": {"D"}}), 400)
	if !strings.Contains(string(page.body), "Invalid email address.") {
		t.Fatalf("expected email error: %s", page.body)
	}
	codeOf(t, e.do(browser, "POST", formAction(t, page.body), "", nil, url.Values{"email": {"dave@example.com"}, "firstName": {"Dave"}, "lastName": {"D"}}))
	_, r = e.passwordGrant("demo", "web", "web-secret", "dave", "pw")
	e.expect(r, 200)

	// with VERIFY_PROFILE disabled incomplete profiles may log in
	e.expect(e.do(nil, "POST", "/admin/realms/demo/users", admin, map[string]any{"username": "erin", "enabled": true,
		"credentials": []any{map[string]any{"value": "pw"}}}, nil), 201)
	var ra map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/authentication/required-actions/VERIFY_PROFILE", admin, nil, nil), 200).json(&ra)
	ra["enabled"] = false
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/authentication/required-actions/VERIFY_PROFILE", admin, ra, nil), 204)
	_, r = e.passwordGrant("demo", "web", "web-secret", "erin", "pw")
	e.expect(r, 200)
}

var otpSecretRe = regexp.MustCompile(`id="kc-totp-secret-key">([A-Z2-7 ]+)<`)

func TestOTP(t *testing.T) {
	e := newEnv(t)
	admin, aliceID := e.setupDemo()
	// HOTP keeps the test deterministic: codes depend on a counter, not the clock.
	e.putRealm(admin, map[string]any{"otpPolicyType": "hotp", "otpPolicyLookAheadWindow": 1})
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/users/"+aliceID, admin, map[string]any{"requiredActions": []string{"CONFIGURE_TOTP"}}, nil), 204)

	browser := newBrowser()
	page := e.expect(e.login(browser, "alice", "wonderland"), 200)
	m := otpSecretRe.FindSubmatch(page.body)
	if m == nil || !strings.Contains(string(page.body), "data:image/png;base64,") {
		t.Fatalf("expected the OTP setup page with a QR code: %s", page.body)
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ReplaceAll(string(m[1]), " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	secret := string(raw)
	code := func(counter int) string { return otp.Code(secret, uint64(counter), 6, "HmacSHA1") }
	e.expect(e.do(browser, "POST", formAction(t, page.body), "", nil, url.Values{"totp": {"000000"}}), 400)
	codeOf(t, e.do(browser, "POST", formAction(t, page.body), "", nil, url.Values{"totp": {code(0)}, "userLabel": {"phone"}}))

	var creds []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users/"+aliceID+"/credentials", admin, nil, nil), 200).json(&creds)
	if !slices.ContainsFunc(creds, func(c map[string]any) bool { return c["type"] == "otp" && c["userLabel"] == "phone" }) {
		t.Fatalf("OTP credential missing: %v", creds)
	}

	// The next browser login asks for the code after the password.
	b2 := newBrowser()
	page = e.expect(e.login(b2, "alice", "wonderland"), 200)
	if !strings.Contains(string(page.body), `name="otp"`) {
		t.Fatalf("expected the OTP form: %s", page.body)
	}
	e.expect(e.do(b2, "POST", formAction(t, page.body), "", nil, url.Values{"otp": {"123456"}}), 401)
	codeOf(t, e.do(b2, "POST", formAction(t, page.body), "", nil, url.Values{"otp": {code(1)}}))

	// Direct grants need the code in the "totp" parameter.
	_, r := e.passwordGrant("demo", "web", "web-secret", "alice", "wonderland")
	e.expect(r, 401)
	e.expect(e.do(nil, "POST", "/realms/demo/protocol/openid-connect/token", "", nil, url.Values{
		"grant_type": {"password"}, "client_id": {"web"}, "client_secret": {"web-secret"},
		"username": {"alice"}, "password": {"wonderland"}, "totp": {code(2)}}), 200)
}

func TestTOTPCodeReuse(t *testing.T) {
	e := newEnv(t)
	admin, aliceID := e.setupDemo()
	secret := otp.GenerateSecret()
	sd, cd := otp.Credential(secret, otp.Policy{Type: "totp", Algorithm: "HmacSHA1", Digits: 6, Period: 30})
	e.expect(e.do(nil, "DELETE", "/admin/realms/demo/users/"+aliceID, admin, nil, nil), 204)
	e.expect(e.do(nil, "POST", "/admin/realms/demo/users", admin, map[string]any{"id": aliceID, "username": "alice",
		"email": "alice@example.com", "firstName": "Alice", "lastName": "L", "enabled": true,
		"credentials": []any{map[string]any{"type": "password", "value": "wonderland"},
			map[string]any{"type": "otp", "secretData": sd, "credentialData": cd}}}, nil), 201)
	code := otp.Code(secret, uint64(time.Now().Unix()/30), 6, "HmacSHA1")
	grant := func() int {
		return e.do(nil, "POST", "/realms/demo/protocol/openid-connect/token", "", nil, url.Values{
			"grant_type": {"password"}, "client_id": {"web"}, "client_secret": {"web-secret"},
			"username": {"alice"}, "password": {"wonderland"}, "totp": {code}}).status
	}
	if first, second := grant(), grant(); first != 200 || second != 401 {
		t.Fatalf("code reuse: first %d, second %d", first, second)
	}
}

func TestRegistration(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	e.putRealm(admin, map[string]any{"registrationAllowed": true, "eventsEnabled": true})
	browser := newBrowser()
	page := e.expect(e.do(browser, "GET", demoAuth, "", nil, nil), 200)
	m := regexp.MustCompile(`id="kc-register" href="([^"]+)"`).FindSubmatch(page.body)
	if m == nil {
		t.Fatalf("no register link: %s", page.body)
	}
	page = e.expect(e.do(browser, "GET", strings.ReplaceAll(string(m[1]), "&amp;", "&"), "", nil, nil), 200)
	form := url.Values{"username": {"frank"}, "email": {"frank@example.com"}, "firstName": {"Frank"}, "lastName": {"F"},
		"password": {"secret1"}, "password-confirm": {"other"}}
	page = e.expect(e.do(browser, "POST", formAction(t, page.body), "", nil, form), 400)
	if !strings.Contains(string(page.body), "Password confirmation doesn&#39;t match.") {
		t.Fatalf("expected confirmation error: %s", page.body)
	}
	form.Set("password-confirm", "secret1")
	form.Set("username", "alice")
	page = e.expect(e.do(browser, "POST", formAction(t, page.body), "", nil, form), 400)
	if !strings.Contains(string(page.body), "Username already exists.") {
		t.Fatalf("expected duplicate username error: %s", page.body)
	}
	form.Set("username", "frank")
	codeOf(t, e.do(browser, "POST", formAction(t, page.body), "", nil, form))
	_, r := e.passwordGrant("demo", "web", "web-secret", "frank", "secret1")
	e.expect(r, 200)
	var events []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/events?type=REGISTER", admin, nil, nil), 200).json(&events)
	if len(events) != 1 {
		t.Fatalf("REGISTER events = %v", events)
	}

	// Terms and conditions in the form, through the registrations endpoint.
	var execs []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/authentication/flows/registration/executions", admin, nil, nil), 200).json(&execs)
	for _, ex := range execs {
		if ex["providerId"] == "registration-terms-and-conditions" {
			ex["requirement"] = "REQUIRED"
			e.expect(e.do(nil, "PUT", "/admin/realms/demo/authentication/flows/registration/executions", admin, ex, nil), 204)
		}
	}
	b2 := newBrowser()
	page = e.expect(e.do(b2, "GET", strings.Replace(demoAuth, "/auth?", "/registrations?", 1), "", nil, nil), 200)
	form = url.Values{"username": {"gina"}, "email": {"gina@example.com"}, "firstName": {"Gina"}, "lastName": {"G"},
		"password": {"secret1"}, "password-confirm": {"secret1"}}
	page = e.expect(e.do(b2, "POST", formAction(t, page.body), "", nil, form), 400)
	form.Set("termsAccepted", "on")
	codeOf(t, e.do(b2, "POST", formAction(t, page.body), "", nil, form))
}

func TestResetCredentials(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	mail := startSMTP(t)
	e.putRealm(admin, map[string]any{"resetPasswordAllowed": true, "smtpServer": mail.settings()})
	browser := newBrowser()
	page := e.expect(e.do(browser, "GET", demoAuth, "", nil, nil), 200)
	m := regexp.MustCompile(`href="([^"]+reset-credentials[^"]+)"`).FindSubmatch(page.body)
	if m == nil {
		t.Fatalf("no forgot password link: %s", page.body)
	}
	page = e.expect(e.do(browser, "GET", strings.ReplaceAll(string(m[1]), "&amp;", "&"), "", nil, nil), 200)
	// unknown users get the same answer, without email
	b2 := newBrowser()
	p2 := e.expect(e.do(b2, "GET", demoAuth, "", nil, nil), 200)
	p2 = e.expect(e.do(b2, "GET", strings.ReplaceAll(string(regexp.MustCompile(`href="([^"]+reset-credentials[^"]+)"`).FindSubmatch(p2.body)[1]), "&amp;", "&"), "", nil, nil), 200)
	p2 = e.expect(e.do(b2, "POST", formAction(t, p2.body), "", nil, url.Values{"username": {"nobody"}}), 200)
	if !strings.Contains(string(p2.body), "You should receive an email shortly") || mail.count() != 0 {
		t.Fatalf("unknown user: %s (mails %d)", p2.body, mail.count())
	}

	page = e.expect(e.do(browser, "POST", formAction(t, page.body), "", nil, url.Values{"username": {"alice@example.com"}}), 200)
	if !strings.Contains(string(page.body), "You should receive an email shortly") {
		t.Fatalf("expected email sent page: %s", page.body)
	}
	if msg := mail.last(t); !strings.Contains(msg, "Subject: Reset password") || !strings.Contains(msg, "To: alice@example.com") {
		t.Fatalf("reset email = %s", msg)
	}
	page = e.expect(e.do(browser, "GET", mail.link(t), "", nil, nil), 200)
	if !strings.Contains(string(page.body), "password-new") {
		t.Fatalf("expected the new password form: %s", page.body)
	}
	codeOf(t, e.do(browser, "POST", formAction(t, page.body), "", nil, url.Values{"password-new": {"newpass1"}, "password-confirm": {"newpass1"}}))
	_, r := e.passwordGrant("demo", "web", "web-secret", "alice", "newpass1")
	e.expect(r, 200)
	// the link is single use
	e.expect(e.do(newBrowser(), "GET", mail.link(t), "", nil, nil), 400)
}

func TestVerifyEmailAndExecuteActions(t *testing.T) {
	e := newEnv(t)
	admin, aliceID := e.setupDemo()
	mail := startSMTP(t)
	e.putRealm(admin, map[string]any{"verifyEmail": true, "smtpServer": mail.settings()})

	browser := newBrowser()
	page := e.expect(e.login(browser, "alice", "wonderland"), 200)
	if !strings.Contains(string(page.body), "verify your email") || !strings.Contains(mail.last(t), "Subject: Verify email") {
		t.Fatalf("expected email verification: %s", page.body)
	}
	codeOf(t, e.do(browser, "GET", mail.link(t), "", nil, nil))
	var u map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users/"+aliceID, admin, nil, nil), 200).json(&u)
	if u["emailVerified"] != true {
		t.Fatalf("email not verified: %v", u)
	}

	// Admin requested actions, completed in another browser.
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/users/"+aliceID+"/execute-actions-email?client_id=web&redirect_uri=http%3A%2F%2Fapp.test%2Fcb%2Fdone",
		admin, []string{"UPDATE_PASSWORD"}, nil), 204)
	if !strings.Contains(mail.last(t), "Subject: Update Your Account") {
		t.Fatalf("execute actions email = %s", mail.last(t))
	}
	b2 := newBrowser()
	page = e.expect(e.do(b2, "GET", mail.link(t), "", nil, nil), 200)
	proceed := regexp.MustCompile(`id="kc-info-link" href="([^"]+)"`).FindSubmatch(page.body)
	if proceed == nil {
		t.Fatalf("no proceed link: %s", page.body)
	}
	page = e.expect(e.do(b2, "GET", strings.ReplaceAll(string(proceed[1]), "&amp;", "&"), "", nil, nil), 200)
	r := e.expect(e.do(b2, "POST", formAction(t, page.body), "", nil, url.Values{"password-new": {"changed1"}, "password-confirm": {"changed1"}}), 302)
	if r.header.Get("Location") != "http://app.test/cb/done" {
		t.Fatalf("redirect = %s", r.header.Get("Location"))
	}
	_, gr := e.passwordGrant("demo", "web", "web-secret", "alice", "changed1")
	e.expect(gr, 200)

	// errors
	e.expect(e.do(nil, "POST", "/admin/realms/demo/users", admin, map[string]any{"username": "nomail", "enabled": true}, nil), 201)
	var users []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users?username=nomail&exact=true", admin, nil, nil), 200).json(&users)
	var body map[string]string
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/users/"+users[0]["id"].(string)+"/send-verify-email", admin, nil, nil), 400).json(&body)
	if body["errorMessage"] != "User email missing" {
		t.Fatalf("error = %v", body)
	}
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/users/"+aliceID+"/execute-actions-email?redirect_uri=http%3A%2F%2Fevil.test", admin, []string{"UPDATE_PASSWORD"}, nil), 400)
}

func TestSMTPConnectionTest(t *testing.T) {
	e := newEnv(t)
	admin := e.adminToken()
	mail := startSMTP(t)
	var body map[string]string
	e.expect(e.do(nil, "POST", "/admin/realms/master/testSMTPConnection", admin, mail.settings(), nil), 500).json(&body)
	if body["error"] != "Logged in user does not have an e-mail." {
		t.Fatalf("error = %v", body)
	}
	var users []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/master/users?username=admin&exact=true", admin, nil, nil), 200).json(&users)
	e.expect(e.do(nil, "PUT", "/admin/realms/master/users/"+users[0]["id"].(string), admin, map[string]any{"email": "admin@example.com"}, nil), 204)
	e.expect(e.do(nil, "POST", "/admin/realms/master/testSMTPConnection", admin, mail.settings(), nil), 204)
	if !strings.Contains(mail.last(t), "SMTP test message") {
		t.Fatalf("test email = %s", mail.last(t))
	}
	e.expect(e.do(nil, "POST", "/admin/realms/master/testSMTPConnection", admin, map[string]string{"host": "127.0.0.1", "port": "1", "from": "a@b.test"}, nil), 500).json(&body)
	if body["errorMessage"] != "Failed to send email" {
		t.Fatalf("error = %v", body)
	}
}

func TestCustomFlows(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	const A = "/admin/realms/demo/authentication"
	var body map[string]string
	e.expect(e.do(nil, "POST", A+"/flows/browser/executions/execution", admin, map[string]string{"provider": "auth-otp-form"}, nil), 400).json(&body)
	if body["error"] != "It is illegal to add execution to a built in flow" {
		t.Fatalf("built-in edit = %v", body)
	}
	flowID := idFromLocation(t, e.expect(e.do(nil, "POST", A+"/flows", admin, map[string]any{"alias": "two-step", "providerId": "basic-flow", "topLevel": true}, nil), 201))
	e.expect(e.do(nil, "POST", A+"/flows/two-step/executions/execution", admin, map[string]string{"provider": "auth-username-form"}, nil), 201)
	e.expect(e.do(nil, "POST", A+"/flows/two-step/executions/execution", admin, map[string]string{"provider": "auth-password-form"}, nil), 201)
	e.expect(e.do(nil, "POST", A+"/flows/two-step/executions/flow", admin, map[string]string{"alias": "editors denied", "type": "basic-flow"}, nil), 201)
	e.expect(e.do(nil, "POST", A+"/flows/editors%20denied/executions/execution", admin, map[string]string{"provider": "conditional-user-role"}, nil), 201)
	e.expect(e.do(nil, "POST", A+"/flows/editors%20denied/executions/execution", admin, map[string]string{"provider": "deny-access-authenticator"}, nil), 201)
	var execs []map[string]any
	e.expect(e.do(nil, "GET", A+"/flows/two-step/executions", admin, nil, nil), 200).json(&execs)
	if len(execs) != 5 || execs[3]["level"] != float64(1) {
		t.Fatalf("executions = %v", execs)
	}
	for _, ex := range execs {
		switch ex["providerId"] {
		case "auth-password-form", "conditional-user-role", "deny-access-authenticator":
			ex["requirement"] = "REQUIRED"
		case nil:
			ex["requirement"] = "CONDITIONAL"
		default:
			continue
		}
		e.expect(e.do(nil, "PUT", A+"/flows/two-step/executions", admin, ex, nil), 204)
		if ex["providerId"] == "conditional-user-role" {
			e.expect(e.do(nil, "POST", A+"/executions/"+ex["id"].(string)+"/config", admin,
				map[string]any{"alias": "editors", "config": map[string]string{"condUserRole": "editor"}}, nil), 201)
		}
	}
	web := clientUUID(e, admin, "web")
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/clients/"+web, admin, map[string]any{
		"authenticationFlowBindingOverrides": map[string]string{"browser": flowID}}, nil), 204)

	// bob is not an editor: username page, then password page.
	e.expect(e.do(nil, "POST", "/admin/realms/demo/users", admin, map[string]any{"username": "bob", "email": "bob@example.com",
		"firstName": "Bob", "lastName": "B", "enabled": true, "credentials": []any{map[string]any{"value": "pw"}}}, nil), 201)
	browser := newBrowser()
	page := e.expect(e.do(browser, "GET", demoAuth, "", nil, nil), 200)
	if strings.Contains(string(page.body), `name="password"`) {
		t.Fatal("expected a username-only form")
	}
	page = e.expect(e.do(browser, "POST", formAction(t, page.body), "", nil, url.Values{"username": {"bob"}}), 200)
	if !strings.Contains(string(page.body), `name="password"`) {
		t.Fatalf("expected the password form: %s", page.body)
	}
	codeOf(t, e.do(browser, "POST", formAction(t, page.body), "", nil, url.Values{"password": {"pw"}}))

	// alice is an editor: denied by the conditional sub flow.
	b2 := newBrowser()
	page = e.expect(e.do(b2, "GET", demoAuth, "", nil, nil), 200)
	page = e.expect(e.do(b2, "POST", formAction(t, page.body), "", nil, url.Values{"username": {"alice"}}), 200)
	r := e.do(b2, "POST", formAction(t, page.body), "", nil, url.Values{"password": {"wonderland"}})
	if r.status == 302 || !strings.Contains(string(r.body), "Access denied") {
		t.Fatalf("expected access denied, got %d %s", r.status, r.body)
	}

	// copies of built-in flows can be edited and deleted
	e.expect(e.do(nil, "POST", A+"/flows/browser/copy", admin, map[string]string{"newName": "my browser"}, nil), 201)
	var flows []map[string]any
	e.expect(e.do(nil, "GET", A+"/flows", admin, nil, nil), 200).json(&flows)
	var copyID string
	for _, f := range flows {
		if f["alias"] == "my browser" && f["builtIn"] == false {
			copyID = f["id"].(string)
		}
	}
	if copyID == "" {
		t.Fatalf("copy missing: %v", flows)
	}
	e.expect(e.do(nil, "POST", A+"/flows/my%20browser/executions/execution", admin, map[string]string{"provider": "auth-otp-form"}, nil), 201)
	e.expect(e.do(nil, "DELETE", A+"/flows/"+copyID, admin, nil, nil), 204)
}

func TestRequiredActionsAdmin(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	const A = "/admin/realms/demo/authentication"
	var actions []map[string]any
	e.expect(e.do(nil, "GET", A+"/required-actions", admin, nil, nil), 200).json(&actions)
	if len(actions) != 11 || actions[0]["alias"] != "CONFIGURE_TOTP" {
		t.Fatalf("required actions = %v", actions)
	}
	var unregistered []map[string]string
	e.expect(e.do(nil, "GET", A+"/unregistered-required-actions", admin, nil, nil), 200).json(&unregistered)
	if len(unregistered) != 1 || unregistered[0]["providerId"] != "UPDATE_EMAIL" {
		t.Fatalf("unregistered = %v", unregistered)
	}
	e.expect(e.do(nil, "POST", A+"/register-required-action", admin, map[string]string{"providerId": "UPDATE_EMAIL", "name": "Update Email"}, nil), 204)
	e.expect(e.do(nil, "POST", A+"/required-actions/UPDATE_EMAIL/raise-priority", admin, nil, nil), 204)

	// default actions apply to new users
	var ra map[string]any
	e.expect(e.do(nil, "GET", A+"/required-actions/TERMS_AND_CONDITIONS", admin, nil, nil), 200).json(&ra)
	ra["enabled"], ra["defaultAction"] = true, true
	e.expect(e.do(nil, "PUT", A+"/required-actions/TERMS_AND_CONDITIONS", admin, ra, nil), 204)
	id := idFromLocation(t, e.expect(e.do(nil, "POST", "/admin/realms/demo/users", admin, map[string]any{"username": "henry", "email": "henry@example.com",
		"firstName": "Henry", "lastName": "H", "enabled": true, "credentials": []any{map[string]any{"value": "pw"}}}, nil), 201))
	var u map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users/"+id, admin, nil, nil), 200).json(&u)
	if fmt.Sprint(u["requiredActions"]) != "[TERMS_AND_CONDITIONS]" {
		t.Fatalf("required actions of new user = %v", u["requiredActions"])
	}
	browser := newBrowser()
	page := e.expect(e.login(browser, "henry", "pw"), 200)
	if !strings.Contains(string(page.body), "Terms and Conditions") {
		t.Fatalf("expected terms: %s", page.body)
	}
	codeOf(t, e.do(browser, "POST", formAction(t, page.body), "", nil, url.Values{"accept": {"accept"}}))
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users/"+id, admin, nil, nil), 200).json(&u)
	if len(u["requiredActions"].([]any)) != 0 {
		t.Fatalf("terms still required: %v", u)
	}
}

func TestWebAuthn(t *testing.T) {
	e := newEnv(t)
	admin, aliceID := e.setupDemo()
	const A = "/admin/realms/demo/authentication"
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/users/"+aliceID, admin, map[string]any{"requiredActions": []string{"webauthn-register"}}, nil), 204)
	auth := newSoftAuthenticator(e.srv.URL)
	browser := newBrowser()
	page := e.expect(e.login(browser, "alice", "wonderland"), 200)
	cred := auth.create(t, webauthnOptions(t, page.body))
	codeOf(t, e.do(browser, "POST", formAction(t, page.body), "", nil, url.Values{"credential": {cred}, "authenticatorLabel": {"laptop"}}))

	// a flow with username then security key
	flowID := idFromLocation(t, e.expect(e.do(nil, "POST", A+"/flows", admin, map[string]any{"alias": "key", "providerId": "basic-flow", "topLevel": true}, nil), 201))
	e.expect(e.do(nil, "POST", A+"/flows/key/executions/execution", admin, map[string]string{"provider": "auth-username-form"}, nil), 201)
	e.expect(e.do(nil, "POST", A+"/flows/key/executions/execution", admin, map[string]string{"provider": "webauthn-authenticator"}, nil), 201)
	var execs []map[string]any
	e.expect(e.do(nil, "GET", A+"/flows/key/executions", admin, nil, nil), 200).json(&execs)
	execs[1]["requirement"] = "REQUIRED"
	e.expect(e.do(nil, "PUT", A+"/flows/key/executions", admin, execs[1], nil), 204)
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/clients/"+clientUUID(e, admin, "web"), admin, map[string]any{
		"authenticationFlowBindingOverrides": map[string]string{"browser": flowID}}, nil), 204)

	b2 := newBrowser()
	page = e.expect(e.do(b2, "GET", demoAuth, "", nil, nil), 200)
	page = e.expect(e.do(b2, "POST", formAction(t, page.body), "", nil, url.Values{"username": {"alice"}}), 200)
	options := webauthnOptions(t, page.body)
	// a wrong signature is rejected
	bad := newSoftAuthenticator(e.srv.URL)
	bad.credID, bad.userID = auth.credID, auth.userID
	e.expect(e.do(b2, "POST", formAction(t, page.body), "", nil, url.Values{"credential": {bad.get(t, options)}}), 401)
	page = e.expect(e.do(b2, "GET", demoAuth, "", nil, nil), 200)
	page = e.expect(e.do(b2, "POST", formAction(t, page.body), "", nil, url.Values{"username": {"alice"}}), 200)
	codeOf(t, e.do(b2, "POST", formAction(t, page.body), "", nil, url.Values{"credential": {auth.get(t, webauthnOptions(t, page.body))}}))

	var creds []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users/"+aliceID+"/credentials", admin, nil, nil), 200).json(&creds)
	if !slices.ContainsFunc(creds, func(c map[string]any) bool { return c["type"] == "webauthn" && c["userLabel"] == "laptop" }) {
		t.Fatalf("webauthn credential = %v", creds)
	}
}

func TestRememberMe(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	e.putRealm(admin, map[string]any{"rememberMe": true})
	identity := func(remember bool) *http.Cookie {
		browser := newBrowser()
		page := e.expect(e.do(browser, "GET", demoAuth, "", nil, nil), 200)
		form := url.Values{"username": {"alice"}, "password": {"wonderland"}}
		if remember {
			form.Set("rememberMe", "on")
		}
		r := e.do(browser, "POST", formAction(t, page.body), "", nil, form)
		codeOf(t, r)
		for _, c := range (&http.Response{Header: r.header}).Cookies() {
			if c.Name == "GOCLOAK_IDENTITY" {
				return c
			}
		}
		t.Fatal("no identity cookie")
		return nil
	}
	if c := identity(false); c.MaxAge != 0 {
		t.Fatalf("session cookie expected, got max-age %d", c.MaxAge)
	}
	if c := identity(true); c.MaxAge <= 0 {
		t.Fatalf("persistent cookie expected, got max-age %d", c.MaxAge)
	}
}

func TestAuthenticationExportImport(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	e.expect(e.do(nil, "POST", "/admin/realms/demo/authentication/flows/browser/copy", admin, map[string]string{"newName": "exported"}, nil), 201)
	e.putRealm(admin, map[string]any{"browserFlow": "exported"})
	rep, err := e.app.ExportRealm(t.Context(), "demo")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.AuthenticationFlows) < 8 || len(rep.RequiredActions) != 11 || len(rep.Components["org.gocloak.keys.KeyProvider"]) != 2 {
		t.Fatalf("export: %d flows, %d actions, components %v", len(rep.AuthenticationFlows), len(rep.RequiredActions), rep.Components)
	}
	// Keys are part of the export: tokens survive a migration.
	tok, r := e.passwordGrant("demo", "web", "web-secret", "alice", "wonderland")
	e.expect(r, 200)
	e.expect(e.do(nil, "DELETE", "/admin/realms/demo", admin, nil, nil), 204)
	b, _ := jsonMarshal(rep)
	e.expect(e.do(nil, "POST", "/admin/realms", admin, jsonRaw(b), nil), 201)
	e.expect(e.do(nil, "GET", "/realms/demo/protocol/openid-connect/userinfo", tok.AccessToken, nil, nil), 401) // its session is gone
	var keys map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/keys", admin, nil, nil), 200).json(&keys)
	if !strings.Contains(fmt.Sprint(keys), claimsKid(t, tok.AccessToken)) {
		t.Fatal("imported realm does not have the exported signing key")
	}
	codeOf(t, e.login(newBrowser(), "alice", "wonderland"))

	// unknown required authenticators are refused
	bad := map[string]any{"realm": "badflow", "authenticationFlows": []any{map[string]any{"alias": "browser", "providerId": "basic-flow", "topLevel": true,
		"authenticationExecutions": []any{map[string]any{"authenticator": "auth-x509-client-username-form", "requirement": "REQUIRED", "priority": 10}}}}}
	e.expect(e.do(nil, "POST", "/admin/realms", admin, bad, nil), 400)
}

func TestPasskeyPasswordless(t *testing.T) {
	e := newEnv(t)
	admin, aliceID := e.setupDemo()
	const A = "/admin/realms/demo/authentication"
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/users/"+aliceID, admin, map[string]any{"requiredActions": []string{"webauthn-register-passwordless"}}, nil), 204)
	auth := newSoftAuthenticator(e.srv.URL)
	browser := newBrowser()
	page := e.expect(e.login(browser, "alice", "wonderland"), 200)
	if !strings.Contains(webauthnOptions(t, page.body), `"residentKey":"required"`) {
		t.Fatalf("passkeys must be discoverable: %s", webauthnOptions(t, page.body))
	}
	codeOf(t, e.do(browser, "POST", formAction(t, page.body), "", nil, url.Values{"credential": {auth.create(t, webauthnOptions(t, page.body))}}))

	// A flow with only the passwordless authenticator: no username typed.
	flowID := idFromLocation(t, e.expect(e.do(nil, "POST", A+"/flows", admin, map[string]any{"alias": "passkey", "providerId": "basic-flow", "topLevel": true}, nil), 201))
	e.expect(e.do(nil, "POST", A+"/flows/passkey/executions/execution", admin, map[string]string{"provider": "webauthn-authenticator-passwordless"}, nil), 201)
	var execs []map[string]any
	e.expect(e.do(nil, "GET", A+"/flows/passkey/executions", admin, nil, nil), 200).json(&execs)
	execs[0]["requirement"] = "REQUIRED"
	e.expect(e.do(nil, "PUT", A+"/flows/passkey/executions", admin, execs[0], nil), 204)
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/clients/"+clientUUID(e, admin, "web"), admin, map[string]any{
		"authenticationFlowBindingOverrides": map[string]string{"browser": flowID}}, nil), 204)
	b2 := newBrowser()
	page = e.expect(e.do(b2, "GET", demoAuth, "", nil, nil), 200)
	if strings.Contains(string(page.body), `name="username"`) {
		t.Fatal("passwordless login must not ask for a username")
	}
	code := codeOf(t, e.do(b2, "POST", formAction(t, page.body), "", nil, url.Values{"credential": {auth.get(t, webauthnOptions(t, page.body))}}))
	var tok tokens
	e.expect(e.do(nil, "POST", "/realms/demo/protocol/openid-connect/token", "", nil, url.Values{"grant_type": {"authorization_code"},
		"code": {code}, "redirect_uri": {"http://app.test/cb"}, "client_id": {"web"}, "client_secret": {"web-secret"}}), 200).json(&tok)
	if claims(t, tok.AccessToken).String("sub") != aliceID {
		t.Fatal("passkey logged in the wrong user")
	}
}

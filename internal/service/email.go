package service

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"

	"github.com/ducnt114/gocloak/internal/model"
)

// Email is a message to send.
type Email struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

// ErrNoSMTP is returned when a realm has no SMTP server configured.
var ErrNoSMTP = errors.New("SMTP server not configured")

// SendEmail sends an email with the realm's smtpServer settings (host,
// port, from, fromDisplayName, replyTo, replyToDisplayName, envelopeFrom,
// ssl, starttls, auth, user, password), as Keycloak's email sender does.
func (s *Service) SendEmail(ctx context.Context, realm *model.Realm, e Email) error {
	return SendWith(ctx, realm.Settings.SMTPServer, e)
}

// SendWith sends e with explicit SMTP settings.
func SendWith(ctx context.Context, cfg map[string]string, e Email) error {
	host := cfg["host"]
	if host == "" || cfg["from"] == "" {
		return ErrNoSMTP
	}
	ssl, starttls, auth := cfg["ssl"] == "true", cfg["starttls"] == "true", cfg["auth"] == "true"
	port := cfg["port"]
	if port == "" {
		port = "25"
		if ssl {
			port = "465"
		}
	}
	addr := net.JoinHostPort(host, port)
	d := net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	var err error
	if ssl {
		conn, err = tls.DialWithDialer(&d, "tcp", addr, &tls.Config{ServerName: host})
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("connect to SMTP server: %w", err)
	}
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if starttls {
		if err := c.StartTLS(&tls.Config{ServerName: host}); err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
	}
	if auth {
		if err := c.Auth(plainAuth{cfg["user"], cfg["password"]}); err != nil {
			return fmt.Errorf("SMTP authentication: %w", err)
		}
	}
	envelope := cfg["envelopeFrom"]
	if envelope == "" {
		envelope = cfg["from"]
	}
	if err := c.Mail(envelope); err != nil {
		return err
	}
	if err := c.Rcpt(e.To); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	msg, err := buildMessage(cfg, e)
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// plainAuth is SMTP AUTH PLAIN. Unlike net/smtp's, it does not refuse
// unencrypted connections: the realm administrator chose the settings.
type plainAuth struct{ user, password string }

func (a plainAuth) Start(*smtp.ServerInfo) (string, []byte, error) {
	return "PLAIN", []byte("\x00" + a.user + "\x00" + a.password), nil
}

func (a plainAuth) Next([]byte, bool) ([]byte, error) { return nil, nil }

func address(addr, name string) string {
	if name == "" {
		return addr
	}
	return (&mail.Address{Name: name, Address: addr}).String()
}

func buildMessage(cfg map[string]string, e Email) ([]byte, error) {
	var b bytes.Buffer
	h := func(k, v string) { fmt.Fprintf(&b, "%s: %s\r\n", k, v) }
	h("From", address(cfg["from"], cfg["fromDisplayName"]))
	h("To", e.To)
	if cfg["replyTo"] != "" {
		h("Reply-To", address(cfg["replyTo"], cfg["replyToDisplayName"]))
	}
	h("Subject", mime.QEncoding.Encode("utf-8", e.Subject))
	h("Date", time.Now().Format(time.RFC1123Z))
	h("Message-ID", "<"+RandomToken(16)+"@gocloak>")
	h("MIME-Version", "1.0")
	mw := multipart.NewWriter(&b)
	h("Content-Type", "multipart/alternative; boundary="+mw.Boundary())
	b.WriteString("\r\n")
	for _, part := range []struct{ typ, body string }{{"text/plain", e.Text}, {"text/html", e.HTML}} {
		if part.body == "" {
			continue
		}
		w, err := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {part.typ + "; charset=UTF-8"}, "Content-Transfer-Encoding": {"8bit"}})
		if err != nil {
			return nil, err
		}
		w.Write([]byte(strings.ReplaceAll(part.body, "\n", "\r\n")))
	}
	mw.Close()
	return b.Bytes(), nil
}

// ---------------------------------------------------------------- templates

func realmDisplay(r *model.Realm) string {
	if r.DisplayName != "" {
		return r.DisplayName
	}
	return r.Name
}

func lifespanText(seconds int) string {
	switch {
	case seconds%86400 == 0:
		return plural(seconds/86400, "day")
	case seconds%3600 == 0:
		return plural(seconds/3600, "hour")
	case seconds%60 == 0:
		return plural(seconds/60, "minute")
	}
	return plural(seconds, "second")
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

func htmlEmail(paragraphs []string, link, linkText string) string {
	var b strings.Builder
	b.WriteString("<html><body>")
	for i, p := range paragraphs {
		if i == 1 && link != "" {
			fmt.Fprintf(&b, `<p><a href="%s">%s</a></p>`, html.EscapeString(link), html.EscapeString(linkText))
		}
		fmt.Fprintf(&b, "<p>%s</p>", html.EscapeString(p))
	}
	b.WriteString("</body></html>")
	return b.String()
}

// VerifyEmailMessage is Keycloak's email-verification email.
func VerifyEmailMessage(realm *model.Realm, to, link string, lifespan int) Email {
	name, exp := realmDisplay(realm), lifespanText(lifespan)
	text := fmt.Sprintf("Someone has created a %s account with this email address. If this was you, click the link below to verify your email address\n\n%s\n\nThis link will expire within %s.\n\nIf you didn't create this account, just ignore this message.", name, link, exp)
	return Email{To: to, Subject: "Verify email", Text: text, HTML: htmlEmail([]string{
		fmt.Sprintf("Someone has created a %s account with this email address. If this was you, click the link below to verify your email address", name),
		fmt.Sprintf("This link will expire within %s.", exp),
		"If you didn't create this account, just ignore this message."}, link, "Link to e-mail address verification")}
}

// ResetPasswordMessage is Keycloak's password-reset email.
func ResetPasswordMessage(realm *model.Realm, to, link string, lifespan int) Email {
	name, exp := realmDisplay(realm), lifespanText(lifespan)
	text := fmt.Sprintf("Someone just requested to change your %s account's credentials. If this was you, click on the link below to reset them.\n\n%s\n\nThis link and code will expire within %s.\n\nIf you don't want to reset your credentials, just ignore this message and nothing will be changed.", name, link, exp)
	return Email{To: to, Subject: "Reset password", Text: text, HTML: htmlEmail([]string{
		fmt.Sprintf("Someone just requested to change your %s account's credentials. If this was you, click on the link below to reset them.", name),
		fmt.Sprintf("This link and code will expire within %s.", exp),
		"If you don't want to reset your credentials, just ignore this message and nothing will be changed."}, link, "Link to reset credentials")}
}

// ExecuteActionsMessage is Keycloak's executeActions email.
func ExecuteActionsMessage(realm *model.Realm, to, link string, lifespan int, actions []string) Email {
	name, exp := realmDisplay(realm), lifespanText(lifespan)
	text := fmt.Sprintf("Your administrator has just requested that you update your %s account by performing the following action(s): %s. Click on the link below to start this process.\n\n%s\n\nThis link will expire within %s.\n\nIf you are unaware that your administrator has requested this, just ignore this message and nothing will be changed.",
		name, strings.Join(actions, ", "), link, exp)
	return Email{To: to, Subject: "Update Your Account", Text: text, HTML: htmlEmail([]string{
		fmt.Sprintf("Your administrator has just requested that you update your %s account by performing the following action(s): %s. Click on the link below to start this process.", name, strings.Join(actions, ", ")),
		fmt.Sprintf("This link will expire within %s.", exp),
		"If you are unaware that your administrator has requested this, just ignore this message and nothing will be changed."}, link, "Link to account update")}
}

// TestMessage is Keycloak's SMTP test email.
func TestMessage(realm *model.Realm, to string) Email {
	return Email{To: to, Subject: "[KEYCLOAK] - SMTP test message", Text: "This is a test message", HTML: "<p>This is a test message</p>"}
}

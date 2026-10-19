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
	"github.com/ducnt114/gocloak/internal/theme"
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

// Email kinds, the prefix of their messages in the email theme
// (<kind>Subject, <kind>Body, optionally <kind>BodyHtml).
const (
	EmailVerification = "emailVerification"
	PasswordReset     = "passwordReset"
	ExecuteActions    = "executeActions"
	EmailTest         = "emailTest"
)

func realmDisplay(r *model.Realm) string {
	if r.DisplayName != "" {
		return r.DisplayName
	}
	return r.Name
}

// emailLocale is the user's locale when the realm supports it, else the
// realm's default locale.
func emailLocale(realm *model.Realm, u *model.User) string {
	def := realm.Settings.DefaultLocale
	if def == "" {
		def = "en"
	}
	if !realm.Settings.InternationalizationEnabled || u == nil {
		return def
	}
	if v := u.Attributes["locale"]; len(v) > 0 {
		for _, l := range realm.Settings.SupportedLocales {
			if strings.EqualFold(l, v[0]) {
				return l
			}
		}
	}
	return def
}

// EmailMessage builds an email of the realm's email theme, in the user's
// language. The body messages get Keycloak's arguments: {0} link, {1}
// lifespan in minutes, {2} realm name, {3} lifespan as text, {4} actions.
func (s *Service) EmailMessage(realm *model.Realm, u *model.User, kind, link string, lifespan int, actions []string) (Email, error) {
	th, err := s.Themes.Get(theme.Email, realm.Settings.EmailTheme)
	if err != nil {
		return Email{}, err
	}
	locale := emailLocale(realm, u)
	names := make([]string, len(actions))
	for i, a := range actions {
		names[i] = th.Message(locale, "requiredAction."+a)
	}
	args := []any{link, lifespan / 60, realmDisplay(realm), lifespanText(th, locale, lifespan), strings.Join(names, ", ")}
	e := Email{To: u.Email, Subject: th.Message(locale, kind+"Subject", args...), Text: th.Message(locale, kind+"Body", args...)}
	if th.HasMessage(locale, kind+"BodyHtml") {
		e.HTML = th.Message(locale, kind+"BodyHtml", args...)
	} else {
		e.HTML = textToHTML(e.Text, link, th.Message(locale, kind+"Link"))
	}
	return e, nil
}

func lifespanText(th *theme.Theme, locale string, seconds int) string {
	unit := func(n int, one, many string) string {
		if n == 1 {
			return "1 " + th.Message(locale, "linkExpirationFormatter.timePeriodUnit."+one)
		}
		return fmt.Sprintf("%d %s", n, th.Message(locale, "linkExpirationFormatter.timePeriodUnit."+many))
	}
	switch {
	case seconds%86400 == 0:
		return unit(seconds/86400, "day", "days")
	case seconds%3600 == 0:
		return unit(seconds/3600, "hour", "hours")
	}
	return unit((seconds+59)/60, "minute", "minutes")
}

// textToHTML turns a text body into HTML paragraphs, with the link as an anchor.
func textToHTML(text, link, linkText string) string {
	var b strings.Builder
	b.WriteString("<html><body>")
	for _, p := range strings.Split(text, "\n\n") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if p == link {
			if linkText == "" || linkText == link {
				linkText = link
			}
			fmt.Fprintf(&b, `<p><a href="%s">%s</a></p>`, html.EscapeString(link), html.EscapeString(linkText))
			continue
		}
		fmt.Fprintf(&b, "<p>%s</p>", strings.ReplaceAll(html.EscapeString(p), "\n", "<br>"))
	}
	b.WriteString("</body></html>")
	return b.String()
}

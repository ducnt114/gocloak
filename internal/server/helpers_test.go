package server

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// mailbox is a minimal SMTP server that keeps every message it receives.
type mailbox struct {
	mu   sync.Mutex
	msgs []string
	host string
	port string
}

func startSMTP(t *testing.T) *mailbox {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	m := &mailbox{}
	m.host, m.port, _ = net.SplitHostPort(ln.Addr().String())
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go m.serve(c)
		}
	}()
	return m
}

func (m *mailbox) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	say := func(s string) { c.Write([]byte(s + "\r\n")) }
	say("220 test")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			say("250 test")
		case cmd == "DATA":
			say("354 go ahead")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			m.mu.Lock()
			m.msgs = append(m.msgs, b.String())
			m.mu.Unlock()
			say("250 ok")
		case cmd == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func (m *mailbox) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.msgs)
}

func (m *mailbox) last(t *testing.T) string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.msgs) == 0 {
		t.Fatal("no email received")
	}
	return m.msgs[len(m.msgs)-1]
}

var actionLinkRe = regexp.MustCompile(`http\S+/login-actions/action-token\?\S+`)

// link returns the action link of the last email.
func (m *mailbox) link(t *testing.T) string {
	t.Helper()
	l := actionLinkRe.FindString(m.last(t))
	if l == "" {
		t.Fatalf("no action link in %s", m.last(t))
	}
	return strings.TrimRight(l, "\r")
}

func (m *mailbox) settings() map[string]string {
	return map[string]string{"host": m.host, "port": m.port, "from": "noreply@example.com", "fromDisplayName": "gocloak"}
}

// softAuthenticator is a software WebAuthn authenticator (ES256, "none"
// attestation) for tests.
type softAuthenticator struct {
	key       *ecdsa.PrivateKey
	credID    []byte
	userID    []byte
	signCount uint32
	origin    string
}

func newSoftAuthenticator(origin string) *softAuthenticator {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 16)
	rand.Read(id)
	return &softAuthenticator{key: k, credID: id, origin: origin}
}

var b64u = base64.RawURLEncoding

type waOptions struct {
	Challenge string `json:"challenge"`
	RPID      string `json:"rpId"`
	RP        struct {
		ID string `json:"id"`
	} `json:"rp"`
	User struct {
		ID string `json:"id"`
	} `json:"user"`
}

func (a *softAuthenticator) clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.origin, "crossOrigin": false})
	return b
}

func (a *softAuthenticator) authData(rpID string, flags byte, attested bool) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := append([]byte{}, h[:]...)
	out = append(out, flags, byte(a.signCount>>24), byte(a.signCount>>16), byte(a.signCount>>8), byte(a.signCount))
	if attested {
		out = append(out, make([]byte, 16)...) // AAGUID
		out = append(out, byte(len(a.credID)>>8), byte(len(a.credID)))
		out = append(out, a.credID...)
		x, y := make([]byte, 32), make([]byte, 32)
		a.key.PublicKey.X.FillBytes(x)
		a.key.PublicKey.Y.FillBytes(y)
		cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
		out = append(out, cose...)
	}
	return out
}

// create answers navigator.credentials.create for the given options JSON.
func (a *softAuthenticator) create(t *testing.T, options string) string {
	t.Helper()
	var o waOptions
	if err := json.Unmarshal([]byte(options), &o); err != nil {
		t.Fatalf("creation options %s: %v", options, err)
	}
	a.userID, _ = b64u.DecodeString(o.User.ID)
	cd := a.clientData("webauthn.create", o.Challenge)
	ao, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": a.authData(o.RP.ID, 0x45, true)})
	b, _ := json.Marshal(map[string]any{"id": b64u.EncodeToString(a.credID), "rawId": b64u.EncodeToString(a.credID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64u.EncodeToString(cd), "attestationObject": b64u.EncodeToString(ao), "transports": []string{"internal"}}})
	return string(b)
}

// get answers navigator.credentials.get for the given options JSON.
func (a *softAuthenticator) get(t *testing.T, options string) string {
	t.Helper()
	var o waOptions
	if err := json.Unmarshal([]byte(options), &o); err != nil {
		t.Fatalf("request options %s: %v", options, err)
	}
	a.signCount++
	cd := a.clientData("webauthn.get", o.Challenge)
	ad := a.authData(o.RPID, 0x05, false)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"id": b64u.EncodeToString(a.credID), "rawId": b64u.EncodeToString(a.credID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64u.EncodeToString(cd), "authenticatorData": b64u.EncodeToString(ad),
			"signature": b64u.EncodeToString(sig), "userHandle": b64u.EncodeToString(a.userID)}})
	return string(b)
}

var webauthnOptionsRe = regexp.MustCompile(`const opts = (\{.*\});`)

func webauthnOptions(t *testing.T, page []byte) string {
	t.Helper()
	m := webauthnOptionsRe.FindSubmatch(page)
	if m == nil {
		t.Fatalf("no WebAuthn options in %s", page)
	}
	return string(m[1])
}

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

// jsonRaw sends pre-encoded JSON as a request body.
type jsonRaw []byte

func (j jsonRaw) MarshalJSON() ([]byte, error) { return j, nil }

func claimsKid(t *testing.T, tok string) string {
	t.Helper()
	h, _ := b64u.DecodeString(strings.Split(tok, ".")[0])
	var hdr struct{ Kid string }
	json.Unmarshal(h, &hdr)
	return hdr.Kid
}

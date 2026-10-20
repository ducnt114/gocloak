// Package saml implements the SAML 2.0 messages of the SAML identity
// provider: reading requests from the HTTP-Redirect and HTTP-POST bindings,
// verifying and creating XML and query string signatures, building
// responses, assertions and logout messages, and encrypting assertions.
//
// XML signatures are handled by goxmldsig; every incoming document is first
// checked with xml-roundtrip-validator, which rejects documents that
// encoding/xml would not reproduce faithfully (a known source of signature
// bypasses).
package saml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/google/uuid"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"
)

// XML namespaces.
const (
	NSProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	NSAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	NSMetadata  = "urn:oasis:names:tc:SAML:2.0:metadata"
	NSDSig      = "http://www.w3.org/2000/09/xmldsig#"
	NSXEnc      = "http://www.w3.org/2001/04/xmlenc#"
	NSSOAP      = "http://schemas.xmlsoap.org/soap/envelope/"
)

// Bindings.
const (
	BindingPOST     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	BindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	BindingSOAP     = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
	BindingArtifact = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
)

// NameID formats.
const (
	NameIDUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	NameIDEmail       = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIDPersistent  = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	NameIDTransient   = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
)

// Status codes.
const (
	StatusSuccess        = "urn:oasis:names:tc:SAML:2.0:status:Success"
	StatusRequester      = "urn:oasis:names:tc:SAML:2.0:status:Requester"
	StatusResponder      = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	StatusAuthnFailed    = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
	StatusNoPassive      = "urn:oasis:names:tc:SAML:2.0:status:NoPassive"
	StatusRequestDenied  = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"
	StatusPartialLogout  = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"
	StatusInvalidNameIDP = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"
)

// Attribute name formats.
const (
	AttrNameFormatBasic       = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
	AttrNameFormatURI         = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
	AttrNameFormatUnspecified = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
)

// maxMessage bounds decoded (and inflated) messages.
const maxMessage = 512 << 10

// ErrInvalid wraps every malformed or unverifiable message.
var ErrInvalid = errors.New("invalid SAML message")

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// NewID returns a message id ("ID_" and a UUID).
func NewID() string { return "ID_" + uuid.NewString() }

// Instant formats a time as SAML does (UTC, millisecond precision).
func Instant(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// ---------------------------------------------------------------- bindings

// Message is a SAML protocol message received through a binding.
type Message struct {
	Binding    string // BindingRedirect or BindingPOST
	Request    bool   // SAMLRequest (true) or SAMLResponse
	XML        []byte
	RelayState string
	// SigAlg and Signature are the query string signature of the redirect
	// binding, over signedOctets.
	SigAlg       string
	Signature    []byte
	signedOctets string
}

// ReadMessage reads the SAMLRequest or SAMLResponse of a request: a GET is
// the HTTP-Redirect binding (deflated), a POST the HTTP-POST binding.
func ReadMessage(r *http.Request) (*Message, error) {
	if r.Method == http.MethodGet {
		return readRedirect(r.URL.RawQuery)
	}
	r.Body = http.MaxBytesReader(nil, r.Body, 2*maxMessage)
	if err := r.ParseForm(); err != nil {
		return nil, invalidf("form: %v", err)
	}
	m := &Message{Binding: BindingPOST, RelayState: r.PostFormValue("RelayState")}
	v := r.PostFormValue("SAMLRequest")
	m.Request = v != ""
	if v == "" {
		v = r.PostFormValue("SAMLResponse")
	}
	if v == "" {
		return nil, invalidf("no SAML message")
	}
	b, err := decodeBase64(v)
	if err != nil {
		return nil, err
	}
	m.XML = b
	return m, nil
}

func readRedirect(rawQuery string) (*Message, error) {
	m := &Message{Binding: BindingRedirect}
	raw := map[string]string{}
	for _, part := range strings.Split(rawQuery, "&") {
		k, v, _ := strings.Cut(part, "=")
		key, err := url.QueryUnescape(k)
		if err != nil {
			continue
		}
		if _, dup := raw[key]; !dup {
			raw[key] = v
		}
	}
	name := "SAMLRequest"
	if _, ok := raw[name]; ok {
		m.Request = true
	} else if _, ok := raw["SAMLResponse"]; ok {
		name = "SAMLResponse"
	} else {
		return nil, invalidf("no SAML message")
	}
	value := func(k string) (string, error) {
		v, err := url.QueryUnescape(raw[k])
		if err != nil {
			return "", invalidf("bad %s", k)
		}
		return v, nil
	}
	enc, err := value(name)
	if err != nil {
		return nil, err
	}
	compressed, err := decodeBase64(enc)
	if err != nil {
		return nil, err
	}
	if m.XML, err = inflate(compressed); err != nil {
		return nil, err
	}
	if m.RelayState, err = value("RelayState"); err != nil {
		return nil, err
	}
	if _, ok := raw["SigAlg"]; ok {
		if m.SigAlg, err = value("SigAlg"); err != nil {
			return nil, err
		}
		sig, err := value("Signature")
		if err != nil {
			return nil, err
		}
		if m.Signature, err = decodeBase64(sig); err != nil {
			return nil, err
		}
		// SAML bindings 3.4.4.1: the signature covers the parameters as
		// they were encoded by the sender.
		octets := name + "=" + raw[name]
		if _, ok := raw["RelayState"]; ok {
			octets += "&RelayState=" + raw["RelayState"]
		}
		m.signedOctets = octets + "&SigAlg=" + raw["SigAlg"]
	}
	return m, nil
}

func decodeBase64(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)
	if len(s) > 2*maxMessage {
		return nil, invalidf("message too large")
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, invalidf("base64: %v", err)
	}
	return b, nil
}

func inflate(b []byte) ([]byte, error) {
	out, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(b)), maxMessage+1))
	if err != nil {
		return nil, invalidf("inflate: %v", err)
	}
	if len(out) > maxMessage {
		return nil, invalidf("message too large")
	}
	return out, nil
}

func deflate(b []byte) []byte {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

// Signed reports whether the message carries a redirect binding signature.
func (m *Message) Signed() bool { return m.SigAlg != "" }

// VerifyQuerySignature checks the redirect binding signature against the
// given certificates.
func (m *Message) VerifyQuerySignature(certs []*x509.Certificate) error {
	if !m.Signed() {
		return invalidf("missing signature")
	}
	hash, ok := queryHashes[m.SigAlg]
	if !ok {
		return invalidf("unsupported signature algorithm %s", m.SigAlg)
	}
	h := hash.New()
	h.Write([]byte(m.signedOctets))
	sum := h.Sum(nil)
	for _, c := range certs {
		if pub, ok := c.PublicKey.(*rsa.PublicKey); ok && rsa.VerifyPKCS1v15(pub, hash, sum, m.Signature) == nil {
			return nil
		}
	}
	return invalidf("invalid signature")
}

var queryHashes = map[string]crypto.Hash{
	dsig.RSASHA1SignatureMethod:   crypto.SHA1,
	dsig.RSASHA256SignatureMethod: crypto.SHA256,
	dsig.RSASHA512SignatureMethod: crypto.SHA512,
}

// RedirectURL encodes a message for the HTTP-Redirect binding, signing the
// query string when signer is not nil.
func RedirectURL(location, param string, xml []byte, relayState string, signer *Signer) (string, error) {
	q := param + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(deflate(xml)))
	if relayState != "" {
		q += "&RelayState=" + url.QueryEscape(relayState)
	}
	if signer != nil {
		q += "&SigAlg=" + url.QueryEscape(signer.Algorithm)
		sig, err := signer.signBytes([]byte(q))
		if err != nil {
			return "", err
		}
		q += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	}
	sep := "?"
	if strings.Contains(location, "?") {
		sep = "&"
	}
	return location + sep + q, nil
}

// ---------------------------------------------------------------- parsing

// Request is a parsed incoming protocol message.
type Request struct {
	Name         string // AuthnRequest, LogoutRequest, LogoutResponse, Response
	ID           string
	IssueInstant string
	Destination  string
	Issuer       string
	HasSignature bool

	// AuthnRequest
	ACSURL          string
	ACSIndex        string
	ProtocolBinding string
	NameIDPolicy    string // requested NameID format
	ForceAuthn      bool
	IsPassive       bool

	// LogoutRequest
	NameID         string
	NameIDFormat   string
	SessionIndexes []string

	// LogoutResponse
	InResponseTo string
	Status       string

	root *etree.Element
}

// Parse parses a protocol message. The document must survive an
// encoding/xml round trip unchanged and use the SAML protocol namespace.
func Parse(raw []byte) (*Request, error) {
	if len(raw) > maxMessage {
		return nil, invalidf("message too large")
	}
	if err := xrv.Validate(bytes.NewReader(raw)); err != nil {
		return nil, invalidf("xml: %v", err)
	}
	doc := etree.NewDocument()
	doc.ReadSettings.Permissive = false
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, invalidf("xml: %v", err)
	}
	root := doc.Root()
	if root == nil {
		return nil, invalidf("empty document")
	}
	if root.NamespaceURI() == NSSOAP && root.Tag == "Envelope" {
		// SOAP binding: the message is the first child of the body
		body := child(root, NSSOAP, "Body")
		if body == nil || len(body.ChildElements()) == 0 {
			return nil, invalidf("empty SOAP body")
		}
		root = body.ChildElements()[0].Copy()
		etree.NewDocument().SetRoot(root)
	}
	return parseRoot(root)
}

func parseRoot(root *etree.Element) (*Request, error) {
	if root.NamespaceURI() != NSProtocol {
		return nil, invalidf("unexpected element %s", root.Tag)
	}
	q := &Request{Name: root.Tag, root: root,
		ID: root.SelectAttrValue("ID", ""), IssueInstant: root.SelectAttrValue("IssueInstant", ""),
		Destination: root.SelectAttrValue("Destination", "")}
	if q.ID == "" {
		return nil, invalidf("missing ID")
	}
	if v := root.SelectAttrValue("Version", ""); v != "2.0" {
		return nil, invalidf("unsupported version %q", v)
	}
	if iss := child(root, NSAssertion, "Issuer"); iss != nil {
		q.Issuer = strings.TrimSpace(iss.Text())
	}
	q.HasSignature = child(root, NSDSig, "Signature") != nil
	switch q.Name {
	case "AuthnRequest":
		q.ACSURL = root.SelectAttrValue("AssertionConsumerServiceURL", "")
		q.ACSIndex = root.SelectAttrValue("AssertionConsumerServiceIndex", "")
		q.ProtocolBinding = root.SelectAttrValue("ProtocolBinding", "")
		q.ForceAuthn = root.SelectAttrValue("ForceAuthn", "") == "true" || root.SelectAttrValue("ForceAuthn", "") == "1"
		q.IsPassive = root.SelectAttrValue("IsPassive", "") == "true" || root.SelectAttrValue("IsPassive", "") == "1"
		if p := child(root, NSProtocol, "NameIDPolicy"); p != nil {
			q.NameIDPolicy = p.SelectAttrValue("Format", "")
		}
	case "LogoutRequest":
		if n := child(root, NSAssertion, "NameID"); n != nil {
			q.NameID = strings.TrimSpace(n.Text())
			q.NameIDFormat = n.SelectAttrValue("Format", "")
		}
		for _, e := range root.ChildElements() {
			if e.NamespaceURI() == NSProtocol && e.Tag == "SessionIndex" {
				q.SessionIndexes = append(q.SessionIndexes, strings.TrimSpace(e.Text()))
			}
		}
	case "LogoutResponse", "Response", "ArtifactResponse":
		q.InResponseTo = root.SelectAttrValue("InResponseTo", "")
		if st := child(root, NSProtocol, "Status"); st != nil {
			if code := child(st, NSProtocol, "StatusCode"); code != nil {
				q.Status = code.SelectAttrValue("Value", "")
			}
		}
	default:
		return nil, invalidf("unsupported message %s", q.Name)
	}
	return q, nil
}

func child(el *etree.Element, ns, tag string) *etree.Element {
	for _, c := range el.ChildElements() {
		if c.Tag == tag && c.NamespaceURI() == ns {
			return c
		}
	}
	return nil
}

// VerifySignature checks the enveloped XML signature of the message against
// the given certificates, and replaces the parsed fields with those of the
// signed content (so that nothing outside the signature is trusted).
func (q *Request) VerifySignature(certs []*x509.Certificate) error {
	el, err := VerifyElement(q.root, certs)
	if err != nil {
		return err
	}
	signed, err := parseRoot(el)
	if err != nil {
		return err
	}
	*q = *signed
	return nil
}

// VerifyElement validates the enveloped signature of el and returns the
// signed element. Certificate validity dates are not enforced: the
// configured certificate is trusted as a key.
func VerifyElement(el *etree.Element, certs []*x509.Certificate) (*etree.Element, error) {
	var lastErr error = invalidf("no certificate")
	for _, c := range certs {
		vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{c}})
		vc.IdAttribute = "ID"
		vc.Clock = dsig.NewFakeClockAt(c.NotBefore.Add(time.Second))
		signed, err := vc.Validate(el)
		if err == nil {
			return signed, nil
		}
		lastErr = invalidf("signature: %v", err)
	}
	return nil, lastErr
}

// ---------------------------------------------------------------- signing

// Signer signs messages with a realm key.
type Signer struct {
	Key       *rsa.PrivateKey
	Cert      *x509.Certificate
	KeyName   string // the key id, shown in ds:KeyName
	Algorithm string // signature method URI
	Canonical string // canonicalization method URI
}

// SignatureAlgorithm maps the saml.signature.algorithm names to
// signature method URIs (RSA_SHA256 by default).
func SignatureAlgorithm(name string) string {
	switch name {
	case "RSA_SHA1":
		return dsig.RSASHA1SignatureMethod
	case "RSA_SHA512":
		return dsig.RSASHA512SignatureMethod
	}
	return dsig.RSASHA256SignatureMethod
}

func (s *Signer) canonicalizer() dsig.Canonicalizer {
	switch s.Canonical {
	case string(dsig.CanonicalXML10ExclusiveWithCommentsAlgorithmId):
		return dsig.MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList("")
	case string(dsig.CanonicalXML10RecAlgorithmId):
		return dsig.MakeC14N10RecCanonicalizer()
	case string(dsig.CanonicalXML10WithCommentsAlgorithmId):
		return dsig.MakeC14N10WithCommentsCanonicalizer()
	}
	return dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
}

// Inclusive reports whether the signer uses inclusive canonicalization,
// whose canonical form of an element includes the namespaces in scope from
// its ancestors.
func (s *Signer) Inclusive() bool {
	return s.Canonical == string(dsig.CanonicalXML10RecAlgorithmId) || s.Canonical == string(dsig.CanonicalXML10WithCommentsAlgorithmId)
}

// Sign adds an enveloped signature to el, placed after its Issuer as the
// SAML schema requires. el must be the root of its document.
func (s *Signer) Sign(el *etree.Element) error {
	ctx, err := dsig.NewSigningContext(s.Key, [][]byte{s.Cert.Raw})
	if err != nil {
		return err
	}
	ctx.IdAttribute = "ID"
	ctx.Prefix = "dsig"
	ctx.Canonicalizer = s.canonicalizer()
	if err := ctx.SetSignatureMethod(s.Algorithm); err != nil {
		return err
	}
	// goxmldsig canonicalizes the element in place (moving or dropping
	// namespace declarations, such as the xs prefix only used in xsi:type
	// values), so the signature is computed on a copy
	sig, err := ctx.ConstructSignature(el.Copy(), true)
	if err != nil {
		return err
	}
	if s.KeyName != "" {
		if ki := sig.FindElement("./KeyInfo"); ki != nil {
			kn := etree.NewElement("dsig:KeyName")
			kn.SetText(s.KeyName)
			ki.InsertChildAt(0, kn)
		}
	}
	at := 0
	for i, t := range el.Child {
		if c, ok := t.(*etree.Element); ok && c.Tag == "Issuer" {
			at = i + 1
			break
		}
	}
	el.InsertChildAt(at, sig)
	return nil
}

func (s *Signer) signBytes(b []byte) ([]byte, error) {
	hash, ok := queryHashes[s.Algorithm]
	if !ok {
		return nil, fmt.Errorf("unsupported signature algorithm %s", s.Algorithm)
	}
	h := hash.New()
	h.Write(b)
	return rsa.SignPKCS1v15(rand.Reader, s.Key, hash, h.Sum(nil))
}

// Serialize writes el as a document without an XML declaration.
func Serialize(el *etree.Element) ([]byte, error) {
	doc := etree.NewDocument()
	doc.SetRoot(el)
	return doc.WriteToBytes()
}

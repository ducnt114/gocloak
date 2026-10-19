package saml

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // xmlenc digest and MGF1 algorithms
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/beevik/etree"
)

// Attribute is a SAML attribute of an assertion.
type Attribute struct {
	Name         string
	NameFormat   string
	FriendlyName string
	Values       []string
}

// Assertion is the content of an assertion issued to a service provider.
type Assertion struct {
	ID           string
	Issuer       string
	IssueInstant time.Time

	NameID       string
	NameIDFormat string

	InResponseTo        string
	Recipient           string
	SubjectNotOnOrAfter time.Time

	NotBefore    time.Time
	NotOnOrAfter time.Time
	Audiences    []string

	AuthnStatement      bool
	AuthnInstant        time.Time
	SessionIndex        string
	SessionNotOnOrAfter time.Time

	Attributes []Attribute
}

func newElement(tag string, attrs ...string) *etree.Element {
	el := etree.NewElement(tag)
	for i := 0; i+1 < len(attrs); i += 2 {
		el.CreateAttr(attrs[i], attrs[i+1])
	}
	return el
}

func textElement(parent *etree.Element, tag, text string, attrs ...string) *etree.Element {
	el := newElement(tag, attrs...)
	el.SetText(text)
	parent.AddChild(el)
	return el
}

// Element builds the saml:Assertion element. It declares its namespaces so
// that it can be signed and encrypted on its own.
func (a *Assertion) Element() *etree.Element {
	el := newElement("saml:Assertion", "xmlns", NSAssertion, "xmlns:saml", NSAssertion,
		"ID", a.ID, "IssueInstant", Instant(a.IssueInstant), "Version", "2.0")
	textElement(el, "saml:Issuer", a.Issuer)

	subject := el.CreateElement("saml:Subject")
	textElement(subject, "saml:NameID", a.NameID, "Format", a.NameIDFormat)
	sc := subject.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	scd := sc.CreateElement("saml:SubjectConfirmationData")
	if a.InResponseTo != "" {
		scd.CreateAttr("InResponseTo", a.InResponseTo)
	}
	scd.CreateAttr("NotOnOrAfter", Instant(a.SubjectNotOnOrAfter))
	if a.Recipient != "" {
		scd.CreateAttr("Recipient", a.Recipient)
	}

	cond := el.CreateElement("saml:Conditions")
	cond.CreateAttr("NotBefore", Instant(a.NotBefore))
	cond.CreateAttr("NotOnOrAfter", Instant(a.NotOnOrAfter))
	if len(a.Audiences) > 0 {
		ar := cond.CreateElement("saml:AudienceRestriction")
		for _, aud := range a.Audiences {
			textElement(ar, "saml:Audience", aud)
		}
	}

	if a.AuthnStatement {
		as := el.CreateElement("saml:AuthnStatement")
		as.CreateAttr("AuthnInstant", Instant(a.AuthnInstant))
		as.CreateAttr("SessionIndex", a.SessionIndex)
		if !a.SessionNotOnOrAfter.IsZero() {
			as.CreateAttr("SessionNotOnOrAfter", Instant(a.SessionNotOnOrAfter))
		}
		ac := as.CreateElement("saml:AuthnContext")
		textElement(ac, "saml:AuthnContextClassRef", "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified")
	}

	if len(a.Attributes) > 0 {
		st := el.CreateElement("saml:AttributeStatement")
		for _, attr := range a.Attributes {
			ae := st.CreateElement("saml:Attribute")
			if attr.FriendlyName != "" {
				ae.CreateAttr("FriendlyName", attr.FriendlyName)
			}
			ae.CreateAttr("Name", attr.Name)
			ae.CreateAttr("NameFormat", attr.NameFormat)
			for _, v := range attr.Values {
				textElement(ae, "saml:AttributeValue", v, "xmlns:xs", "http://www.w3.org/2001/XMLSchema",
					"xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance", "xsi:type", "xs:string")
			}
		}
	}
	return el
}

// Response is a samlp:Response.
type Response struct {
	ID           string
	InResponseTo string
	Destination  string
	Issuer       string
	IssueInstant time.Time
	Status       string // top level status code (Success by default)
	SubStatus    string
	// Assertion is the (signed or encrypted) assertion element, if any.
	Assertion *etree.Element
}

func protocolElement(tag, id, destination, inResponseTo string, issueInstant time.Time) *etree.Element {
	el := newElement(tag, "xmlns:samlp", NSProtocol, "xmlns:saml", NSAssertion)
	if destination != "" {
		el.CreateAttr("Destination", destination)
	}
	el.CreateAttr("ID", id)
	if inResponseTo != "" {
		el.CreateAttr("InResponseTo", inResponseTo)
	}
	el.CreateAttr("IssueInstant", Instant(issueInstant))
	el.CreateAttr("Version", "2.0")
	return el
}

func statusElement(parent *etree.Element, status, sub string) {
	if status == "" {
		status = StatusSuccess
	}
	st := parent.CreateElement("samlp:Status")
	code := st.CreateElement("samlp:StatusCode")
	code.CreateAttr("Value", status)
	if sub != "" {
		code.CreateElement("samlp:StatusCode").CreateAttr("Value", sub)
	}
}

// Element builds the samlp:Response element.
func (r *Response) Element() *etree.Element {
	el := protocolElement("samlp:Response", r.ID, r.Destination, r.InResponseTo, r.IssueInstant)
	textElement(el, "saml:Issuer", r.Issuer)
	statusElement(el, r.Status, r.SubStatus)
	if r.Assertion != nil {
		el.AddChild(r.Assertion)
	}
	return el
}

// LogoutRequest is a samlp:LogoutRequest sent to a service provider.
type LogoutRequest struct {
	ID           string
	Destination  string
	Issuer       string
	IssueInstant time.Time
	NameID       string
	NameIDFormat string
	SessionIndex string
}

// Element builds the samlp:LogoutRequest element.
func (l *LogoutRequest) Element() *etree.Element {
	el := protocolElement("samlp:LogoutRequest", l.ID, l.Destination, "", l.IssueInstant)
	textElement(el, "saml:Issuer", l.Issuer)
	nameID := textElement(el, "saml:NameID", l.NameID)
	if l.NameIDFormat != "" {
		nameID.CreateAttr("Format", l.NameIDFormat)
	}
	if l.SessionIndex != "" {
		textElement(el, "samlp:SessionIndex", l.SessionIndex)
	}
	return el
}

// LogoutResponse is a samlp:LogoutResponse.
type LogoutResponse struct {
	ID           string
	InResponseTo string
	Destination  string
	Issuer       string
	IssueInstant time.Time
	Status       string
}

// Element builds the samlp:LogoutResponse element.
func (l *LogoutResponse) Element() *etree.Element {
	el := protocolElement("samlp:LogoutResponse", l.ID, l.Destination, l.InResponseTo, l.IssueInstant)
	textElement(el, "saml:Issuer", l.Issuer)
	statusElement(el, l.Status, "")
	return el
}

// SOAPEnvelope wraps a message for the SOAP binding.
func SOAPEnvelope(msg *etree.Element) *etree.Element {
	env := newElement("soap:Envelope", "xmlns:soap", NSSOAP)
	env.CreateElement("soap:Body").AddChild(msg)
	return env
}

// ---------------------------------------------------------------- encryption

// Encryption algorithm URIs.
const (
	EncAES128CBC = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	EncAES192CBC = "http://www.w3.org/2001/04/xmlenc#aes192-cbc"
	EncAES256CBC = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
	EncAES128GCM = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	EncAES192GCM = "http://www.w3.org/2009/xmlenc11#aes192-gcm"
	EncAES256GCM = "http://www.w3.org/2009/xmlenc11#aes256-gcm"

	KeyRSAOAEPMGF1P = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	KeyRSAOAEP11    = "http://www.w3.org/2009/xmlenc11#rsa-oaep"

	DigestSHA1   = "http://www.w3.org/2000/09/xmldsig#sha1"
	DigestSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
	DigestSHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"

	MGF1SHA1   = "http://www.w3.org/2009/xmlenc11#mgf1sha1"
	MGF1SHA256 = "http://www.w3.org/2009/xmlenc11#mgf1sha256"
	MGF1SHA512 = "http://www.w3.org/2009/xmlenc11#mgf1sha512"
)

// EncryptionOptions are the algorithms of an encrypted assertion; empty
// fields take Keycloak's defaults (AES-128-CBC, RSA-OAEP-MGF1P with SHA-1).
type EncryptionOptions struct {
	Algorithm    string
	KeyAlgorithm string
	Digest       string // OAEP digest
	MGF          string // OAEP mask generation function (xmlenc11#rsa-oaep only)
}

var dataKeySizes = map[string]int{
	EncAES128CBC: 16, EncAES192CBC: 24, EncAES256CBC: 32,
	EncAES128GCM: 16, EncAES192GCM: 24, EncAES256GCM: 32,
}

var digestHashes = map[string]crypto.Hash{
	DigestSHA1: crypto.SHA1, DigestSHA256: crypto.SHA256, DigestSHA512: crypto.SHA512,
	"http://www.w3.org/2001/04/xmldsig-more#sha256": crypto.SHA256,
}

var mgfHashes = map[string]crypto.Hash{MGF1SHA1: crypto.SHA1, MGF1SHA256: crypto.SHA256, MGF1SHA512: crypto.SHA512}

// EncryptAssertion encrypts a (possibly signed) assertion for the
// certificate of a service provider and returns the saml:EncryptedAssertion.
func EncryptAssertion(assertion *etree.Element, cert *x509.Certificate, opts EncryptionOptions) (*etree.Element, error) {
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("the encryption certificate has no RSA key")
	}
	if opts.Algorithm == "" {
		opts.Algorithm = EncAES128CBC
	}
	if opts.KeyAlgorithm == "" {
		opts.KeyAlgorithm = KeyRSAOAEPMGF1P
	}
	size, ok := dataKeySizes[opts.Algorithm]
	if !ok {
		return nil, fmt.Errorf("unsupported encryption algorithm %s", opts.Algorithm)
	}
	plain, err := Serialize(assertion)
	if err != nil {
		return nil, err
	}
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var ciphertext []byte
	if strings.HasSuffix(opts.Algorithm, "gcm") {
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		nonce := make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		ciphertext = gcm.Seal(nonce, nonce, plain, nil)
	} else {
		// xmlenc padding: arbitrary bytes, the last one giving the length
		pad := aes.BlockSize - len(plain)%aes.BlockSize
		padded := make([]byte, len(plain)+pad)
		copy(padded, plain)
		if _, err := rand.Read(padded[len(plain) : len(padded)-1]); err != nil {
			return nil, err
		}
		padded[len(padded)-1] = byte(pad)
		iv := make([]byte, aes.BlockSize)
		if _, err := rand.Read(iv); err != nil {
			return nil, err
		}
		ciphertext = make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
		ciphertext = append(iv, ciphertext...)
	}

	digest, mgf := crypto.SHA1, crypto.SHA1
	if opts.Digest != "" {
		if digest, ok = digestHashes[opts.Digest]; !ok {
			return nil, fmt.Errorf("unsupported digest %s", opts.Digest)
		}
	}
	switch opts.KeyAlgorithm {
	case KeyRSAOAEPMGF1P:
		// the MGF of rsa-oaep-mgf1p is always MGF1 with SHA-1
	case KeyRSAOAEP11:
		if opts.MGF != "" {
			if mgf, ok = mgfHashes[opts.MGF]; !ok {
				return nil, fmt.Errorf("unsupported mask generation function %s", opts.MGF)
			}
		}
	default:
		return nil, fmt.Errorf("unsupported key transport algorithm %s", opts.KeyAlgorithm)
	}
	encKey, err := encryptOAEP(pub, key, digest, mgf)
	if err != nil {
		return nil, err
	}

	out := etree.NewElement("saml:EncryptedAssertion")
	ed := newElement("xenc:EncryptedData", "xmlns:xenc", NSXEnc, "Type", "http://www.w3.org/2001/04/xmlenc#Element")
	out.AddChild(ed)
	ed.CreateElement("xenc:EncryptionMethod").CreateAttr("Algorithm", opts.Algorithm)
	ki := ed.CreateElement("ds:KeyInfo")
	ki.CreateAttr("xmlns:ds", NSDSig)
	ek := ki.CreateElement("xenc:EncryptedKey")
	em := ek.CreateElement("xenc:EncryptionMethod")
	em.CreateAttr("Algorithm", opts.KeyAlgorithm)
	if opts.Digest != "" {
		em.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", opts.Digest)
	}
	if opts.KeyAlgorithm == KeyRSAOAEP11 && opts.MGF != "" {
		m := em.CreateElement("xenc11:MGF")
		m.CreateAttr("xmlns:xenc11", "http://www.w3.org/2009/xmlenc11#")
		m.CreateAttr("Algorithm", opts.MGF)
	}
	textElement(ek.CreateElement("xenc:CipherData"), "xenc:CipherValue", base64.StdEncoding.EncodeToString(encKey))
	textElement(ed.CreateElement("xenc:CipherData"), "xenc:CipherValue", base64.StdEncoding.EncodeToString(ciphertext))
	return out, nil
}

// encryptOAEP is RSAES-OAEP (RFC 8017 7.1.1) with an empty label, allowing
// a mask generation hash different from the digest as xmlenc 1.1 does.
func encryptOAEP(pub *rsa.PublicKey, msg []byte, digest, mgf crypto.Hash) ([]byte, error) {
	k := pub.Size()
	hLen := digest.Size()
	if len(msg) > k-2*hLen-2 {
		return nil, errors.New("key too short for OAEP")
	}
	lHash := newHash(digest)
	db := make([]byte, k-hLen-1)
	copy(db, lHash.Sum(nil))
	db[len(db)-len(msg)-1] = 1
	copy(db[len(db)-len(msg):], msg)
	seed := make([]byte, hLen)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	xorInto(db, mgf1(seed, len(db), mgf))
	xorInto(seed, mgf1(db, hLen, mgf))
	em := append(append([]byte{0}, seed...), db...)
	m := new(big.Int).SetBytes(em)
	c := new(big.Int).Exp(m, big.NewInt(int64(pub.E)), pub.N)
	out := make([]byte, k)
	return c.FillBytes(out), nil
}

func newHash(h crypto.Hash) interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
} {
	switch h {
	case crypto.SHA256:
		return sha256.New()
	case crypto.SHA512:
		return sha512.New()
	}
	return sha1.New() //nolint:gosec
}

func mgf1(seed []byte, length int, h crypto.Hash) []byte {
	var out []byte
	for counter := uint32(0); len(out) < length; counter++ {
		d := newHash(h)
		d.Write(seed)
		d.Write([]byte{byte(counter >> 24), byte(counter >> 16), byte(counter >> 8), byte(counter)})
		out = d.Sum(out)
	}
	return out[:length]
}

func xorInto(dst, mask []byte) {
	for i := range dst {
		dst[i] ^= mask[i]
	}
}

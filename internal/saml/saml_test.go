package saml

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
)

func keyPair(t testing.TB) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}

const authnRequest = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="https://idp/protocol/saml" AssertionConsumerServiceURL="https://sp/acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ForceAuthn="true"><saml:Issuer>https://sp</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/></samlp:AuthnRequest>`

func TestParse(t *testing.T) {
	q, err := Parse([]byte(authnRequest))
	if err != nil {
		t.Fatal(err)
	}
	if q.Name != "AuthnRequest" || q.ID != "_r1" || q.Issuer != "https://sp" || q.ACSURL != "https://sp/acs" ||
		q.ProtocolBinding != BindingPOST || !q.ForceAuthn || q.IsPassive || q.NameIDPolicy != NameIDEmail || q.HasSignature {
		t.Fatalf("%+v", q)
	}
	lr := `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_l" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">sp</saml:Issuer><saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Format="f"> bob </saml:NameID><samlp:SessionIndex>a::b</samlp:SessionIndex><samlp:SessionIndex>c</samlp:SessionIndex></samlp:LogoutRequest>`
	q, err = Parse([]byte(lr))
	if err != nil || q.NameID != "bob" || q.NameIDFormat != "f" || len(q.SessionIndexes) != 2 {
		t.Fatalf("%+v %v", q, err)
	}
	// SOAP envelope
	q, err = Parse([]byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>` + lr + `</soap:Body></soap:Envelope>`))
	if err != nil || q.Name != "LogoutRequest" {
		t.Fatalf("soap: %+v %v", q, err)
	}
	for name, doc := range map[string]string{
		"wrong namespace": `<AuthnRequest xmlns="urn:x" ID="a" Version="2.0"/>`,
		"no id":           `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0"/>`,
		"version":         `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="a" Version="1.1"/>`,
		"unknown":         `<samlp:ArtifactResolve xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="a" Version="2.0"/>`,
		"not xml":         `<a`,
		"empty":           ``,
		// encoding/xml would not round trip this (a namespace trick behind
		// past signature bypasses)
		"round trip": `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="a" Version="2.0"><x::Element></::Element></samlp:AuthnRequest>`,
	} {
		if _, err := Parse([]byte(doc)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestXMLSignature(t *testing.T) {
	key, cert := keyPair(t)
	_, other := keyPair(t)
	q, _ := Parse([]byte(authnRequest))
	signer := &Signer{Key: key, Cert: cert, KeyName: "kid", Algorithm: SignatureAlgorithm("RSA_SHA256")}
	if err := signer.Sign(q.root); err != nil {
		t.Fatal(err)
	}
	// the signature goes after the Issuer
	if kids := q.root.ChildElements(); kids[0].Tag != "Issuer" || kids[1].Tag != "Signature" {
		t.Fatalf("signature position: %s, %s", kids[0].Tag, kids[1].Tag)
	}
	signed, _ := Serialize(q.root)
	verify := func(doc []byte, certs ...*x509.Certificate) error {
		q, err := Parse(doc)
		if err != nil {
			return err
		}
		return q.VerifySignature(certs)
	}
	if err := verify(signed, other, cert); err != nil {
		t.Fatalf("valid signature: %v", err)
	}
	if err := verify(signed, other); err == nil {
		t.Fatal("verified with the wrong certificate")
	}
	tampered := bytes.Replace(signed, []byte("https://sp/acs"), []byte("https://evil/acs"), 1)
	if err := verify(tampered, cert); err == nil {
		t.Fatal("tampered document verified")
	}
	if err := verify([]byte(authnRequest), cert); err == nil {
		t.Fatal("unsigned document verified")
	}
	// the namespaces used by the content are kept (signing works on a copy)
	a := (&Assertion{ID: "a1", Issuer: "idp", NameID: "n", Attributes: []Attribute{{Name: "x", Values: []string{"1"}}}}).Element()
	if err := signer.Sign(a); err != nil {
		t.Fatal(err)
	}
	if out, _ := Serialize(a); !bytes.Contains(out, []byte(`xmlns:xs="http://www.w3.org/2001/XMLSchema"`)) {
		t.Fatalf("lost a namespace: %s", out)
	}
}

func TestRedirectBinding(t *testing.T) {
	key, cert := keyPair(t)
	signer := &Signer{Key: key, Cert: cert, Algorithm: SignatureAlgorithm("RSA_SHA1")}
	u, err := RedirectURL("https://idp/saml?x=1", "SAMLRequest", []byte(authnRequest), "state &=1", signer)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(u, "https://idp/saml?x=1&SAMLRequest=") {
		t.Fatal(u)
	}
	pu, _ := url.Parse(u)
	m, err := ReadMessage(httptest.NewRequest("GET", pu.RequestURI(), nil))
	if err != nil {
		t.Fatal(err)
	}
	if !m.Request || m.Binding != BindingRedirect || string(m.XML) != authnRequest || m.RelayState != "state &=1" {
		t.Fatalf("%+v", m)
	}
	if err := m.VerifyQuerySignature([]*x509.Certificate{cert}); err != nil {
		t.Fatal(err)
	}
	// changing the relay state breaks the signature
	m2, _ := ReadMessage(httptest.NewRequest("GET", strings.Replace(pu.RequestURI(), "RelayState=state", "RelayState=other", 1), nil))
	if err := m2.VerifyQuerySignature([]*x509.Certificate{cert}); err == nil {
		t.Fatal("tampered relay state verified")
	}
	// unsigned messages fail verification
	u, _ = RedirectURL("https://idp/saml", "SAMLResponse", []byte(authnRequest), "", nil)
	pu, _ = url.Parse(u)
	m, err = ReadMessage(httptest.NewRequest("GET", pu.RequestURI(), nil))
	if err != nil || m.Request || m.Signed() || m.VerifyQuerySignature([]*x509.Certificate{cert}) == nil {
		t.Fatalf("unsigned: %+v %v", m, err)
	}
	// POST binding
	body := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(authnRequest))}, "RelayState": {"r"}}.Encode()
	req := httptest.NewRequest("POST", "/saml", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	m, err = ReadMessage(req)
	if err != nil || m.Binding != BindingPOST || string(m.XML) != authnRequest || m.RelayState != "r" {
		t.Fatalf("post: %+v %v", m, err)
	}
	// a deflate bomb is cut off
	huge := deflate(bytes.Repeat([]byte("a"), 4*maxMessage))
	if _, err := ReadMessage(httptest.NewRequest("GET", "/saml?SAMLRequest="+url.QueryEscape(base64.StdEncoding.EncodeToString(huge)), nil)); err == nil {
		t.Fatal("oversized message accepted")
	}
}

// decrypt is an independent xmlenc decryption for the encryption tests.
func decrypt(t *testing.T, key *rsa.PrivateKey, encrypted *etree.Element) []byte {
	t.Helper()
	ed := encrypted.FindElement("./EncryptedData")
	alg := ed.FindElement("./EncryptionMethod").SelectAttrValue("Algorithm", "")
	ek := ed.FindElement("./KeyInfo/EncryptedKey")
	em := ek.FindElement("./EncryptionMethod")
	digest, mgf := crypto.SHA1, crypto.SHA1
	if d := em.FindElement("./DigestMethod"); d != nil {
		digest = digestHashes[d.SelectAttrValue("Algorithm", "")]
	}
	if m := em.FindElement("./MGF"); m != nil {
		mgf = mgfHashes[m.SelectAttrValue("Algorithm", "")]
	}
	ct, _ := base64.StdEncoding.DecodeString(ek.FindElement("./CipherData/CipherValue").Text())
	// RSA then OAEP decoding with separate digest and MGF hashes
	em2 := new(big.Int).Exp(new(big.Int).SetBytes(ct), key.D, key.N).FillBytes(make([]byte, key.Size()))
	hLen := digest.Size()
	seed, db := em2[1:1+hLen], em2[1+hLen:]
	xorInto(seed, mgf1(db, hLen, mgf))
	xorInto(db, mgf1(seed, len(db), mgf))
	lHash := newHash(digest)
	if !bytes.Equal(db[:hLen], lHash.Sum(nil)) {
		t.Fatalf("OAEP label hash mismatch")
	}
	i := hLen
	for db[i] == 0 {
		i++
	}
	cek := db[i+1:]
	data, _ := base64.StdEncoding.DecodeString(ed.FindElement("./CipherData/CipherValue").Text())
	block, err := aes.NewCipher(cek)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(alg, "gcm") {
		gcm, _ := cipher.NewGCM(block)
		plain, err := gcm.Open(nil, data[:12], data[12:], nil)
		if err != nil {
			t.Fatal(err)
		}
		return plain
	}
	plain := make([]byte, len(data)-16)
	cipher.NewCBCDecrypter(block, data[:16]).CryptBlocks(plain, data[16:])
	return plain[:len(plain)-int(plain[len(plain)-1])]
}

func TestEncryptAssertion(t *testing.T) {
	key, cert := keyPair(t)
	a := (&Assertion{ID: "a1", Issuer: "idp", NameID: "bob", NameIDFormat: NameIDUnspecified}).Element()
	want, _ := Serialize(a)
	for _, opts := range []EncryptionOptions{
		{},
		{Algorithm: EncAES256CBC, Digest: DigestSHA256},
		{Algorithm: EncAES128GCM},
		{Algorithm: EncAES256GCM, KeyAlgorithm: KeyRSAOAEP11, Digest: DigestSHA256, MGF: MGF1SHA256},
		{Algorithm: EncAES192CBC, KeyAlgorithm: KeyRSAOAEP11, Digest: DigestSHA512},
	} {
		enc, err := EncryptAssertion(a, cert, opts)
		if err != nil {
			t.Fatalf("%+v: %v", opts, err)
		}
		if got := decrypt(t, key, enc); !bytes.Equal(got, want) {
			t.Fatalf("%+v: decrypted %s", opts, got)
		}
	}
	if _, err := EncryptAssertion(a, cert, EncryptionOptions{Algorithm: "urn:nope"}); err == nil {
		t.Fatal("unknown algorithm accepted")
	}
}

func TestSPMetadata(t *testing.T) {
	_, cert := keyPair(t)
	c := base64.StdEncoding.EncodeToString(cert.Raw)
	md, err := ParseSPMetadata([]byte(`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp"><md:SPSSODescriptor AuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>` + c + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
		`<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>` +
		`<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp/acs" index="1"/>` +
		`</md:SPSSODescriptor></md:EntityDescriptor>`))
	if err != nil || md.EntityID != "https://sp" || !md.AuthnRequestsSigned || md.SigningCert != c || md.EncryptionCert != "" ||
		md.NameIDFormat != NameIDPersistent || md.ACS[BindingPOST] != "https://sp/acs" {
		t.Fatalf("%+v %v", md, err)
	}
	if _, err := ParseSPMetadata([]byte(`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"/>`)); err == nil {
		t.Fatal("metadata without SP accepted")
	}
}

func TestIdPDescriptor(t *testing.T) {
	_, cert := keyPair(t)
	d := IdPDescriptor("https://idp/realms/r&d", "https://idp/realms/r&d/protocol/saml", []DescriptorKey{{Name: "k1", Cert: cert}})
	doc := etree.NewDocument()
	if err := doc.ReadFromString(d); err != nil {
		t.Fatal(err)
	}
	if doc.Root().SelectAttrValue("entityID", "") != "https://idp/realms/r&d" || len(doc.FindElements("//SingleSignOnService")) != 4 {
		t.Fatal(d)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(authnRequest))
	f.Add([]byte(`<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="a" Version="2.0" InResponseTo="b"><samlp:Status><samlp:StatusCode Value="x"/></samlp:Status></samlp:LogoutResponse>`))
	f.Add([]byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>`))
	f.Add([]byte(`<!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>`))
	_, cert := keyPair(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		q, err := Parse(b)
		if err != nil {
			return
		}
		// verification of arbitrary documents must fail without panicking
		if q.VerifySignature([]*x509.Certificate{cert}) == nil {
			t.Fatal("verified a fuzzed document")
		}
	})
}

func FuzzReadRedirect(f *testing.F) {
	u, _ := RedirectURL("/saml", "SAMLRequest", []byte(authnRequest), "rs", nil)
	f.Add(strings.TrimPrefix(u, "/saml?"))
	f.Add("SAMLRequest=%%&SigAlg=x&Signature=y")
	f.Fuzz(func(t *testing.T, q string) {
		m, err := readRedirect(q)
		if err == nil {
			_ = m.VerifyQuerySignature(nil)
			_, _ = Parse(m.XML)
		}
	})
}

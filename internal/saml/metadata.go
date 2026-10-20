package saml

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"html"
	"strings"

	"github.com/beevik/etree"
	xrv "github.com/mattermost/xml-roundtrip-validator"
)

// DescriptorKey is a signing key listed in the IdP metadata.
type DescriptorKey struct {
	Name string // key id
	Cert *x509.Certificate
}

// IdPDescriptor returns the metadata of a realm as a SAML identity provider.
func IdPDescriptor(entityID, endpoint string, keys []DescriptorKey) string {
	e := html.EscapeString
	var b strings.Builder
	b.WriteString(`<md:EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="` + e(entityID) + `">`)
	b.WriteString(`<md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">`)
	for _, k := range keys {
		b.WriteString(`<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:KeyName>` + e(k.Name) + `</ds:KeyName><ds:X509Data><ds:X509Certificate>` +
			base64.StdEncoding.EncodeToString(k.Cert.Raw) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`)
	}
	b.WriteString(`<md:ArtifactResolutionService Binding="` + BindingSOAP + `" Location="` + e(endpoint) + `/resolve" index="0"></md:ArtifactResolutionService>`)
	for _, binding := range []string{BindingPOST, BindingRedirect, BindingArtifact, BindingSOAP} {
		b.WriteString(`<md:SingleLogoutService Binding="` + binding + `" Location="` + e(endpoint) + `"></md:SingleLogoutService>`)
	}
	for _, f := range []string{NameIDPersistent, NameIDTransient, NameIDUnspecified, NameIDEmail} {
		b.WriteString(`<md:NameIDFormat>` + f + `</md:NameIDFormat>`)
	}
	for _, binding := range []string{BindingPOST, BindingRedirect, BindingSOAP, BindingArtifact} {
		b.WriteString(`<md:SingleSignOnService Binding="` + binding + `" Location="` + e(endpoint) + `"></md:SingleSignOnService>`)
	}
	b.WriteString(`</md:IDPSSODescriptor></md:EntityDescriptor>`)
	return b.String()
}

// SPMetadata is what a service provider's metadata says about it.
type SPMetadata struct {
	EntityID             string
	AuthnRequestsSigned  bool
	WantAssertionsSigned bool
	SigningCert          string // base64 DER
	EncryptionCert       string
	NameIDFormat         string
	ACS                  map[string]string // binding -> location (first of each)
	SLO                  map[string]string
}

// ParseSPMetadata reads an EntityDescriptor with an SPSSODescriptor.
func ParseSPMetadata(raw []byte) (*SPMetadata, error) {
	if err := xrv.Validate(bytes.NewReader(raw)); err != nil {
		return nil, invalidf("xml: %v", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, invalidf("xml: %v", err)
	}
	root := doc.Root()
	if root == nil {
		return nil, invalidf("empty document")
	}
	if root.Tag == "EntitiesDescriptor" && root.NamespaceURI() == NSMetadata {
		root = child(root, NSMetadata, "EntityDescriptor")
	}
	if root == nil || root.Tag != "EntityDescriptor" || root.NamespaceURI() != NSMetadata {
		return nil, invalidf("not SAML metadata")
	}
	sp := child(root, NSMetadata, "SPSSODescriptor")
	if sp == nil {
		return nil, invalidf("no SPSSODescriptor")
	}
	md := &SPMetadata{EntityID: root.SelectAttrValue("entityID", ""), ACS: map[string]string{}, SLO: map[string]string{},
		AuthnRequestsSigned:  sp.SelectAttrValue("AuthnRequestsSigned", "") == "true",
		WantAssertionsSigned: sp.SelectAttrValue("WantAssertionsSigned", "") == "true"}
	for _, el := range sp.ChildElements() {
		if el.NamespaceURI() != NSMetadata {
			continue
		}
		switch el.Tag {
		case "KeyDescriptor":
			cert := ""
			if ki := child(el, NSDSig, "KeyInfo"); ki != nil {
				if xd := child(ki, NSDSig, "X509Data"); xd != nil {
					if c := child(xd, NSDSig, "X509Certificate"); c != nil {
						cert = strings.Join(strings.Fields(c.Text()), "")
					}
				}
			}
			switch el.SelectAttrValue("use", "") {
			case "signing":
				md.SigningCert = cert
			case "encryption":
				md.EncryptionCert = cert
			default:
				md.SigningCert, md.EncryptionCert = cert, cert
			}
		case "NameIDFormat":
			if md.NameIDFormat == "" {
				md.NameIDFormat = strings.TrimSpace(el.Text())
			}
		case "AssertionConsumerService":
			if b := el.SelectAttrValue("Binding", ""); md.ACS[b] == "" {
				md.ACS[b] = el.SelectAttrValue("Location", "")
			}
		case "SingleLogoutService":
			if b := el.SelectAttrValue("Binding", ""); md.SLO[b] == "" {
				md.SLO[b] = el.SelectAttrValue("Location", "")
			}
		}
	}
	return md, nil
}

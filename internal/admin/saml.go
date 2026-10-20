package admin

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"strings"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/saml"
	"github.com/ducnt114/gocloak/internal/service"
)

// convertClientDescription implements /client-description-converter: it
// turns SAML service provider metadata (or a client representation) into a
// client representation, as the console's "Import client" does.
func (h *Handler) convertClientDescription(w http.ResponseWriter, r *http.Request, p *principal) error {
	if _, err := h.realmFor(r, p, permCreateClient); err != nil {
		return err
	}
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, 4<<20))
	if err != nil {
		return badRequest("Invalid request")
	}
	body = bytes.TrimSpace(body)
	if bytes.HasPrefix(body, []byte("<")) {
		md, err := saml.ParseSPMetadata(body)
		if err != nil {
			return badRequest("Unsupported format")
		}
		return ok(w, samlClientFromMetadata(md))
	}
	var rep ClientRep
	if err := json.Unmarshal(body, &rep); err != nil || rep.ClientID == nil {
		return badRequest("Unsupported format")
	}
	return ok(w, rep)
}

// samlClientFromMetadata is Keycloak's saml2-entity-descriptor converter.
func samlClientFromMetadata(md *saml.SPMetadata) map[string]any {
	attrs := map[string]string{
		service.SAMLServerSignature:     "true",
		service.SAMLServerSigKeyInfoExt: "false",
		service.SAMLSignatureAlgorithm:  "RSA_SHA256",
		service.SAMLAuthnStatement:      "true",
		service.SAMLClientSignature:     boolString(md.AuthnRequestsSigned),
		service.SAMLAssertionSignature:  boolString(md.WantAssertionsSigned),
	}
	switch md.NameIDFormat {
	case saml.NameIDEmail:
		attrs[service.SAMLNameIDFormat] = "email"
	case saml.NameIDPersistent:
		attrs[service.SAMLNameIDFormat] = "persistent"
	case saml.NameIDTransient:
		attrs[service.SAMLNameIDFormat] = "transient"
	case saml.NameIDUnspecified:
		attrs[service.SAMLNameIDFormat] = "username"
	}
	var redirects []string
	for binding, attr := range map[string]string{saml.BindingPOST: service.SAMLACSPost, saml.BindingRedirect: service.SAMLACSRedirect,
		saml.BindingArtifact: service.SAMLACSArtifact} {
		if loc := md.ACS[binding]; loc != "" {
			attrs[attr] = loc
		}
	}
	for _, binding := range []string{saml.BindingPOST, saml.BindingRedirect, saml.BindingArtifact} {
		if loc := md.ACS[binding]; loc != "" {
			redirects = append(redirects, loc)
		}
	}
	for binding, attr := range map[string]string{saml.BindingPOST: service.SAMLSLOPost, saml.BindingRedirect: service.SAMLSLORedirect,
		saml.BindingSOAP: service.SAMLSLOSOAP, saml.BindingArtifact: service.SAMLSLOArtifact} {
		if loc := md.SLO[binding]; loc != "" {
			attrs[attr] = loc
		}
	}
	if md.SigningCert != "" {
		attrs[service.SAMLSigningCert] = md.SigningCert
	}
	if md.EncryptionCert != "" {
		attrs[service.SAMLEncrypt] = "true"
		attrs[service.SAMLEncryptionCert] = md.EncryptionCert
	}
	if redirects == nil {
		redirects = []string{}
	}
	return map[string]any{"clientId": md.EntityID, "protocol": service.ProtocolSAML, "fullScopeAllowed": true,
		"attributes": attrs, "redirectUris": redirects, "protocolMappers": []any{}}
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// clientInstallation serves /clients/{id}/installation/providers/{provider}:
// the adapter configuration or metadata of a client.
func (h *Handler) clientInstallation(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewClients)
	if err != nil {
		return err
	}
	c, err := h.loadClient(r, realm)
	if err != nil {
		return err
	}
	var out string
	switch r.PathValue("provider") {
	case "gocloak-oidc-gocloak-json":
		out = adapterJSON(h.URLs.Base(r), realm, c)
	case "saml-sp-descriptor":
		if c.Protocol != service.ProtocolSAML {
			return notFound("Unknown Provider")
		}
		out = samlSPDescriptor(c)
	default:
		return notFound("Unknown Provider")
	}
	w.Header().Set("Content-Type", "text/plain")
	_, err = w.Write([]byte(out))
	return err
}

func adapterJSON(base string, realm *model.Realm, c *model.Client) string {
	var b strings.Builder
	q := func(s string) string { v, _ := json.Marshal(s); return string(v) }
	b.WriteString("{\n")
	b.WriteString(`  "realm" : ` + q(realm.Name) + ",\n")
	b.WriteString(`  "auth-server-url" : ` + q(base+"/") + ",\n")
	ssl := realm.Settings.SSLRequired
	if ssl == "" {
		ssl = "external"
	}
	b.WriteString(`  "ssl-required" : ` + q(ssl) + ",\n")
	b.WriteString(`  "resource" : ` + q(c.ClientID) + ",\n")
	switch {
	case c.BearerOnly:
		b.WriteString(`  "bearer-only" : true` + ",\n")
	case c.PublicClient:
		b.WriteString(`  "public-client" : true` + ",\n")
	default:
		b.WriteString(`  "credentials" : {` + "\n" + `    "secret" : ` + q(c.Secret) + "\n  },\n")
	}
	b.WriteString(`  "confidential-port" : 0` + "\n}")
	return b.String()
}

// samlSPDescriptor is the metadata of a SAML client as Keycloak describes it.
func samlSPDescriptor(c *model.Client) string {
	e := html.EscapeString
	a := c.Attributes
	format := map[string]string{"email": saml.NameIDEmail, "transient": saml.NameIDTransient,
		"persistent": saml.NameIDPersistent}[a[service.SAMLNameIDFormat]]
	if format == "" {
		format = saml.NameIDUnspecified
	}
	or := func(v string) string {
		if v == "" {
			return "ERROR:ENDPOINT_NOT_SET"
		}
		return v
	}
	var b strings.Builder
	b.WriteString(`<md:EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="` +
		e(c.ClientID) + `" ID="` + saml.NewID() + `">`)
	b.WriteString(`<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="` +
		boolString(a[service.SAMLClientSignature] == "true") + `" WantAssertionsSigned="` + boolString(a[service.SAMLAssertionSignature] == "true") + `">`)
	key := func(use, cert string) {
		if cert = strings.Join(strings.Fields(cert), ""); cert != "" {
			if _, err := base64.StdEncoding.DecodeString(cert); err == nil {
				b.WriteString(`<md:KeyDescriptor use="` + use + `"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + cert +
					`</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`)
			}
		}
	}
	if a[service.SAMLClientSignature] == "true" {
		key("signing", a[service.SAMLSigningCert])
	}
	if a[service.SAMLEncrypt] == "true" {
		key("encryption", a[service.SAMLEncryptionCert])
	}
	b.WriteString(`<md:SingleLogoutService Binding="` + saml.BindingPOST + `" Location="` + e(or(a[service.SAMLSLOPost])) + `"></md:SingleLogoutService>`)
	if v := a[service.SAMLSLORedirect]; v != "" {
		b.WriteString(`<md:SingleLogoutService Binding="` + saml.BindingRedirect + `" Location="` + e(v) + `"></md:SingleLogoutService>`)
	}
	b.WriteString(`<md:NameIDFormat>` + format + `</md:NameIDFormat>`)
	acs := a[service.SAMLACSPost]
	if acs == "" {
		acs = c.AdminURL
	}
	b.WriteString(`<md:AssertionConsumerService Binding="` + saml.BindingPOST + `" Location="` + e(or(acs)) + `" isDefault="true" index="1"></md:AssertionConsumerService>`)
	if v := a[service.SAMLACSRedirect]; v != "" {
		b.WriteString(`<md:AssertionConsumerService Binding="` + saml.BindingRedirect + `" Location="` + e(v) + `" index="2"></md:AssertionConsumerService>`)
	}
	b.WriteString(`</md:SPSSODescriptor></md:EntityDescriptor>`)
	return b.String()
}
